"""Privileged control CLI for the NVR-local shim (runs as root on the NVR).

Every mutating command supports --dry-run, is idempotent, and takes a lock so
the timer, unit hooks and an operator never interleave firewall changes.
Redirects are only installed for cameras whose shim instance is verifiably
serving (fresh heartbeat from the unit's MainPID, listening, not unsafe);
anything else is fail-open: the redirect is removed and Protect talks to the
camera directly, exactly as before installation.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import socket
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import __version__, units
from .config import Camera, Config, ConfigError, from_dict, load, load_raw
from .firewall import Firewall, FirewallError, Redirect, Runner, State
from .units import Paths

SHOW_PROPS = "Id,LoadState,ActiveState,SubState,MainPID,Result,UnitFileState,NRestarts"
ACTIVE_STATES = ("active", "activating", "reloading", "deactivating")
STALE_FACTOR = 3
MIN_STALE_SECONDS = 15.0
ACTIVATE_WAIT_SECONDS = 10.0
MANIFEST = "MANIFEST.sha256"
EMPTY_INVENTORY = (
    '{\n  "schema_version": 1,\n  "client_user": "unifi-protect",\n  "cameras": []\n}\n'
)


class CtlError(RuntimeError):
    pass


class Probe:
    """Host facts; tests substitute a fake."""

    proc_tables = ("/proc/net/tcp", "/proc/net/tcp6")

    def uid(self, user: str) -> int | None:
        try:
            return pwd.getpwnam(user).pw_uid
        except KeyError:
            return None

    def now(self) -> float:
        return time.time()

    def listening(self, port: int) -> bool:
        """Anything listening on port that would block binding 127.0.0.1:port.

        IPv6 counts too: a dual-stack [::] listener also holds the IPv4 port.
        """
        suffix = f":{port:04X}"
        blocking = {
            "0100007F",  # 127.0.0.1
            "00000000",  # 0.0.0.0
            "00000000000000000000000000000000",  # ::
            "00000000000000000000000001000000",  # ::1
            "0000000000000000FFFF00000100007F",  # ::ffff:127.0.0.1
            "0000000000000000FFFF000000000000",  # ::ffff:0.0.0.0
        }
        for path in self.proc_tables:
            try:
                with open(path) as table:
                    next(table, None)
                    for line in table:
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == "0A" and parts[1].endswith(suffix):
                            if parts[1][: -len(suffix)] in blocking:
                                return True
            except OSError:
                continue
        return False

    def read_status(self, path: str) -> dict | None:
        try:
            with open(path, "rb") as source:
                data = source.read(1 << 20)
            status = json.loads(data)
        except (OSError, ValueError):
            return None
        return status if isinstance(status, dict) else None

    def is_local_ip(self, ip: str) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((ip, 0))
            return True
        except OSError:
            return False

    def conntrack_count(self) -> int | None:
        try:
            with open("/proc/sys/net/netfilter/nf_conntrack_count") as source:
                return int(source.read().strip())
        except (OSError, ValueError):
            return None

    def euid(self) -> int:
        return os.geteuid()

    def which(self, tool: str) -> str | None:
        return shutil.which(tool)


class Systemctl:
    def __init__(self, runner: Runner, unit_dir: str):
        self.runner = runner
        self.unit_dir = unit_dir

    def show(self, names: list[str]) -> dict[str, dict[str, str]]:
        if not names:
            return {}
        result = self.runner.run(["systemctl", "show", "--no-pager", "-p", SHOW_PROPS, *names])
        if result.returncode != 0:
            raise CtlError("systemctl show failed")
        blocks = [b for b in result.stdout.strip().split("\n\n")]
        parsed = {}
        for name, block in zip(names, blocks):
            props = {}
            for line in block.splitlines():
                key, _, value = line.partition("=")
                props[key] = value
            parsed[name] = props
        return parsed

    def call(self, *args: str) -> bool:
        return self.runner.run(["systemctl", *args]).returncode == 0

    def instances(self) -> set[str]:
        """Instance units known to systemd or enabled via symlink."""
        found = set()
        result = self.runner.run(
            [
                "systemctl",
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--no-pager",
                "onvif-shim@*.service",
            ]
        )
        for line in result.stdout.splitlines():
            name = line.split()[0] if line.split() else ""
            if name.startswith("onvif-shim@") and name.endswith(".service"):
                found.add(name)
        wants = os.path.join(self.unit_dir, "multi-user.target.wants")
        try:
            for name in os.listdir(wants):
                if name.startswith("onvif-shim@") and name.endswith(".service"):
                    found.add(name)
        except OSError:
            pass
        return found


def camera_of(unit: str) -> str:
    return unit[len("onvif-shim@") : -len(".service")]


def redirect_for(camera: Camera) -> Redirect:
    return Redirect(camera.id, camera.camera_ip, camera.onvif_port, camera.listen_port)


def _atomic_write(path: str, text: str, mode: int = 0o644) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w") as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read(path: str) -> str | None:
    try:
        with open(path) as source:
            return source.read()
    except OSError:
        return None


@dataclass
class Row:
    camera: Camera
    unit: dict
    healthy: bool
    reason: str
    redirect: bool = False
    status: dict | None = None


@dataclass
class Outcome:
    rows: list[Row] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    firewall: State | None = None


class Ctl:
    def __init__(
        self,
        paths: Paths,
        *,
        runner: Runner | None = None,
        probe: Probe | None = None,
        out=print,
        dry_run: bool = False,
        check_ownership: bool = True,
    ):
        self.paths = paths
        self.runner = runner or Runner()
        self.probe = probe or Probe()
        self.out = out
        self.dry_run = dry_run
        self.check_ownership = check_ownership
        self.firewall = Firewall(self.runner)
        self.systemctl = Systemctl(self.runner, paths.unit_dir)

    # --- helpers -----------------------------------------------------------------

    def say(self, message: str) -> None:
        self.out(("[dry-run] " if self.dry_run else "") + message)

    @contextmanager
    def lock(self):
        os.makedirs(os.path.dirname(self.paths.lock_file), exist_ok=True)
        with open(self.paths.lock_file, "a") as handle:
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise CtlError("another shimctl operation holds the lock") from None
                    time.sleep(0.1)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    @property
    def uninstall_marker(self) -> str:
        return self.paths.lock_file + ".uninstalling"

    def require_root(self) -> None:
        if self.probe.euid() != 0:
            raise CtlError("must run as root on the NVR")

    def load_config(self) -> Config:
        return load(self.paths.config)

    def health(self, camera: Camera, config: Config, props: dict, *, starting=False):
        """(healthy, reason, status) — healthy means safe to redirect Protect to it."""
        active = props.get("ActiveState", "")
        if not (active == "active" or (starting and active == "activating")):
            return False, f"unit_{active or 'unknown'}", None
        status = self.probe.read_status(self.paths.status_file(camera.id))
        if status is None:
            return False, "no_status", None
        try:
            main_pid = int(props.get("MainPID") or 0)
        except ValueError:
            main_pid = 0
        if not main_pid or status.get("pid") != main_pid:
            return False, "stale_status", status
        limit = max(STALE_FACTOR * config.status.heartbeat_seconds, MIN_STALE_SECONDS)
        heartbeat = status.get("heartbeat_at")
        if not isinstance(heartbeat, (int, float)) or self.probe.now() - heartbeat > limit:
            return False, "heartbeat_stale", status
        process = status.get("process") or {}
        if not process.get("serviceable"):
            return False, process.get("unsafe_reason") or "not_serviceable", status
        if not self.probe.listening(camera.listen_port):
            return False, "not_listening", status
        return True, "ok", status

    # --- reconcile -----------------------------------------------------------------

    def reconcile(
        self, *, manage_units: bool = True, starting: str | None = None, stopping: str | None = None
    ) -> Outcome:
        outcome = Outcome()
        with self.lock():
            try:
                config = self.load_config()
            except (ConfigError, OSError) as exc:
                outcome.alerts.append(f"config_invalid detail={str(exc)[:160]!r}")
                self._fail_open_all(outcome)
                return outcome
            uid = self.probe.uid(config.client_user)
            if uid is None:
                outcome.alerts.append(f"client_user_missing user={config.client_user}")
                self._fail_open_all(outcome)
                return outcome
            bypass = os.path.exists(self.paths.bypass_flag)
            if bypass:
                outcome.alerts.append("bypass_all_active (run `resume` to re-enable redirects)")
            if os.path.exists(self.uninstall_marker):
                bypass = True
            names = [units.instance(c.id) for c in config.cameras]
            props = self.systemctl.show(names)
            try:
                state = self.firewall.read()
            except FirewallError as exc:
                outcome.alerts.append(f"firewall_unreadable detail={exc}")
                return outcome
            foreign = set(state.foreign_dnat)
            desired = set()
            to_start, to_stop = [], []
            for camera in config.cameras:
                unit = units.instance(camera.id)
                p = props.get(unit, {})
                if camera.id == stopping or not camera.enabled:
                    healthy, reason, status = (
                        False,
                        "stopping" if camera.enabled else "disabled",
                        None,
                    )
                else:
                    healthy, reason, status = self.health(
                        camera, config, p, starting=camera.id == starting
                    )
                if camera.enabled and camera.upstream in foreign:
                    healthy, reason = False, "conflicting_dnat"
                    outcome.alerts.append(
                        f"conflicting_dnat cam={camera.id} (another nat OUTPUT DNAT targets "
                        "this camera; remove the legacy single-camera onvif-shim first)"
                    )
                row = Row(camera, p, healthy, reason, status=status)
                if healthy and not bypass:
                    desired.add(redirect_for(camera))
                    row.redirect = True
                outcome.rows.append(row)
                active = p.get("ActiveState", "")
                if camera.enabled and active == "failed":
                    outcome.alerts.append(
                        f"unit_failed cam={camera.id} (restart limit or safety refusal; "
                        "redirect is off; inspect journal then run `reset`)"
                    )
                elif camera.enabled and manage_units and active in ("inactive", ""):
                    to_start.append(unit)
                elif camera.enabled and not healthy and active == "active":
                    outcome.alerts.append(f"unhealthy cam={camera.id} reason={reason}")
                if not camera.enabled and manage_units and active in ACTIVE_STATES:
                    to_stop.append(unit)
            configured = {units.instance(c.id) for c in config.cameras}
            stale = sorted(self.systemctl.instances() - configured)
            if manage_units:
                to_stop.extend(stale)
            # Keep the conntrack anchor while any camera is enabled or any instance is
            # still running/draining, so removing the last redirect never strands
            # in-flight redirected connections (see firewall.py). A later run drops it.
            draining = any(p.get("ActiveState") in ACTIVE_STATES for p in props.values())
            draining = draining or any(
                p.get("ActiveState") in ACTIVE_STATES for p in self.systemctl.show(stale).values()
            )
            anchor = bool(config.enabled) or draining
            try:
                lines, outcome.firewall = self.firewall.converge(
                    desired, uid, anchor=anchor, dry_run=self.dry_run
                )
                if lines:
                    outcome.changes.append(
                        f"firewall: {len(desired)} redirect(s) "
                        f"[{', '.join(sorted(r.camera_id for r in desired)) or 'none'}]"
                    )
                    for line in lines:
                        outcome.changes.append(f"  iptables-restore: {line}")
            except FirewallError as exc:
                outcome.alerts.append(f"firewall_apply_failed detail={exc}")
                self._fail_open_all(outcome)
            for unit in to_stop:
                outcome.changes.append(f"stop+disable {unit}")
                if not self.dry_run:
                    self.systemctl.call("disable", "--now", "--no-block", unit)
            for unit in to_start:
                outcome.changes.append(f"start {unit}")
                if not self.dry_run:
                    self.systemctl.call("start", "--no-block", unit)
        return outcome

    def _fail_open_all(self, outcome: Outcome) -> None:
        try:
            lines, outcome.firewall = self.firewall.remove_all(dry_run=self.dry_run)
            if lines:
                outcome.changes.append("firewall: fail-open, all redirects removed")
        except FirewallError as exc:
            outcome.alerts.append(
                f"CRITICAL fail_open_failed detail={exc}; remove manually: "
                "iptables -t nat -D OUTPUT <jump>; iptables -t nat -F ONVIF_SHIM; "
                "iptables -t nat -X ONVIF_SHIM"
            )

    def report(self, outcome: Outcome, *, quiet: bool) -> int:
        alert_file = self.paths.lock_file + ".alerts"
        previous = _read(alert_file)
        current = "\n".join(sorted(outcome.alerts))
        for change in outcome.changes:
            self.say(change)
        if not quiet or current != (previous or ""):
            for alert in outcome.alerts:
                self.out(f"ALERT {alert}")
            if quiet and not outcome.alerts and previous:
                self.out("alerts cleared")
        if not self.dry_run and current != (previous or ""):
            try:
                _atomic_write(alert_file, current, 0o600)
            except OSError:
                pass
        if not quiet and not outcome.changes:
            self.say("no changes")
        return 1 if outcome.alerts else 0

    def activate(self, camera_id: str) -> Outcome:
        """ExecStartPost: wait (bounded) for the instance to serve, then redirect it."""
        config = self.load_config()
        camera = config.camera(camera_id)
        deadline = time.monotonic() + ACTIVATE_WAIT_SECONDS
        unit = units.instance(camera_id)
        while time.monotonic() < deadline:
            props = self.systemctl.show([unit]).get(unit, {})
            healthy, _, _ = self.health(camera, config, props, starting=True)
            if healthy:
                break
            time.sleep(0.2)
        return self.reconcile(manage_units=False, starting=camera_id)

    def deactivate(self, camera_id: str) -> Outcome:
        """ExecStopPost: remove this camera's redirect immediately (fail open)."""
        return self.reconcile(manage_units=False, stopping=camera_id)

    # --- release management ------------------------------------------------------

    def verify_release(self, directory: str) -> str:
        manifest = os.path.join(directory, MANIFEST)
        text = _read(manifest)
        if text is None:
            raise CtlError(f"release has no {MANIFEST}")
        listed = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            digest, _, name = line.partition("  ")
            if len(digest) != 64 or not name or name.startswith("/") or ".." in name.split("/"):
                raise CtlError("malformed manifest")
            listed[name] = digest
        for name, digest in listed.items():
            path = os.path.join(directory, name)
            with open(path, "rb") as source:
                if hashlib.sha256(source.read()).hexdigest() != digest:
                    raise CtlError(f"checksum mismatch: {name}")
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), directory)
                if rel.endswith(".py") and rel not in listed:
                    raise CtlError(f"unlisted python file in release: {rel}")
        if self.check_ownership:
            paths = [self.paths.base, self.paths.releases, directory]
            for root, dirs, files in os.walk(directory):
                paths.extend(os.path.join(root, n) for n in dirs + files)
            for path in paths:
                info = os.lstat(path)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise CtlError(
                        f"release path must be root-owned, not group/other writable: {path}"
                    )
        version = (_read(os.path.join(directory, "VERSION")) or "").strip()
        if not version:
            raise CtlError("release has no VERSION")
        return version

    def _history(self) -> dict:
        path = os.path.join(self.paths.state, "releases.json")
        try:
            data = json.loads(_read(path) or "{}")
        except ValueError:
            data = {}
        return data if isinstance(data, dict) else {}

    def current_release(self) -> str | None:
        try:
            return os.path.basename(os.readlink(self.paths.current))
        except OSError:
            return None

    def switch_release(self, name: str) -> bool:
        directory = os.path.join(self.paths.releases, name)
        self.verify_release(directory)
        before = self.current_release()
        if before == name:
            return False
        self.say(f"switch current release {before or '(none)'} -> {name}")
        if self.dry_run:
            return True
        link = self.paths.current + ".tmp"
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(os.path.join("releases", name), link)
        os.replace(link, self.paths.current)
        history = self._history()
        previous = [r for r in history.get("history", []) if r != name]
        if before:
            previous = [before] + [r for r in previous if r != before]
        _atomic_write(
            os.path.join(self.paths.state, "releases.json"),
            json.dumps({"current": name, "history": previous[:10]}, indent=2) + "\n",
        )
        return True

    # --- install / uninstall -------------------------------------------------------

    def preflight(self, config: Config) -> list[str]:
        problems = []
        if sys.version_info < (3, 11):
            problems.append("python3 >= 3.11 required")
        for tool in ("systemctl", "iptables", "iptables-restore"):
            if self.probe.which(tool) is None:
                problems.append(f"{tool} not found")
        if self.probe.uid(config.client_user) is None:
            problems.append(f"client user {config.client_user!r} does not exist")
        result = self.runner.run(["iptables", "-m", "owner", "--help"])
        if result.returncode != 0:
            problems.append("iptables owner match unavailable")
        if os.path.exists(os.path.join(self.paths.unit_dir, "onvif-shim.service")):
            problems.append(
                "legacy single-camera onvif-shim (onvif-shim.service) is installed; "
                "run its `install.sh uninstall` first"
            )
        names = [units.instance(c.id) for c in config.cameras]
        props = self.systemctl.show(names)
        for camera in config.cameras:
            if self.probe.is_local_ip(camera.camera_ip):
                problems.append(f"cam={camera.id} camera_ip is an address of this NVR")
            ours = props.get(units.instance(camera.id), {}).get("ActiveState") in ACTIVE_STATES
            if camera.enabled and not ours and self.probe.listening(camera.listen_port):
                problems.append(f"cam={camera.id} listen_port {camera.listen_port} already in use")
        return problems

    def install(self, release: str | None = None) -> int:
        self.require_root()
        # A dry run of a first install has no inventory file to reconcile against;
        # with no cameras there is nothing to redirect anyway.
        preview_only = self.dry_run and not os.path.exists(self.paths.config)
        if not os.path.exists(self.paths.config):
            # First install: start with no cameras; add them with `shimctl add`/`setup`.
            self.say(f"create empty inventory {self.paths.config}")
            if not self.dry_run:
                _atomic_write(self.paths.config, EMPTY_INVENTORY)
            config = from_dict(json.loads(EMPTY_INVENTORY))
        else:
            config = self.load_config()
        problems = self.preflight(config)
        if problems:
            for problem in problems:
                self.out(f"PREFLIGHT {problem}")
            return 2
        # Instances run current/onvif_shim.py, so a new release needs a restart even
        # when the unit files are unchanged.
        switched = bool(release) and self.switch_release(release)
        if not release:
            current = self.current_release()
            if current is None:
                raise CtlError("no current release; pass --release VERSION")
            self.verify_release(os.path.join(self.paths.releases, current))
        changed = False
        for name, text in units.render(self.paths).items():
            path = os.path.join(self.paths.unit_dir, name)
            if _read(path) != text:
                changed = True
                self.say(f"write {path}")
                if not self.dry_run:
                    _atomic_write(path, text)
        if changed:
            self.say("systemctl daemon-reload")
            if not self.dry_run:
                self.systemctl.call("daemon-reload")
        # Remove redirects for disabled/unhealthy cameras before touching services.
        if not preview_only:
            self.report(self.reconcile(manage_units=False), quiet=True)
        names = [units.instance(c.id) for c in config.cameras]
        props = self.systemctl.show(names)
        stale = self.systemctl.instances() - set(names)
        for unit in sorted(stale):
            self.say(f"stop+disable stale {unit}")
            if not self.dry_run:
                self.systemctl.call("disable", "--now", unit)
        for camera in config.cameras:
            unit = units.instance(camera.id)
            p = props.get(unit, {})
            if camera.enabled:
                if p.get("UnitFileState") != "enabled":
                    self.say(f"enable {unit}")
                    if not self.dry_run:
                        self.systemctl.call("enable", unit)
                if p.get("ActiveState") != "active":
                    self.say(f"start {unit}")
                    if not self.dry_run and not self.systemctl.call("start", unit):
                        self.out(f"WARN start failed: {unit} (redirect stays off)")
                elif changed or switched:
                    why = "unit definition changed" if changed else "release changed"
                    self.say(f"restart {unit} ({why})")
                    if not self.dry_run:
                        self.systemctl.call("restart", unit)
            elif p.get("UnitFileState") == "enabled" or p.get("ActiveState") in ACTIVE_STATES:
                self.say(f"stop+disable {unit} (camera disabled)")
                if not self.dry_run:
                    self.systemctl.call("disable", "--now", unit)
        timer = self.systemctl.show([units.RECONCILE_TIMER]).get(units.RECONCILE_TIMER, {})
        if timer.get("UnitFileState") != "enabled" or timer.get("ActiveState") != "active":
            self.say(f"enable --now {units.RECONCILE_TIMER}")
            if not self.dry_run:
                self.systemctl.call("enable", "--now", units.RECONCILE_TIMER)
        code = 0 if preview_only else self.report(self.reconcile(), quiet=False)
        if not self.dry_run:
            _atomic_write(
                os.path.join(self.paths.state, "installed.json"),
                json.dumps(
                    {
                        "version": __version__,
                        "release": self.current_release(),
                        "installed_at": round(self.probe.now()),
                        "units": {
                            n: hashlib.sha256(t.encode()).hexdigest()
                            for n, t in units.render(self.paths).items()
                        },
                    },
                    indent=2,
                )
                + "\n",
            )
        return code

    def uninstall(self) -> int:
        self.require_root()
        found = self.systemctl.instances()
        uid = None
        try:
            config = self.load_config()
            found |= {units.instance(c.id) for c in config.cameras}
            uid = self.probe.uid(config.client_user)
        except (ConfigError, OSError):
            pass
        # Fail open first: Protect goes direct before any service is touched. The
        # conntrack anchor stays until instances have drained in-flight requests;
        # the marker stops their ExecStopPost hooks from re-adding redirects.
        if not self.dry_run:
            _atomic_write(self.uninstall_marker, "uninstalling\n", 0o600)
        with self.lock():
            installed = self.firewall.read().installed
            lines, state = self.firewall.converge(
                set(), uid, anchor=uid is not None and installed, dry_run=self.dry_run
            )
            for line in lines:
                self.say(f"iptables-restore: {line}")
        acted = bool(lines) or state.installed
        timer = self.systemctl.show([units.RECONCILE_TIMER]).get(units.RECONCILE_TIMER, {})
        if timer.get("LoadState") == "loaded" and (
            timer.get("UnitFileState") == "enabled" or timer.get("ActiveState") in ACTIVE_STATES
        ):
            acted = True
            self.say(f"disable --now {units.RECONCILE_TIMER}")
            if not self.dry_run:
                self.systemctl.call("disable", "--now", units.RECONCILE_TIMER)
        props = self.systemctl.show(sorted(found))
        for unit in sorted(found):
            p = props.get(unit, {})
            if p.get("UnitFileState") == "enabled" or p.get("ActiveState") in ACTIVE_STATES + (
                "failed",
            ):
                acted = True
                self.say(f"disable --now {unit}")
                if not self.dry_run:
                    self.systemctl.call("disable", "--now", unit)
                    self.systemctl.call("reset-failed", unit)
        removed = False
        for name in units.UNIT_FILES:
            path = os.path.join(self.paths.unit_dir, name)
            if os.path.exists(path):
                removed = True
                self.say(f"remove {path}")
                if not self.dry_run:
                    os.unlink(path)
        if removed:
            self.say("systemctl daemon-reload")
            if not self.dry_run:
                self.systemctl.call("daemon-reload")
        if self.dry_run:
            self.say("remove conntrack anchor, jump and chain after instances stop")
        else:
            # Instances are stopped (drained); now remove the anchor and verify.
            with self.lock():
                lines, state = self.firewall.remove_all()
            for line in lines:
                self.say(f"iptables-restore: {line}")
            if os.path.exists(self.uninstall_marker):
                os.unlink(self.uninstall_marker)
            if state.installed:
                self.out("ALERT firewall chain still present after uninstall")
                return 1
        if not (acted or removed):
            self.say("nothing installed")
        self.say(f"kept {self.paths.base} (configuration and releases)")
        return 0

    # --- per-camera lifecycle ------------------------------------------------------

    def set_enabled(self, camera_id: str, enabled: bool) -> int:
        self.require_root()
        raw = load_raw(self.paths.config)
        cameras = raw.get("cameras") if isinstance(raw, dict) else None
        entry = next(
            (c for c in cameras or [] if isinstance(c, dict) and c.get("id") == camera_id), None
        )
        if entry is None:
            raise CtlError(f"unknown camera id {camera_id!r}")
        unit = units.instance(camera_id)
        if entry.get("enabled") is not enabled:
            entry["enabled"] = enabled
            from_dict(raw)  # validate before writing
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            backup = os.path.join(self.paths.backups, f"cameras.json.{stamp}")
            self.say(f"backup {self.paths.config} -> {backup}")
            self.say(f"set cam={camera_id} enabled={str(enabled).lower()}")
            if not self.dry_run:
                os.makedirs(self.paths.backups, exist_ok=True)
                shutil.copy2(self.paths.config, backup)
                _atomic_write(self.paths.config, json.dumps(raw, indent=2) + "\n")
        else:
            self.say(f"cam={camera_id} already enabled={str(enabled).lower()}")
        if self.dry_run:
            # Simulate the outcome without writing the configuration.
            action = "enable --now" if enabled else "remove redirect, then disable --now"
            self.say(f"would {action} {unit}")
            return 0
        if enabled:
            self.systemctl.call("enable", unit)
            if not self.systemctl.call("start", unit):
                self.out(f"WARN start failed: {unit}; redirect stays off")
        else:
            # Redirect first, so new connections go straight to the camera; then stop
            # the instance, which drains in-flight long polls (bounded) before exit.
            self.report(self.reconcile(manage_units=False), quiet=True)
            self.systemctl.call("disable", "--now", unit)
        return self.report(self.reconcile(), quiet=False)

    def reset(self, camera_id: str) -> int:
        self.require_root()
        self.load_config().camera(camera_id)
        unit = units.instance(camera_id)
        self.say(f"reset-failed + start {unit}")
        if not self.dry_run:
            self.systemctl.call("reset-failed", unit)
            if not self.systemctl.call("start", unit):
                self.out(f"WARN start failed: {unit}; redirect stays off")
        return self.report(self.reconcile(), quiet=False)

    def bypass_all(self, on: bool) -> int:
        self.require_root()
        if on:
            self.say(f"create {self.paths.bypass_flag} (all redirects off until `resume`)")
            if not self.dry_run:
                _atomic_write(self.paths.bypass_flag, "bypass\n", 0o600)
        else:
            self.say(f"remove {self.paths.bypass_flag}")
            if not self.dry_run and os.path.exists(self.paths.bypass_flag):
                os.unlink(self.paths.bypass_flag)
        return self.report(self.reconcile(manage_units=False), quiet=False)

    def rollback_release(self, target: str | None) -> int:
        self.require_root()
        history = self._history().get("history", [])
        target = target or (history[0] if history else None)
        if not target:
            raise CtlError("no previous release recorded")
        if not self.switch_release(target):
            self.say(f"release {target} already current")
            return 0
        if self.dry_run:
            return 0
        for camera in self.load_config().enabled:
            unit = units.instance(camera.id)
            self.say(f"restart {unit}")
            self.systemctl.call("restart", unit)
        return self.report(self.reconcile(), quiet=False)

    # --- status --------------------------------------------------------------------

    def status(self, *, as_json: bool, camera_id: str | None = None) -> int:
        outcome = Outcome()
        try:
            config = self.load_config()
        except (ConfigError, OSError) as exc:
            self.out(f"ALERT config_invalid detail={exc}")
            return 2
        cameras = [config.camera(camera_id)] if camera_id else list(config.cameras)
        props = self.systemctl.show([units.instance(c.id) for c in cameras])
        try:
            state = self.firewall.read()
        except FirewallError as exc:
            state = None
            outcome.alerts.append(f"firewall_unreadable detail={exc}")
        timer = self.systemctl.show([units.RECONCILE_TIMER]).get(units.RECONCILE_TIMER, {})
        redirected = {r.camera_id for r in state.redirects} if state else set()
        jump_ok = bool(state and state.jumps)
        rows = []
        for camera in cameras:
            p = props.get(units.instance(camera.id), {})
            healthy, reason, status = self.health(camera, config, p)
            status = status or self.probe.read_status(self.paths.status_file(camera.id)) or {}
            pulls = status.get("pulls") or {}
            rows.append(
                {
                    "camera": camera.id,
                    "enabled": camera.enabled,
                    "mode": camera.mode,
                    "unit": p.get("ActiveState", "unknown"),
                    "restarts": p.get("NRestarts"),
                    "redirect": camera.id in redirected and jump_ok,
                    "process_healthy": healthy,
                    "process_reason": reason,
                    "event_transport": status.get("event_transport", "unknown"),
                    "pulls_ok": pulls.get("ok"),
                    "pulls_failed": pulls.get("failed"),
                    "pull_last_failure": pulls.get("last_failure"),
                    "repairs": status.get("repairs"),
                    "last_motion_notification_at": pulls.get("last_motion_true_at"),
                    "upstream": status.get("upstream"),
                    "requests": status.get("requests"),
                    "detection_verified": False,
                    "recording": "not_assessed (verify in Protect)",
                }
            )
        summary = {
            "version": __version__,
            "release": self.current_release(),
            "timer": timer.get("ActiveState", "unknown"),
            "chain": bool(state and state.chain_exists),
            "jump": jump_ok,
            "bypass_all": os.path.exists(self.paths.bypass_flag),
            "conntrack_count": self.probe.conntrack_count(),
            "foreign_dnat": sorted(
                f"{ip}:{port}" for ip, port in (state.foreign_dnat if state else [])
            ),
            "cameras": rows,
        }
        if as_json:
            self.out(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        self.out(
            f"onvif-shim {summary['version']} release={summary['release']} "
            f"timer={summary['timer']} chain={'yes' if summary['chain'] else 'no'} "
            f"jump={'yes' if jump_ok else 'no'} bypass_all={summary['bypass_all']} "
            f"conntrack={summary['conntrack_count']}"
        )
        header = (
            f"{'CAMERA':<20} {'EN':<3} {'UNIT':<12} {'REDIR':<5} {'PROCESS':<20} "
            f"{'TRANSPORT':<10} {'PULLS ok/fail':<14} {'REPAIRED':<8} LAST MOTION NOTIF"
        )
        self.out(header)
        for row in rows:
            motion = row["last_motion_notification_at"]
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(motion)) if motion else "never"
            repaired = (row["repairs"] or {}).get("repaired", 0)
            self.out(
                f"{row['camera']:<20} {'y' if row['enabled'] else 'n':<3} {row['unit']:<12} "
                f"{'on' if row['redirect'] else 'off':<5} "
                f"{('healthy' if row['process_healthy'] else row['process_reason']):<20} "
                f"{row['event_transport']:<10} "
                f"{str(row['pulls_ok'] or 0) + '/' + str(row['pulls_failed'] or 0):<14} "
                f"{repaired:<8} {when}"
            )
        self.out(
            "Detection is NOT verified by this tool: confirm motion events on the Protect "
            "timeline. Recording health is not assessed: confirm recordings advance in Protect."
        )
        for alert in outcome.alerts:
            self.out(f"ALERT {alert}")
        return 0


def _print_validation(config: Config, out) -> None:
    out(
        f"Valid configuration: {len(config.cameras)} camera(s), {len(config.enabled)} enabled, "
        f"client_user={config.client_user}"
    )
    for c in config.cameras:
        out(
            f"  {c.id:<20} {c.camera_ip}:{c.onvif_port} -> 127.0.0.1:{c.listen_port} "
            f"enabled={str(c.enabled).lower()} mode={c.mode} wsa={'+'.join(c.wsa_repair)}"
        )


def _wsa_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main(
    argv=None, *, runner=None, probe=None, out=print, check_ownership=True, input_fn=None
) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base", default=Paths.base, help="install root (default %(default)s)")
    common.add_argument("--unit-dir", default=Paths.unit_dir)
    common.add_argument("--run-dir", default=Paths.run_dir)
    common.add_argument("--lock-file", default=Paths.lock_file)
    common.add_argument("--dry-run", action="store_true", help="print actions, change nothing")
    parser = argparse.ArgumentParser(prog="shimctl.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name, help=None):
        return sub.add_parser(name, help=help, parents=[common])

    v = command("validate", "validate the inventory (optionally the host)")
    v.add_argument("--config", help="inventory to validate (default BASE/cameras.json)")
    v.add_argument("--preflight", action="store_true", help="also check this host (root, NVR)")
    i = command("install", "install/update units, start instances, reconcile")
    i.add_argument("--release", help="release directory name under BASE/releases")
    command("uninstall", "remove redirects, stop and remove units (keeps BASE)")
    r = command("reconcile", "converge services and redirects (timer entry point)")
    r.add_argument("--quiet", action="store_true")
    s = command("status", "sanitized health per camera")
    s.add_argument("camera", nargs="?")
    s.add_argument("--json", action="store_true")
    for name, text in (
        ("enable", "enable one camera (config + service + redirect)"),
        ("disable", "per-camera rollback: redirect off, service stopped"),
        ("reset", "clear a failed instance after fixing the cause"),
        ("activate", "unit hook: redirect once the instance serves"),
        ("deactivate", "unit hook: remove this camera's redirect"),
    ):
        command(name, text).add_argument("camera")
    command("bypass-all", "emergency: remove every redirect until `resume`")
    command("resume", "undo bypass-all")
    rb = command("rollback-release", "switch to the previous verified release")
    rb.add_argument("--to")
    command("units", "print generated unit files")
    c = command("cameras", "list Protect's third-party cameras and their shim status")
    c.add_argument("--needs-shim", action="store_true", help="only adopted cameras that need one")
    c.add_argument("--all", action="store_true", help="include discovered, unadopted cameras")
    c.add_argument("--json", action="store_true")
    a = command("add", "add a camera (by IP, Protect name or MAC) and apply it now")
    a.add_argument("selector", help="camera IP, Protect name (quoted) or MAC")
    a.add_argument("--id", dest="camera_id", help="inventory id (default: from Protect name)")
    a.add_argument("--name", help="display name (default: Protect name)")
    a.add_argument("--onvif-port", type=int, help="default: from Protect, else 8000")
    a.add_argument("--listen-port", type=int, help="default: 18100 + last IP octet, or next free")
    a.add_argument("--mode", choices=["passthrough", "ai_motion"], default="passthrough")
    a.add_argument("--wsa", type=_wsa_list, help="headers to add, e.g. To,Action,MessageID")
    a.add_argument("--no-must-understand", dest="must_understand", action="store_false")
    a.add_argument("--stage", action="store_true", help="write disabled; apply later with enable")
    command("remove", "redirect off, stop, and delete a camera from the inventory").add_argument(
        "camera"
    )
    command("setup", "interactive: pick Protect cameras to shim, then add and apply them")
    args = parser.parse_args(argv)
    paths = Paths(
        base=args.base,
        unit_dir=args.unit_dir,
        run_dir=args.run_dir,
        lock_file=args.lock_file,
    )
    ctl = Ctl(
        paths,
        runner=runner,
        probe=probe,
        out=out,
        dry_run=args.dry_run,
        check_ownership=check_ownership,
    )
    from .cameras import CameraError, CameraTool
    from .protect import ProtectUnavailable

    tool = CameraTool(ctl, input_fn=input_fn)
    try:
        if args.command == "cameras":
            return tool.list(needs_shim=args.needs_shim, show_all=args.all, as_json=args.json)
        if args.command == "add":
            opts = {
                key: getattr(args, key)
                for key in (
                    "camera_id",
                    "name",
                    "onvif_port",
                    "listen_port",
                    "mode",
                    "wsa",
                    "must_understand",
                    "stage",
                )
            }
            return tool.add(args.selector, opts)
        if args.command == "remove":
            return tool.remove(args.camera)
        if args.command == "setup":
            return tool.setup()
        if args.command == "validate":
            config = load(args.config or paths.config)
            _print_validation(config, out)
            if args.preflight:
                problems = ctl.preflight(config)
                for problem in problems:
                    out(f"PREFLIGHT {problem}")
                return 2 if problems else 0
            return 0
        if args.command == "units":
            for name, text in units.render(paths).items():
                out(f"### {name}\n{text}")
            return 0
        if args.command == "install":
            return ctl.install(args.release)
        if args.command == "uninstall":
            return ctl.uninstall()
        if args.command == "reconcile":
            return ctl.report(ctl.reconcile(), quiet=args.quiet)
        if args.command == "status":
            return ctl.status(as_json=args.json, camera_id=args.camera)
        if args.command in ("enable", "disable"):
            return ctl.set_enabled(args.camera, args.command == "enable")
        if args.command == "reset":
            return ctl.reset(args.camera)
        if args.command == "activate":
            return ctl.report(ctl.activate(args.camera), quiet=True)
        if args.command == "deactivate":
            return ctl.report(ctl.deactivate(args.camera), quiet=True)
        if args.command in ("bypass-all", "resume"):
            return ctl.bypass_all(args.command == "bypass-all")
        if args.command == "rollback-release":
            return ctl.rollback_release(args.to)
    except (
        CameraError,
        ConfigError,
        CtlError,
        FirewallError,
        OSError,
        ProtectUnavailable,
    ) as exc:
        out(f"ERROR {exc}")
        return 2
    return 2
