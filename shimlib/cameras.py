"""Camera onboarding: list Protect's cameras, add/remove them in the inventory.

`shimctl cameras` joins Protect's third-party cameras (read-only, see protect.py)
with the inventory; `shimctl add` derives an inventory entry from Protect (id,
name, ONVIF port), assigns a free listener port, writes the inventory (with a
backup) and applies it immediately; `shimctl remove` reverses that;
`shimctl setup` is the interactive front end for `add`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import sys
import time

from . import protect, units
from .config import HTTP_PORTS, MAX_CAMERAS, SCHEMA_VERSION, ConfigError, from_dict, parse_json
from .ctl import _atomic_write
from .protect import ProtectCamera, ProtectUnavailable

PORT_BASE = 18100
PORT_LAST = 18999
NEEDS_SHIM = "misconfigured"


class CameraError(RuntimeError):
    pass


def slug(name: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if value and not value[0].isalpha():
        value = "cam_" + value
    return value[:32].rstrip("_")


def is_ipv4(value: str) -> bool:
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def normalize_mac(value: str) -> str | None:
    compact = re.sub(r"[:\-.]", "", value).upper()
    return compact if re.fullmatch(r"[0-9A-F]{12}", compact) else None


class CameraTool:
    def __init__(self, ctl, *, input_fn=None):
        self.ctl = ctl
        self.out = ctl.out
        self.input_fn = input_fn

    # --- data -------------------------------------------------------------------

    def protect_cameras(self, *, warn: bool = True) -> list[ProtectCamera] | None:
        try:
            return protect.query(self.ctl.runner)
        except ProtectUnavailable as exc:
            if warn:
                self.out(f"WARN cannot read Protect's camera list: {exc}")
            return None

    def raw_inventory(self) -> dict:
        path = self.ctl.paths.config
        if not os.path.exists(path):
            return {"schema_version": SCHEMA_VERSION, "client_user": "unifi-protect", "cameras": []}
        with open(path, "rb") as source:
            raw = parse_json(source.read())
        if not isinstance(raw.get("cameras"), list):
            raise CameraError("inventory has no camera list")
        return raw

    def shim_state(self, raw: dict) -> dict[str, dict]:
        """camera_ip -> {"id", "enabled", "redirect"} for inventory entries."""
        try:
            redirected = {r.camera_ip for r in self.ctl.firewall.read().redirects}
        except Exception:  # noqa: BLE001 - listing must work without firewall access
            redirected = set()
        state = {}
        for entry in raw["cameras"]:
            if isinstance(entry, dict) and isinstance(entry.get("camera_ip"), str):
                state[entry["camera_ip"]] = {
                    "id": entry.get("id"),
                    "enabled": entry.get("enabled") is True,
                    "redirect": entry["camera_ip"] in redirected,
                }
        return state

    @staticmethod
    def advice(cam: ProtectCamera, shim: dict | None) -> str:
        if not cam.adopted:
            return "not adopted in Protect"
        if shim:
            if not shim["enabled"]:
                return "in inventory, disabled"
            if cam.motion == NEEDS_SHIM:
                return "shimmed; Protect retries within 5 min"
            return "shimmed"
        if cam.motion == NEEDS_SHIM:
            return "NEEDS SHIM"
        return "ok without shim"

    # --- shimctl cameras ---------------------------------------------------------

    def list(self, *, needs_shim: bool, show_all: bool, as_json: bool) -> int:
        self.ctl.require_root()
        cams = self.protect_cameras()
        if cams is None:
            return 2
        raw = self.raw_inventory()
        state = self.shim_state(raw)
        rows = []
        for cam in cams:
            shim = state.get(cam.host or "")
            advice = self.advice(cam, shim)
            if needs_shim and advice != "NEEDS SHIM":
                continue
            if not show_all and not needs_shim and not cam.adopted:
                continue
            rows.append((cam, shim, advice))
        if as_json:
            self.out(
                json.dumps(
                    [
                        {
                            "name": c.name,
                            "ip": c.host,
                            "mac": c.mac,
                            "vendor": c.vendor,
                            "protect_type": c.type,
                            "adopted": c.adopted,
                            "onvif_port": c.onvif_port,
                            "protect_motion": c.motion,
                            "shim": s,
                            "advice": a,
                        }
                        for c, s, a in rows
                    ],
                    indent=2,
                )
            )
            return 0
        self.out(
            f"{'#':>3}  {'NAME':<22} {'IP':<15} {'MAC':<12} {'VENDOR':<8} {'ONVIF':<5} "
            f"{'PROTECT MOTION':<15} {'SHIM':<16} ADVICE"
        )
        for number, (cam, shim, advice) in enumerate(rows, 1):
            if shim:
                shim_text = f"{shim['id']}:" + (
                    "on" if shim["redirect"] else ("off" if shim["enabled"] else "disabled")
                )
            else:
                shim_text = "-"
            self.out(
                f"{number:>3}  {cam.label[:22]:<22} {cam.host or '?':<15} {cam.mac or '?':<12} "
                f"{cam.vendor[:8]:<8} {str(cam.onvif_port or '?'):<5} "
                f"{(cam.motion or '-')[:15]:<15} {shim_text[:16]:<16} {advice}"
            )
        hidden = sum(1 for cam in cams if not cam.adopted)
        if not show_all and not needs_shim and hidden:
            self.out(f"({hidden} discovered but unadopted cameras hidden; --all to show)")
        return 0

    # --- shimctl add -------------------------------------------------------------

    def resolve(self, selector: str, cams: list[ProtectCamera] | None) -> ProtectCamera | None:
        if cams is None:
            return None
        if is_ipv4(selector):
            matches = [c for c in cams if c.host == selector]
        elif normalize_mac(selector):
            matches = [c for c in cams if c.mac == normalize_mac(selector)]
        else:
            matches = [c for c in cams if (c.name or "").casefold() == selector.casefold()]
        adopted = [c for c in matches if c.adopted]
        matches = adopted or matches
        if len(matches) > 1:
            raise CameraError(f"{selector!r} matches {len(matches)} Protect cameras; use the IP")
        return matches[0] if matches else None

    def assign_port(self, raw: dict, ip: str) -> int:
        used = {e.get("listen_port") for e in raw["cameras"] if isinstance(e, dict)}
        onvif = {e.get("onvif_port") for e in raw["cameras"] if isinstance(e, dict)}
        preferred = PORT_BASE + int(ip.rsplit(".", 1)[1])
        for port in [preferred, *range(PORT_BASE, PORT_LAST + 1)]:
            if port not in used and port not in onvif and not self.ctl.probe.listening(port):
                return port
        raise CameraError(f"no free listener port in {PORT_BASE}..{PORT_LAST}")

    def plan(self, selector: str, cams: list[ProtectCamera] | None, raw: dict, opts: dict):
        """(entry, warnings) for a new inventory camera; raises CameraError."""
        cam = self.resolve(selector, cams)
        warnings = []
        if cam is None:
            if not is_ipv4(selector):
                hint = "see `shimctl cameras`" if cams is not None else "use the camera IP"
                raise CameraError(f"no Protect camera matches {selector!r}; {hint}")
            ip = selector
            if cams is not None:
                warnings.append(f"{ip} is not a third-party camera in Protect")
        else:
            ip = cam.host
            if not ip:
                raise CameraError(f"Protect has no IP address for {cam.label!r}")
            if not cam.adopted:
                warnings.append(f"{cam.label} is not adopted in Protect: no effect until it is")
            if cam.motion and cam.motion != NEEDS_SHIM:
                warnings.append(f"Protect reports motion '{cam.motion}' (not misconfigured)")
            if not cam.is_reolink:
                warnings.append(f"vendor {cam.vendor}: the repair is proven only for Reolink")
        for entry in raw["cameras"]:
            if isinstance(entry, dict) and entry.get("camera_ip") == ip:
                state = "enabled" if entry.get("enabled") else "disabled"
                raise CameraError(
                    f"{ip} is already in the inventory as {entry.get('id')!r} ({state}); "
                    f"use `shimctl enable {entry.get('id')}`"
                )
        if len(raw["cameras"]) >= MAX_CAMERAS:
            raise CameraError(f"inventory already has {MAX_CAMERAS} cameras")
        ids = {e.get("id") for e in raw["cameras"] if isinstance(e, dict)}
        camera_id = opts.get("camera_id")
        if camera_id is None:
            base = slug(cam.name) if cam and cam.name else ""
            base = base or "cam_" + ip.replace(".", "_")
            camera_id, n = base, 2
            while camera_id in ids:
                suffix = f"_{n}"
                camera_id, n = base[: 32 - len(suffix)] + suffix, n + 1
        elif camera_id in ids:
            raise CameraError(f"camera id {camera_id!r} is already used")
        onvif_port = opts.get("onvif_port") or (cam.onvif_port if cam else None)
        if onvif_port is None:
            onvif_port = 8000
            warnings.append("ONVIF port unknown; assuming Reolink's 8000 (override: --onvif-port)")
        entry = {"id": camera_id}
        name = opts.get("name") or (cam.name if cam else None)
        if name:
            entry["name"] = "".join(ch for ch in name if ch.isprintable())[:64]
        entry.update(
            camera_ip=ip,
            onvif_port=onvif_port,
            listen_port=opts.get("listen_port") or self.assign_port(raw, ip),
            enabled=not opts.get("stage", False),
        )
        if onvif_port in HTTP_PORTS:
            entry["onvif_port_shared_with_http"] = True
            warnings.append(
                f"ONVIF shares the camera's web port {onvif_port}: Protect's snapshot requests "
                "to this camera will also pass through the shim (unchanged)"
            )
        if opts.get("mode") and opts["mode"] != "passthrough":
            entry["mode"] = opts["mode"]
        if opts.get("wsa"):
            entry["wsa_repair"] = opts["wsa"]
        if opts.get("must_understand") is False:
            entry["wsa_must_understand"] = False
        return entry, warnings

    def _write(self, raw: dict) -> None:
        paths = self.ctl.paths
        if os.path.exists(paths.config):
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            backup = os.path.join(paths.backups, f"cameras.json.{stamp}")
            os.makedirs(paths.backups, exist_ok=True)
            shutil.copy2(paths.config, backup)
            self.out(f"backup {paths.config} -> {backup}")
        _atomic_write(paths.config, json.dumps(raw, indent=2) + "\n")

    def installed(self) -> bool:
        return os.path.exists(os.path.join(self.ctl.paths.unit_dir, units.TEMPLATE))

    def add(self, selector: str, opts: dict, *, cams=None, quiet_listing=False) -> int:
        self.ctl.require_root()
        stage = opts.get("stage", False)
        if not stage and not self.ctl.dry_run and not self.installed():
            raise CameraError("the shim is not installed yet: run install.sh first, or use --stage")
        if cams is None:
            cams = self.protect_cameras()
        raw = self.raw_inventory()
        entry, warnings = self.plan(selector, cams, raw, opts)
        candidate = dict(raw, cameras=[*raw["cameras"], entry])
        try:
            config = from_dict(candidate)
        except ConfigError as exc:
            raise CameraError(f"invalid camera entry: {exc}") from None
        for warning in warnings:
            self.out(f"WARN {warning}")
        self.ctl.say(f"add to {self.ctl.paths.config}:")
        self.out(json.dumps(entry, indent=2))
        if not stage:
            problems = [
                p
                for p in self.ctl.preflight(config)
                if "cam=" not in p or f"cam={entry['id']} " in p
            ]
            if problems:
                for problem in problems:
                    self.out(f"PREFLIGHT {problem}")
                return 2
        unit = units.instance(entry["id"])
        if self.ctl.dry_run:
            if not stage:
                self.ctl.say(f"enable --now {unit}; redirect once it serves")
            return 0
        self._write(candidate)
        if stage:
            self.out(f"staged {entry['id']} (disabled); apply with `shimctl enable {entry['id']}`")
            return 0
        self.ctl.systemctl.call("enable", unit)
        if not self.ctl.systemctl.call("start", unit):
            self.out(f"WARN start failed: {unit}; redirect stays off (journalctl -u {unit})")
        code = self.ctl.report(self.ctl.reconcile(), quiet=True)
        self.ctl.status(as_json=False, camera_id=entry["id"])
        return code

    # --- shimctl remove ----------------------------------------------------------

    def remove(self, camera_id: str) -> int:
        self.ctl.require_root()
        raw = self.raw_inventory()
        keep = [e for e in raw["cameras"] if not (isinstance(e, dict) and e.get("id") == camera_id)]
        if len(keep) == len(raw["cameras"]):
            raise CameraError(f"unknown camera id {camera_id!r}")
        unit = units.instance(camera_id)
        self.ctl.say(f"remove {camera_id} from {self.ctl.paths.config}")
        if self.ctl.dry_run:
            self.ctl.say(f"redirect off, then disable --now {unit}")
            return 0
        self._write(dict(raw, cameras=keep))
        # Redirect first (camera no longer configured), then stop the instance, which
        # drains in-flight polls; the anchor stays until no instance is running.
        self.ctl.report(self.ctl.reconcile(manage_units=False), quiet=True)
        self.ctl.systemctl.call("disable", "--now", unit)
        return self.ctl.report(self.ctl.reconcile(), quiet=False)

    # --- shimctl setup -----------------------------------------------------------

    def setup(self) -> int:
        self.ctl.require_root()
        ask = self.input_fn
        if ask is None:
            if not sys.stdin.isatty():
                raise CameraError("setup is interactive; use `shimctl cameras` and `shimctl add`")
            ask = input
        cams = self.protect_cameras()
        if cams is None:
            return 2
        raw = self.raw_inventory()
        shimmed = {e.get("camera_ip") for e in raw["cameras"] if isinstance(e, dict)}
        candidates = [c for c in cams if c.adopted and c.host and c.host not in shimmed]
        candidates.sort(key=lambda c: (c.motion != NEEDS_SHIM, not c.is_reolink, c.label))
        if not candidates:
            self.out("Every adopted third-party camera is already in the inventory.")
            return 0
        self.out("Adopted third-party cameras not yet shimmed:")
        for number, cam in enumerate(candidates, 1):
            flag = "NEEDS SHIM" if cam.motion == NEEDS_SHIM else (cam.motion or "-")
            self.out(
                f"{number:>3}  {cam.label[:22]:<22} {cam.host:<15} {cam.vendor[:8]:<8} "
                f"ONVIF {str(cam.onvif_port or '?'):<5} {flag}"
            )
        answer = ask("Cameras to add (e.g. 1,3 or 'all'; Enter cancels): ").strip().lower()
        if not answer:
            self.out("cancelled")
            return 0
        try:
            if answer == "all":
                chosen = candidates
            else:
                chosen = [candidates[int(x) - 1] for x in re.split(r"[,\s]+", answer) if x]
        except (ValueError, IndexError):
            raise CameraError(f"invalid selection {answer!r}") from None
        planned = dict(raw, cameras=list(raw["cameras"]))
        for cam in chosen:
            entry, warnings = self.plan(cam.host, cams, planned, {})
            planned["cameras"].append(entry)
            for warning in warnings:
                self.out(f"WARN {warning}")
            self.out(
                f"  {entry['id']}: {cam.host}:{entry['onvif_port']} -> "
                f"127.0.0.1:{entry['listen_port']} (header-only)"
            )
        if self.ctl.dry_run:
            self.ctl.say("would add and apply the cameras above")
            return 0
        if ask("Add and apply now? [y/N]: ").strip().lower() not in ("y", "yes"):
            self.out("cancelled")
            return 0
        code = 0
        for cam in chosen:
            code = max(code, self.add(cam.host, {}, cams=cams))
        return code
