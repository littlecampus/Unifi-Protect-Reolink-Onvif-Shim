"""In-memory iptables (nat table, atomic restore) and systemctl for lifecycle tests.

The model follows iptables-legacy semantics that matter here: restore input is
applied as one transaction at COMMIT (all or nothing), user chains cannot be
deleted while referenced or non-empty, -D needs an exact rule match. Real
kernel behavior is covered separately by tests/kernel (Docker, root).
"""

from __future__ import annotations

import copy
import json
import os
import shlex
import subprocess

BUILTIN = ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")


def done(rc=0, out=""):
    return subprocess.CompletedProcess([], rc, out, "")


class FakeIptables:
    def __init__(self):
        self.chains: dict[str, list[list[str]]] = {name: [] for name in BUILTIN}
        self.restores: list[str] = []
        self.fail_restore = False

    def save(self) -> str:
        lines = [f"-P {name} ACCEPT" for name in BUILTIN]
        lines += [f"-N {name}" for name in self.chains if name not in BUILTIN]
        for name, rules in self.chains.items():
            for rule in rules:
                lines.append(
                    " ".join(["-A", name] + [shlex.quote(t) if " " in t else t for t in rule])
                )
        return "\n".join(lines) + "\n"

    def add_foreign(self, chain: str, rule: str):
        self.chains.setdefault(chain, []).append(shlex.split(rule))

    def restore(self, text: str) -> int:
        self.restores.append(text)
        if self.fail_restore:
            return 1
        work = copy.deepcopy(self.chains)
        for line in text.splitlines():
            line = line.strip()
            if not line or line in ("*nat", "COMMIT"):
                continue
            if line.startswith(":"):
                name = line[1:].split()[0]
                if name in work and name not in BUILTIN:
                    work[name] = []  # legacy --noflush flushes declared user chains
                work.setdefault(name, [])
                continue
            tokens = shlex.split(line)
            op, chain, rest = tokens[0], tokens[1], tokens[2:]
            if chain not in work:
                return 1
            if op == "-F":
                work[chain] = []
            elif op == "-X":
                referenced = any(
                    r[r.index("-j") + 1] == chain
                    for rules in work.values()
                    for r in rules
                    if "-j" in r
                )
                if referenced or work[chain] or chain in BUILTIN:
                    return 1
                del work[chain]
            elif op == "-A":
                if rest[rest.index("-j") + 1] not in work and rest[rest.index("-j") + 1] not in (
                    "DNAT",
                    "RETURN",
                    "ACCEPT",
                ):
                    return 1
                work[chain].append(rest)
            elif op == "-I":
                position = int(rest[0]) - 1
                target = rest[1:][rest[1:].index("-j") + 1]
                if target not in work and target not in ("DNAT", "RETURN", "ACCEPT"):
                    return 1
                work[chain].insert(position, rest[1:])
            elif op == "-D":
                if rest not in work[chain]:
                    return 1
                work[chain].remove(rest)
            else:
                return 1
        self.chains = work
        return 0


class FakeHost:
    """Dispatches Runner commands to fake iptables/systemctl; also a Probe."""

    def __init__(self, run_dir: str, unit_dir: str, *, protect_uid: int = 996):
        self.ipt = FakeIptables()
        self.run_dir = run_dir
        self.unit_dir = unit_dir
        self.units: dict[str, dict[str, str]] = {}
        self.calls: list[list[str]] = []
        self.protect_uid = protect_uid
        self.listening_ports: set[int] = set()
        self.now_value = 1_000_000.0
        self.next_pid = 4000
        self.ports: dict[str, int] = {}  # camera id -> listen port
        self.start_fails: set[str] = set()
        self.owner_match = True
        self.root = True

    # --- Runner ---
    def run(self, argv, input=None):
        self.calls.append(list(argv))
        tool = argv[0]
        if tool == "iptables":
            if "-S" in argv:
                return done(0, self.ipt.save())
            if "-m" in argv and "owner" in argv:
                return done(0 if self.owner_match else 2)
            return done(2)
        if tool == "iptables-restore":
            return done(self.ipt.restore(input or ""))
        if tool == "systemctl":
            return self._systemctl(argv[1:])
        return done(127)

    def mutating_calls(self):
        readonly = {"show", "list-units"}
        out = []
        for call in self.calls:
            if call[0] == "systemctl" and call[1] not in readonly:
                out.append(call)
            if call[0] == "iptables-restore":
                out.append(call)
        return out

    def unit(self, name):
        return self.units.setdefault(
            name,
            {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": "0",
                "Result": "success",
                "UnitFileState": "disabled",
                "NRestarts": "0",
            },
        )

    def _camera(self, name):
        if name.startswith("onvif-shim@"):
            return name[len("onvif-shim@") : -len(".service")]
        return None

    def start_unit(self, name):
        unit = self.unit(name)
        cam = self._camera(name)
        if cam in self.start_fails:
            unit.update(ActiveState="failed", SubState="failed", MainPID="0", Result="exit-code")
            return False
        self.next_pid += 1
        unit.update(ActiveState="active", SubState="running", MainPID=str(self.next_pid))
        if cam is not None:
            self.write_status(cam, pid=self.next_pid)
            if cam in self.ports:
                self.listening_ports.add(self.ports[cam])
        return True

    def stop_unit(self, name):
        unit = self.unit(name)
        unit.update(ActiveState="inactive", SubState="dead", MainPID="0")
        cam = self._camera(name)
        if cam is not None:
            path = os.path.join(self.run_dir, cam, "status.json")
            if os.path.exists(path):
                os.unlink(path)
            self.listening_ports.discard(self.ports.get(cam))

    def write_status(self, cam, *, pid, serviceable=True, heartbeat=None, reason=None):
        os.makedirs(os.path.join(self.run_dir, cam), exist_ok=True)
        with open(os.path.join(self.run_dir, cam, "status.json"), "w") as out:
            json.dump(
                {
                    "camera": cam,
                    "pid": pid,
                    "heartbeat_at": self.now_value if heartbeat is None else heartbeat,
                    "process": {"serviceable": serviceable, "unsafe_reason": reason},
                    "event_transport": "unobserved",
                    "pulls": {"ok": 0, "failed": 0},
                    "repairs": {},
                },
                out,
            )

    def _systemctl(self, args):
        verb = args[0]
        rest = [a for a in args[1:] if not a.startswith("--")]
        if verb == "show":
            names = [
                a for a in args[1:] if not a.startswith("-") and a not in self._show_props(args)
            ]
            blocks = []
            for name in names:
                unit = self.unit(name) if name in self.units or self._known(name) else None
                props = unit or {"LoadState": "not-found", "ActiveState": "inactive"}
                blocks.append("\n".join(f"{k}={v}" for k, v in {"Id": name, **props}.items()))
            return done(0, "\n\n".join(blocks) + "\n")
        if verb == "list-units":
            lines = [
                f"{n} loaded {u['ActiveState']} {u['SubState']} x"
                for n, u in self.units.items()
                if n.startswith("onvif-shim@") and u["ActiveState"] != "inactive"
            ]
            return done(0, "\n".join(lines))
        if verb == "daemon-reload":
            return done(0)
        if verb == "enable":
            for name in rest:
                self.unit(name)["UnitFileState"] = "enabled"
                if "--now" in args:
                    self.start_unit(name)
                self._link(name, True)
            return done(0)
        if verb == "disable":
            for name in rest:
                self.unit(name)["UnitFileState"] = "disabled"
                if "--now" in args:
                    self.stop_unit(name)
                self._link(name, False)
            return done(0)
        if verb in ("start", "restart"):
            ok = all(self.start_unit(name) for name in rest)
            return done(0 if ok else 1)
        if verb == "stop":
            for name in rest:
                self.stop_unit(name)
            return done(0)
        if verb == "reset-failed":
            for name in rest:
                if self.unit(name)["ActiveState"] == "failed":
                    self.unit(name).update(ActiveState="inactive", SubState="dead")
            return done(0)
        return done(1)

    def _show_props(self, args):
        return {args[args.index("-p") + 1]} if "-p" in args else set()

    def _known(self, name):
        return name.startswith("onvif-shim")

    def _link(self, name, on):
        if not name.startswith("onvif-shim@"):
            return
        wants = os.path.join(self.unit_dir, "multi-user.target.wants")
        os.makedirs(wants, exist_ok=True)
        path = os.path.join(wants, name)
        if on and not os.path.exists(path):
            open(path, "w").close()
        if not on and os.path.exists(path):
            os.unlink(path)

    # --- Probe ---
    def uid(self, user):
        return self.protect_uid if user == "unifi-protect" else None

    def now(self):
        return self.now_value

    def listening(self, port):
        return port in self.listening_ports

    def read_status(self, path):
        try:
            with open(path) as source:
                return json.load(source)
        except (OSError, ValueError):
            return None

    def is_local_ip(self, ip):
        return ip == "10.48.20.10"

    def conntrack_count(self):
        return 0

    def euid(self):
        return 0 if self.root else 1000

    def which(self, tool):
        return f"/usr/sbin/{tool}"
