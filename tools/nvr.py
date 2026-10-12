#!/usr/bin/env python3
"""Drive a remote UniFi console's shim from this workstation over SSH.

Development tool; not shipped to the console. Targets live in
.claude/nvr-targets.json (gitignored; format: .claude/nvr-targets.example.json).
SSH runs in batch mode, so each target needs key authentication as root.

    python3 tools/nvr.py targets                         list configured targets
    python3 tools/nvr.py targets add NAME --ssh DEST --production true|false
    python3 tools/nvr.py targets remove NAME
    python3 tools/nvr.py snapshot TARGET                 read-only health/inventory bundle
    python3 tools/nvr.py shimctl TARGET status --json    run shimctl on the console
    python3 tools/nvr.py shimctl TARGET --release V cameras   ...from an uploaded release
    python3 tools/nvr.py run TARGET -- 'journalctl -u onvif-shim@cam -n 50 -o cat'
    python3 tools/nvr.py upload TARGET dist/onvif-shim-V.tar.gz   copy, verify, extract

`upload` writes only /root/<tarball> and /data/onvif-shim/releases/V on the console;
installing the release is a separate step (install.sh).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_FILE = os.environ.get("NVR_TARGETS", os.path.join(ROOT, ".claude", "nvr-targets.json"))
BASE = "/data/onvif-shim"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
TARGET_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
TARBALL = re.compile(r"^onvif-shim-(?P<version>[0-9][A-Za-z0-9.+-]*)\.tar\.gz$")

# Read-only: every command only reads state. Sections are printed even when a
# component is missing, so the bundle works before the first install too.
SNAPSHOT = r"""
B=/data/onvif-shim
section() { printf '\n=== %s ===\n' "$1"; }
section identity
echo "user=$(id -un) host=$(hostname) date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ubnt-device-info firmware 2>&1 || echo "ubnt-device-info unavailable"
dpkg-query -W unifi-protect unifi-core 2>&1
python3 -VV 2>&1; iptables -V 2>&1; id unifi-protect 2>&1
uptime; free -m
section install
if [ -L $B/current ]; then echo "current -> $(readlink $B/current)"
else echo "current: none (not installed)"; fi
ls $B/releases 2>/dev/null || echo "no releases"
cat $B/state/releases.json 2>/dev/null
cat $B/state/installed.json 2>/dev/null
ls /etc/systemd/system 2>/dev/null | grep onvif-shim || echo "no onvif-shim unit files"
[ -e /etc/systemd/system/onvif-shim.service ] && echo "LEGACY v1 onvif-shim.service present"
[ -e $B/state/bypass-all ] && echo "BYPASS-ALL ACTIVE"
section units
systemctl list-units 'onvif-shim*' --all --no-legend --no-pager 2>&1
if [ -e $B/current/shimctl.py ]; then
  S="python3 -I $B/current/shimctl.py"
  section "shimctl validate --preflight"; $S validate --preflight 2>&1
  section "shimctl status --json"; $S status --json 2>&1
  section "shimctl cameras --json"; $S cameras --json 2>&1
fi
section firewall
iptables -t nat -S 2>&1 | grep -E 'ONVIF_SHIM|onvif-shim|DNAT' || echo "no shim or DNAT nat rules"
iptables -t nat -L ONVIF_SHIM -n -v 2>/dev/null
echo "nf_conntrack_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
section "protect onvif.events.log"
grep -iE "circuit-breaker|Deactivated ONVIF|Started ONVIF|misconfigured" \
  /srv/unifi-protect/logs/onvif.events.log 2>&1 | tail -n 40
section "reconcile journal"
journalctl -u onvif-shim-reconcile -n 30 -o short-iso --no-pager 2>&1
"""


def fail(message: str) -> None:
    raise SystemExit(f"nvr: {message}")


def read_targets() -> dict:
    """Configured targets; empty when the file does not exist yet."""
    try:
        with open(TARGETS_FILE) as source:
            data = json.load(source)
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        fail(f"{TARGETS_FILE}: {exc}")
    targets = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(targets, dict):
        fail(f'{TARGETS_FILE}: expected {{"targets": {{NAME: {{"ssh": ...}}}}}}')
    for name, target in targets.items():
        if not isinstance(target, dict) or not isinstance(target.get("ssh"), str):
            fail(f'{TARGETS_FILE}: target {name!r} needs an "ssh" destination')
        if not isinstance(target.get("production"), bool):
            fail(f'{TARGETS_FILE}: target {name!r} needs "production": true or false')
    return targets


def load_targets() -> dict:
    targets = read_targets()
    if not targets:
        fail(
            "no targets configured; add one with "
            "`nvr.py targets add NAME --ssh DEST --production true|false`"
        )
    return targets


def write_targets(targets: dict) -> None:
    os.makedirs(os.path.dirname(TARGETS_FILE), exist_ok=True)
    tmp = TARGETS_FILE + ".tmp"
    with open(tmp, "w") as sink:
        sink.write(json.dumps({"targets": targets}, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, TARGETS_FILE)


def target(name: str) -> dict:
    targets = load_targets()
    if name not in targets:
        fail(f"unknown target {name!r}; configured: {', '.join(sorted(targets))}")
    return targets[name]


def ssh(name: str, remote: str, *, stdin: str | None = None, check: bool = False) -> int:
    dest = target(name)["ssh"]
    result = subprocess.run(["ssh", *SSH_OPTS, dest, remote], input=stdin, text=True)
    if check and result.returncode != 0:
        fail(f"remote command failed ({result.returncode}): {remote}")
    return result.returncode


def ssh_output(name: str, remote: str) -> str:
    return dest_output(target(name)["ssh"], remote)


def dest_output(dest: str, remote: str) -> str:
    result = subprocess.run(["ssh", *SSH_OPTS, dest, remote], capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"remote command failed ({result.returncode}): {remote}\n{result.stderr.strip()}")
    return result.stdout


def cmd_targets(args) -> int:
    if args.action == "add":
        return targets_add(args)
    if args.action == "remove":
        return targets_remove(args)
    for name, t in sorted(load_targets().items()):
        kind = "PRODUCTION" if t["production"] else "test"
        print(f"{name:<12} {kind:<10} {t['ssh']:<28} {t.get('description', '')}")
    return 0


def targets_add(args) -> int:
    if not args.name or not TARGET_NAME.match(args.name):
        fail("target name must match [a-z][a-z0-9_-]{0,31}")
    if args.ssh is None or args.production is None:
        fail("targets add NAME needs --ssh DEST and --production true|false")
    targets = read_targets()
    if args.name in targets:
        fail(f"target {args.name!r} exists; `targets remove {args.name}` first to change it")
    # Prove the destination is a UniFi console reachable as root before saving it.
    out = dest_output(
        args.ssh, "id -u; ubnt-device-info firmware 2>/dev/null || echo not-a-unifi-console"
    ).split()
    if not out or out[0] != "0":
        fail(f"{args.ssh}: SSH works but not as root (uid {out[0] if out else '?'})")
    if out[-1] == "not-a-unifi-console":
        fail(f"{args.ssh}: no ubnt-device-info; not a UniFi console")
    entry = {"ssh": args.ssh, "production": args.production == "true"}
    if args.description:
        entry["description"] = args.description
    targets[args.name] = entry
    write_targets(targets)
    kind = "PRODUCTION" if entry["production"] else "test"
    print(f"added {args.name} ({kind}) -> {args.ssh}, firmware {out[-1]}")
    return 0


def targets_remove(args) -> int:
    targets = read_targets()
    if not args.name or args.name not in targets:
        fail(f"unknown target {args.name!r}")
    del targets[args.name]
    write_targets(targets)
    print(f"removed {args.name} (the console itself is unchanged)")
    return 0


def cmd_snapshot(args) -> int:
    t = target(args.target)
    print(f"target={args.target} ssh={t['ssh']} production={str(t['production']).lower()}")
    return ssh(args.target, "sh -s", stdin=SNAPSHOT)


def cmd_shimctl(args) -> int:
    rest = list(args.args)
    if rest[:1] == ["--release"]:
        if len(rest) < 2 or not re.fullmatch(r"[0-9][A-Za-z0-9.+-]*", rest[1]):
            fail("usage: nvr.py shimctl TARGET --release VERSION SHIMCTL_ARGS")
        script = f"{BASE}/releases/{rest[1]}/shimctl.py"
        rest = rest[2:]
    else:
        script = f"{BASE}/current/shimctl.py"
    if not rest:
        fail("no shimctl command; e.g. nvr.py shimctl TARGET status")
    return ssh(args.target, shlex.join(["python3", "-I", script, *rest]))


def cmd_run(args) -> int:
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        fail("nothing to run; usage: nvr.py run TARGET -- COMMAND")
    return ssh(args.target, " ".join(command))


def cmd_upload(args) -> int:
    name = os.path.basename(args.tarball)
    match = TARBALL.match(name)
    if not match:
        fail(f"{name}: expected onvif-shim-VERSION.tar.gz from `python3 -m shimlib.release`")
    version = match["version"]
    if version.endswith("-dirty"):
        fail("dirty release: build from a clean, committed checkout")
    with open(args.tarball, "rb") as source:
        digest = hashlib.sha256(source.read()).hexdigest()
    release = f"{BASE}/releases/{version}"
    exists = ssh_output(args.target, f"[ -e {release} ] && echo yes || echo no").strip()
    if exists == "yes":
        fail(f"{release} already exists on {args.target}; nothing uploaded")
    dest = target(args.target)["ssh"]
    remote = f"/root/{name}"
    print(f"copy {name} -> {dest}:{remote}")
    if subprocess.run(["scp", "-q", *SSH_OPTS, args.tarball, f"{dest}:{remote}"]).returncode:
        fail("scp failed")
    remote_digest = ssh_output(args.target, f"sha256sum {remote}").split()[0]
    print(f"sha256 local  {digest}\nsha256 remote {remote_digest}")
    if remote_digest != digest:
        fail("checksum mismatch after copy; nothing extracted")
    ssh(
        args.target,
        f"mkdir -p {BASE}/releases && tar -xzf {remote} -C {BASE}/releases && "
        f"cat {release}/VERSION",
        check=True,
    )
    print(f"extracted {release} (not installed; next: install.sh --dry-run)")
    return 0


def main(argv=None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # keep order with ssh's output
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("targets", help="list, add or remove targets")
    t.add_argument("action", nargs="?", choices=["list", "add", "remove"], default="list")
    t.add_argument("name", nargs="?")
    t.add_argument("--ssh", help="add: SSH destination (alias or root@HOST)")
    t.add_argument("--production", choices=["true", "false"], help="add: required")
    t.add_argument("--description", help="add: free text")
    t.set_defaults(func=cmd_targets)
    s = sub.add_parser("snapshot", help="read-only health and inventory bundle")
    s.add_argument("target")
    s.set_defaults(func=cmd_snapshot)
    c = sub.add_parser(
        "shimctl",
        help="run shimctl on the console: TARGET [--release VERSION] SHIMCTL_ARGS",
    )
    c.add_argument("target")
    c.add_argument("args", nargs=argparse.REMAINDER)
    c.set_defaults(func=cmd_shimctl)
    r = sub.add_parser("run", help="run a shell command on the console")
    r.add_argument("target")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(func=cmd_run)
    u = sub.add_parser("upload", help="copy, verify and extract a release tarball")
    u.add_argument("target")
    u.add_argument("tarball")
    u.set_defaults(func=cmd_upload)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
