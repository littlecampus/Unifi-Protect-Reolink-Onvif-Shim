"""Real-netfilter verification of the NVR-local redirect (run as root in a privileged container).

Topology: this namespace plays the NVR (10.99.0.1); a separate network namespace
plays the camera (10.99.0.13) behind a veth pair, so camera traffic is genuinely
routed, NAT'd and conntrack'd. "Protect" is a client running as uid 996; the shim
runs as uid 61000 with every capability dropped (as with systemd DynamicUser).

Each scenario prints evidence (client view, camera view, shim counters, rules,
conntrack) and asserts the expected packet path. Exit status 0 = all passed.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/src")
from shimlib.firewall import Firewall, Redirect, Runner  # noqa: E402

CAM = "10.99.0.13"
PROTECT_UID, PROTECT_GID = 996, 981
SHIM_UID = 61000
LISTEN = 18113
STATUS_DIR = "/run/onvif-shim/parking_east"
CONFIG = "/tmp/k/cameras.json"
CAMERA_LOG = "/tmp/camera.jsonl"
REDIRECT = Redirect("parking_east", CAM, 8000, LISTEN)
RESULTS: list[dict] = []
fw = Firewall(Runner())


def sh(*args, check=True, **kw):
    return subprocess.run(args, check=check, capture_output=True, text=True, **kw)


def setup():
    sh("ip", "netns", "add", "camns")
    sh("ip", "link", "add", "veth-nvr", "type", "veth", "peer", "name", "veth-cam")
    sh("ip", "link", "set", "veth-cam", "netns", "camns")
    sh("ip", "addr", "add", "10.99.0.1/24", "dev", "veth-nvr")
    sh("ip", "link", "set", "veth-nvr", "up")
    sh("ip", "netns", "exec", "camns", "ip", "addr", "add", f"{CAM}/24", "dev", "veth-cam")
    sh("ip", "netns", "exec", "camns", "ip", "link", "set", "veth-cam", "up")
    sh("ip", "netns", "exec", "camns", "ip", "link", "set", "lo", "up")
    sh("groupadd", "-g", str(PROTECT_GID), "unifi-streaming")
    sh("useradd", "-u", str(PROTECT_UID), "-g", str(PROTECT_GID), "-M", "unifi-protect")
    os.makedirs("/tmp/k", exist_ok=True)
    with open(CONFIG, "w") as out:
        json.dump(
            {
                "schema_version": 1,
                "client_user": "unifi-protect",
                "status": {"heartbeat_seconds": 1},
                "cameras": [
                    {
                        "id": "parking_east",
                        "camera_ip": CAM,
                        "onvif_port": 8000,
                        "listen_port": LISTEN,
                        "enabled": True,
                    }
                ],
            },
            out,
        )
    os.chmod(CONFIG, 0o644)
    camera = subprocess.Popen(
        ["ip", "netns", "exec", "camns", "python3", "/src/tests/kernel/camera_server.py"],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert camera.stdout.readline().strip() == "camera ready"
    return camera


def start_shim():
    os.makedirs(STATUS_DIR, exist_ok=True)
    os.chown(STATUS_DIR, SHIM_UID, SHIM_UID)
    status = os.path.join(STATUS_DIR, "status.json")
    if os.path.exists(status):
        os.unlink(status)
    proc = subprocess.Popen(
        [
            "setpriv",
            f"--reuid={SHIM_UID}",
            f"--regid={SHIM_UID}",
            "--clear-groups",
            "--inh-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "python3",
            "-I",
            "/src/onvif_shim.py",
            "--config",
            CONFIG,
            "--camera",
            "parking_east",
            "--status-dir",
            STATUS_DIR,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(100):
        if os.path.exists(status):
            break
        time.sleep(0.05)
    assert proc.poll() is None, proc.stdout.read()
    return proc


def shim_status():
    """Status from a heartbeat written *after* this call (counters are not stale)."""
    asked = time.time()
    deadline = asked + 5
    while True:
        with open(os.path.join(STATUS_DIR, "status.json")) as source:
            status = json.load(source)
        if status["heartbeat_at"] > asked or time.time() > deadline:
            return status
        time.sleep(0.1)


def counters(status):
    r = status["requests"]
    return {k: r[k] for k in ("accepted", "redirected", "direct", "loop_detected", "completed")} | {
        "repaired": status["repairs"].get("repaired", 0)
    }


def client(uid, gid, port, kind="pull", hold=0.5, background=False):
    argv = [
        "setpriv",
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "python3",
        "/src/tests/kernel/client.py",
        CAM,
        str(port),
        kind,
        str(hold),
    ]
    if background:
        return subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
    return json.loads(sh(*argv).stdout)


def camera_log_since(mark):
    with open(CAMERA_LOG) as source:
        lines = source.readlines()
    return [json.loads(line) for line in lines[mark:]], len(lines)


def camera_mark():
    try:
        with open(CAMERA_LOG) as source:
            return len(source.readlines())
    except OSError:
        return 0


def conntrack(port_filter):
    out = sh("conntrack", "-L", "-p", "tcp", "--orig-port-dst", str(port_filter), check=False)
    return [line for line in out.stdout.splitlines() if "dport" in line]


def ct_count():
    with open("/proc/sys/net/netfilter/nf_conntrack_count") as source:
        return int(source.read())


def nat_rules():
    return sh("iptables", "-t", "nat", "-S").stdout.splitlines()


def check(name, condition, **evidence):
    RESULTS.append({"scenario": name, "passed": bool(condition), **evidence})
    print(json.dumps(RESULTS[-1], indent=2), flush=True)


def main():
    pristine = sh("iptables-save", "-t", "nat").stdout
    print("iptables:", sh("iptables", "-V").stdout.strip(), "| kernel:", os.uname().release)
    setup()
    shim = start_shim()
    caps = {
        line.split(":")[0]: line.split()[1]
        for line in open(f"/proc/{shim.pid}/status")
        if line.startswith(("CapEff", "CapPrm", "CapBnd", "Uid"))
    }
    child = sh("pgrep", "-P", str(shim.pid), check=False).stdout.split()
    if child:  # setpriv execs, so the pid is python itself; keep for clarity
        caps["child"] = child
    check(
        "shim_runs_unprivileged",
        caps["CapEff"] == "0000000000000000" and caps["CapPrm"] == "0000000000000000",
        capabilities=caps,
    )
    ct_before = ct_count()
    lines, _ = fw.converge({REDIRECT}, PROTECT_UID)
    rules = nat_rules()
    check(
        "rules_installed",
        any("onvif-shim:cam:parking_east" in r for r in rules),
        restore_input=lines,
        nat=rules,
    )

    # 1. Protect's PullMessages without wsa:To traverses the shim and succeeds.
    mark, before = camera_mark(), counters(shim_status())
    reply = client(PROTECT_UID, PROTECT_GID, 8000)
    seen, _ = camera_log_since(mark)
    after = counters(shim_status())
    check(
        "protect_pull_redirected_and_repaired",
        reply.get("status_line") == "HTTP/1.1 200 OK"
        and reply["peer_seen_by_client"] == f"{CAM}:8000"
        and after["redirected"] == before["redirected"] + 1
        and after["repaired"] == before["repaired"] + 1
        and seen
        and seen[-1]["has_to"]
        and seen[-1]["peer"] == "10.99.0.1",
        client=reply,
        camera=seen,
        shim_before=before,
        shim_after=after,
    )

    # 2. Reply direction and conntrack while a long poll is held open.
    background = client(PROTECT_UID, PROTECT_GID, 8000, hold=2.0, background=True)
    time.sleep(0.7)
    entries = conntrack(8000)
    background.wait(10)
    held = json.loads(background.stdout.read())
    redirected_entry = [e for e in entries if "src=127.0.0.1" in e and f"sport={LISTEN}" in e]
    upstream_entry = [e for e in entries if f"src={CAM}" in e and "127.0.0.1" not in e]
    check(
        "conntrack_reply_tuple_and_unmarked_upstream",
        held.get("status_line") == "HTTP/1.1 200 OK" and redirected_entry and upstream_entry,
        conntrack_entries=entries,
        long_poll=held,
    )

    # 3. Other uids (root, the `ms` video recorder uid 982) are never redirected.
    for uid, gid in ((0, 0), (982, 982)):
        mark, before = camera_mark(), counters(shim_status())
        reply = client(uid, gid, 8000)
        seen, _ = camera_log_since(mark)
        after = counters(shim_status())
        check(
            f"uid_{uid}_not_redirected",
            reply.get("status_line") is None  # camera closes: Reolink behavior without To
            and after == before
            and seen
            and not seen[-1]["has_to"],
            client=reply,
            camera=seen,
        )

    # 4. Video/web ports from Protect's own uid stay direct.
    for port, expect in ((554, "RTSP/1.0 200 OK"), (80, "HTTP/1.1 200 OK")):
        mark, before = camera_mark(), counters(shim_status())
        reply = client(PROTECT_UID, PROTECT_GID, port, kind="raw")
        seen, _ = camera_log_since(mark)
        check(
            f"port_{port}_not_intercepted",
            reply.get("status_line") == expect
            and counters(shim_status()) == before
            and seen
            and seen[-1]["port"] == port
            and seen[-1]["peer"] == "10.99.0.1",
            client=reply,
            camera=seen,
        )

    # 5. A direct local connection is classified "direct" via SO_ORIGINAL_DST.
    before = counters(shim_status())
    sh(
        "python3",
        "-c",
        f"import socket; s=socket.create_connection(('127.0.0.1',{LISTEN})); s.close()",
    )
    after = counters(shim_status())
    check(
        "direct_connection_classified",
        after["direct"] == before["direct"] + 1,
        before=before,
        after=after,
    )

    # 6. Removing the redirect does not cut an established (already NAT'd) long poll;
    #    new connections then go straight to the camera.
    background = client(PROTECT_UID, PROTECT_GID, 8000, hold=3.0, background=True)
    time.sleep(0.7)
    fw.converge(set(), PROTECT_UID)
    background.wait(10)
    held = json.loads(background.stdout.read())
    mark = camera_mark()
    fresh = client(PROTECT_UID, PROTECT_GID, 8000)
    seen, _ = camera_log_since(mark)
    check(
        "rule_removal_keeps_established_and_bypasses_new",
        held.get("status_line") == "HTTP/1.1 200 OK"
        and fresh.get("status_line") is None
        and seen
        and not seen[-1]["has_to"],
        established=held,
        new_connection=fresh,
        camera=seen,
        nat=nat_rules(),
    )

    # 7. Shim crash with the rule still present: in-flight and new connections fail
    #    (exactly why the rule must be removed), and removal restores the direct path.
    fw.converge({REDIRECT}, PROTECT_UID)
    background = client(PROTECT_UID, PROTECT_GID, 8000, hold=3.0, background=True)
    time.sleep(0.7)
    shim.send_signal(signal.SIGKILL)
    shim.wait(5)
    background.wait(10)
    inflight = json.loads(background.stdout.read())
    refused = client(PROTECT_UID, PROTECT_GID, 8000)
    fw.converge(set(), PROTECT_UID)  # what ExecStopPost / reconcile do
    mark = camera_mark()
    direct = client(PROTECT_UID, PROTECT_GID, 8000)
    seen, _ = camera_log_since(mark)
    check(
        "crash_then_fail_open",
        inflight.get("status_line") is None
        and refused.get("error") == "ConnectionRefusedError"
        and direct.get("status_line") is None
        and seen
        and seen[-1]["peer"] == "10.99.0.1"
        and not seen[-1]["has_to"],
        inflight_when_killed=inflight,
        new_while_rule_present=refused,
        after_rule_removed=direct,
        camera=seen,
    )

    # 8. Loop prevention: a (wrong) rule matching the shim's own uid. The shim must
    #    detect its own connection, refuse it, and exit 78 instead of recursing.
    shim = start_shim()
    fw.converge({REDIRECT}, SHIM_UID)
    mark = camera_mark()
    attempt = client(SHIM_UID, SHIM_UID, 8000)
    try:
        code = shim.wait(10)
    except subprocess.TimeoutExpired:
        code = None
    seen, _ = camera_log_since(mark)
    output = shim.stdout.read()
    fw.converge(set(), PROTECT_UID)
    check(
        "loop_detected_and_fails_closed_to_exit_78",
        code == 78 and "loop_detected" in output and not seen,
        exit_code=code,
        client=attempt,
        camera=seen,
        shim_log=output.splitlines()[-4:],
    )

    # 9. Negative control for the conntrack anchor: removing the *last* DNAT rule
    #    without it strands an established redirected long poll (no reply un-NAT).
    shim = start_shim()
    fw.converge({REDIRECT}, PROTECT_UID, anchor=False)
    background = client(PROTECT_UID, PROTECT_GID, 8000, hold=3.0, background=True)
    time.sleep(0.7)
    fw.remove_all()
    try:
        background.wait(25)
        stranded = json.loads(background.stdout.read())
    except subprocess.TimeoutExpired:
        background.kill()
        stranded = {"error": "still hung after 25s"}
    check(
        "negative_control_without_anchor_inflight_is_stranded",
        stranded.get("status_line") is None and stranded.get("error"),
        established=stranded,
        note="expected failure mode that the anchor rule exists to prevent",
    )
    shim.send_signal(signal.SIGTERM)
    shim.wait(30)

    # 10. Uninstall returns the nat table to its pristine state.
    fw.remove_all()
    final = sh("iptables-save", "-t", "nat").stdout

    def strip(text):
        return [line for line in text.splitlines() if not line.startswith(("#", ":"))]

    check("uninstall_restores_pristine_nat", strip(final) == strip(pristine), nat=strip(final))
    check(
        "conntrack_activation_observed",
        True,
        note="informational: count before first DNAT rule vs after traffic",
        before=ct_before,
        after=ct_count(),
    )
    failed = [r["scenario"] for r in RESULTS if not r["passed"]]
    print(json.dumps({"total": len(RESULTS), "failed": failed}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
