"""Simulated 50-camera measurement on a real kernel (privileged container, mocks only).

50 shim processes (uid 61000, no capabilities), 50 DNAT redirects, 50 mock
cameras (one namespace, 50 addresses), then rounds of 50 concurrent long polls
from Protect's uid, with one camera made unreachable. Reports measured RSS,
latency and success counts. This is NOT production acceptance: real cameras,
Protect's real polling pattern and the UNVR's CPU are not represented.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, "/src/tests/kernel")
sys.path.insert(0, "/src")
import kernel_test as k  # noqa: E402

from shimlib.firewall import Firewall, Redirect, Runner  # noqa: E402

COUNT = 50
STALLED = 49


def ip(i):
    return f"10.99.1.{10 + i}"


def setup():
    k.sh("ip", "netns", "add", "camns")
    k.sh("ip", "link", "add", "veth-nvr", "type", "veth", "peer", "name", "veth-cam")
    k.sh("ip", "link", "set", "veth-cam", "netns", "camns")
    k.sh("ip", "addr", "add", "10.99.1.1/24", "dev", "veth-nvr")
    k.sh("ip", "link", "set", "veth-nvr", "up")
    for i in range(COUNT):
        k.sh("ip", "netns", "exec", "camns", "ip", "addr", "add", f"{ip(i)}/24", "dev", "veth-cam")
    k.sh("ip", "netns", "exec", "camns", "ip", "link", "set", "veth-cam", "up")
    k.sh("ip", "netns", "exec", "camns", "ip", "link", "set", "lo", "up")
    # The stalled camera silently drops packets (offline camera: connect timeout).
    k.sh("ip", "netns", "exec", "camns", "iptables", "-A", "INPUT", "-d", ip(STALLED), "-j", "DROP")
    k.sh("groupadd", "-g", "981", "unifi-streaming")
    k.sh("useradd", "-u", "996", "-g", "981", "-M", "unifi-protect")
    script = (
        "import asyncio,sys;sys.path.insert(0,'/src');"
        "from tests.support import MockCamera\n"
        "async def main():\n"
        "    await MockCamera(host='0.0.0.0', port=8000, initial=[]).start()\n"
        "    print('ready', flush=True)\n"
        "    await asyncio.Event().wait()\n"
        "asyncio.run(main())"
    )
    camera = subprocess.Popen(
        ["ip", "netns", "exec", "camns", "python3", "-c", script], stdout=subprocess.PIPE, text=True
    )
    assert camera.stdout.readline().strip() == "ready"
    os.makedirs("/tmp/k", exist_ok=True)
    config = {
        "schema_version": 1,
        "client_user": "unifi-protect",
        "status": {"heartbeat_seconds": 1},
        "cameras": [
            {
                "id": f"cam_{i:02d}",
                "camera_ip": ip(i),
                "onvif_port": 8000,
                "listen_port": 18200 + i,
                "enabled": True,
            }
            for i in range(COUNT)
        ],
    }
    with open(k.CONFIG, "w") as out:
        json.dump(config, out)
    os.chmod(k.CONFIG, 0o644)


def start_shims():
    procs = []
    for i in range(COUNT):
        status_dir = f"/run/onvif-shim/cam_{i:02d}"
        os.makedirs(status_dir, exist_ok=True)
        os.chown(status_dir, k.SHIM_UID, k.SHIM_UID)
        procs.append(
            subprocess.Popen(
                [
                    "setpriv",
                    f"--reuid={k.SHIM_UID}",
                    f"--regid={k.SHIM_UID}",
                    "--clear-groups",
                    "--inh-caps=-all",
                    "--bounding-set=-all",
                    "--no-new-privs",
                    "python3",
                    "-I",
                    "/src/onvif_shim.py",
                    "--config",
                    k.CONFIG,
                    "--camera",
                    f"cam_{i:02d}",
                    "--status-dir",
                    status_dir,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
    deadline = time.time() + 30
    while time.time() < deadline:
        ready = sum(
            os.path.exists(f"/run/onvif-shim/cam_{i:02d}/status.json") for i in range(COUNT)
        )
        if ready == COUNT:
            break
        time.sleep(0.2)
    return procs


def rss_kib(pids):
    total = []
    for pid in pids:
        with open(f"/proc/{pid}/status") as source:
            for line in source:
                if line.startswith("VmRSS:"):
                    total.append(int(line.split()[1]))
    return total


def pss_kib(pids):
    """Proportional set size: shared interpreter pages split across processes."""
    total = []
    for pid in pids:
        with open(f"/proc/{pid}/smaps_rollup") as source:
            for line in source:
                if line.startswith("Pss:"):
                    total.append(int(line.split()[1]))
    return total


def poll_round(hold):
    started = time.monotonic()
    clients = [
        subprocess.Popen(
            [
                "setpriv",
                "--reuid=996",
                "--regid=981",
                "--clear-groups",
                "python3",
                "/src/tests/kernel/client.py",
                ip(i),
                "8000",
                "pull",
                str(hold),
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        for i in range(COUNT)
    ]
    results = []
    for i, proc in enumerate(clients):
        out, _ = proc.communicate(timeout=60)
        results.append((i, json.loads(out)))
    wall = time.monotonic() - started
    healthy = [r for i, r in results if i != STALLED]
    stalled = [r for i, r in results if i == STALLED][0]
    return {
        "wall_s": round(wall, 2),
        "healthy_ok": sum(r.get("status_line") == "HTTP/1.1 200 OK" for r in healthy),
        "healthy_total": len(healthy),
        "healthy_max_elapsed_s": max(r["elapsed"] for r in healthy),
        "stalled_camera": {k_: stalled.get(k_) for k_ in ("status_line", "error", "elapsed")},
    }


def main():
    setup()
    procs = start_shims()
    pids = [p.pid for p in procs]
    idle = rss_kib(pids)
    fw = Firewall(Runner())
    fw.converge(
        {Redirect(f"cam_{i:02d}", ip(i), 8000, 18200 + i) for i in range(COUNT)}, k.PROTECT_UID
    )
    rounds = [poll_round(hold=2.0) for _ in range(3)]
    loaded = rss_kib(pids)
    pss = pss_kib(pids)
    with open(f"/run/onvif-shim/cam_{STALLED:02d}/status.json") as source:
        stalled_status = json.load(source)
    alive = sum(p.poll() is None for p in procs)
    summary = {
        "note": "simulated: 50 mock cameras in one namespace, not production acceptance",
        "processes_alive": alive,
        "rss_kib_idle": {"per_instance_max": max(idle), "total": sum(idle)},
        "rss_kib_after_load": {"per_instance_max": max(loaded), "total": sum(loaded)},
        "pss_kib_after_load": {"per_instance_max": max(pss), "total": sum(pss)},
        "rounds_of_50_concurrent_2s_long_polls": rounds,
        "stalled_camera_shim_state": {
            "event_transport": stalled_status["event_transport"],
            "last_error": stalled_status["upstream"]["last_error"],
        },
        "rules_in_chain": sum("onvif-shim:cam:" in r for r in k.nat_rules()),
    }
    print(json.dumps(summary, indent=2))
    fw.remove_all()
    for p in procs:
        p.terminate()
    ok = alive == COUNT and all(r["healthy_ok"] == COUNT - 1 for r in rounds)
    ok = ok and all(r["healthy_max_elapsed_s"] < 4 for r in rounds)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
