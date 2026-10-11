"""Lifecycle test with real systemd (PID 1) in a privileged throwaway container.

Deploys exactly as the runbook does (root-owned release tarball under /data,
`shimctl.py install`), then exercises the generated units: DynamicUser
sandboxing, ExecStartPost/ExecStopPost redirect hooks, crash and watchdog
recovery, bounded restarts, safety refusal without restart loops, per-camera
disable/enable, bypass-all, a simulated reboot, and uninstall. Run from the repo
root on a workstation: `python3 tests/systemd/systemd_test.py`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from shimlib import release  # noqa: E402

IMAGE = "onvif-shim-systemd-test"
NAME = "onvif-shim-systemd-test"
VERSION = "0.1.0-systemdtest"
BASE = "/data/onvif-shim"
CTL = f"python3 -I {BASE}/current/shimctl.py"
UNIT = "onvif-shim@parking_east.service"
RESULTS: list[dict] = []
CONFIG = {
    "schema_version": 1,
    "client_user": "unifi-protect",
    "status": {"heartbeat_seconds": 1},
    "cameras": [
        {
            "id": "parking_east",
            "camera_ip": "10.99.0.13",
            "onvif_port": 8000,
            "listen_port": 18113,
            "enabled": True,
        },
        {
            "id": "parking_north",
            "camera_ip": "10.99.0.14",
            "onvif_port": 8000,
            "listen_port": 18114,
            "enabled": False,
        },
    ],
}


def host(*args, check=True, input=None):
    return subprocess.run(args, check=check, capture_output=True, text=True, input=input)


def dx(command: str, check=False, input=None):
    return host("docker", "exec", "-i", NAME, "sh", "-c", command, check=check, input=input)


def check(name, condition, **evidence):
    RESULTS.append({"scenario": name, "passed": bool(condition), **evidence})
    print(json.dumps(RESULTS[-1], indent=2), flush=True)


def wait_for(predicate, timeout, step=0.5):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        value = predicate()
        if value:
            return round(time.monotonic() - started, 1)
        time.sleep(step)
    return None


def prop(name, unit=UNIT):
    return dx(f"systemctl show -p {name} --value {unit}").stdout.strip()


def cam_rule():
    return "onvif-shim:cam:parking_east" in dx("iptables -t nat -S").stdout


def chain_present():
    return "ONVIF_SHIM" in dx("iptables -t nat -S").stdout


def status_json():
    out = dx(f"{CTL} status --json").stdout
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out}


def protect_pull():
    out = dx(
        "setpriv --reuid=996 --regid=981 --clear-groups "
        "python3 /src/tests/kernel/client.py 10.99.0.13 8000 pull 0.3"
    ).stdout
    return json.loads(out) if out.strip() else {}


def boot():
    host("docker", "rm", "-f", NAME, check=False)
    host(
        "docker",
        "run",
        "-d",
        "--name",
        NAME,
        "--privileged",
        "--cgroupns=host",
        "-v",
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "-v",
        f"{ROOT}:/src:ro",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        IMAGE,
    )
    assert (
        wait_for(
            lambda: dx("systemctl is-system-running").stdout.strip() in ("running", "degraded"), 60
        )
        is not None
    )


def camera_network():
    script = """
set -e
ip netns add camns
ip link add veth-nvr type veth peer name veth-cam
ip link set veth-cam netns camns
ip addr add 10.99.0.1/24 dev veth-nvr && ip link set veth-nvr up
ip netns exec camns ip addr add 10.99.0.13/24 dev veth-cam
ip netns exec camns ip link set veth-cam up && ip netns exec camns ip link set lo up
systemd-run --unit mockcam --setenv=PYTHONDONTWRITEBYTECODE=1 \
  ip netns exec camns python3 /src/tests/kernel/camera_server.py
"""
    dx(script, check=True)
    wait_for(lambda: dx("ip netns exec camns ss -ltn").stdout.count("10.99.0.13:8000"), 15)


def deploy():
    with tempfile.TemporaryDirectory() as tmp:
        staged = release.stage(tmp, VERSION, ROOT)
        tarball = release.tarball(staged, tmp)
        host("docker", "cp", tarball, f"{NAME}:/root/release.tar.gz")
    dx(f"mkdir -p {BASE}/releases && tar -xzf /root/release.tar.gz -C {BASE}/releases", check=True)
    dx(f"cat > {BASE}/cameras.json && chmod 0644 {BASE}/cameras.json", input=json.dumps(CONFIG))
    return dx(f"stat -c '%U:%G %a %n' {BASE}/releases/{VERSION}/shimctl.py").stdout.strip()


def main():
    host("docker", "build", "-q", "-t", IMAGE, os.path.join(ROOT, "tests/systemd"))
    boot()
    camera_network()
    owner = deploy()
    pristine = dx("iptables-save -t nat | grep -v '^#'").stdout

    dry = dx(f"sh {BASE}/releases/{VERSION}/install.sh --dry-run")
    check(
        "install_dry_run_changes_nothing",
        dry.returncode == 0
        and not dx("ls /etc/systemd/system | grep onvif-shim").stdout
        and not chain_present()
        and not dx(f"test -e {BASE}/current && echo yes").stdout,
        output=dry.stdout.splitlines()[-12:],
        release_owner=owner,
    )

    first = dx(f"sh {BASE}/releases/{VERSION}/install.sh")
    pid = prop("MainPID")
    proc = dx(f"grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/{pid}/status").stdout
    st = status_json()
    row = st.get("cameras", [{}])[0]
    check(
        "install_starts_instance_and_redirects",
        first.returncode == 0
        and prop("ActiveState") == "active"
        and prop("ActiveState", "onvif-shim-reconcile.timer") == "active"
        and cam_rule()
        and row.get("process_healthy")
        and row.get("redirect"),
        install_output=first.stdout.splitlines()[-14:],
        status=row,
    )
    uid_line = next((line for line in proc.splitlines() if line.startswith("Uid")), "")
    check(
        "instance_is_unprivileged_dynamic_user",
        "CapEff:\t0000000000000000" in proc
        and "NoNewPrivs:\t1" in proc
        and "Seccomp:\t2" in proc
        and uid_line.split()[1] not in ("0", "996"),
        proc_status=proc.splitlines(),
    )

    reply = protect_pull()
    time.sleep(1.5)
    row = status_json()["cameras"][0]
    check(
        "protect_pull_via_systemd_instance",
        reply.get("status_line") == "HTTP/1.1 200 OK" and (row.get("pulls_ok") or 0) >= 1,
        client=reply,
        status=row,
    )

    again = dx(f"{CTL} install")
    check(
        "install_is_idempotent",
        again.returncode == 0 and "no changes" in again.stdout and prop("MainPID") == pid,
        output=again.stdout.splitlines()[-4:],
    )

    # Planned stop: ExecStop removes the redirect before SIGTERM; the in-flight long
    # poll drains through the shim while a new connection already goes direct.
    dx(
        "setpriv --reuid=996 --regid=981 --clear-groups python3 "
        "/src/tests/kernel/client.py 10.99.0.13 8000 pull 3 > /root/inflight.json 2>&1 &"
    )
    time.sleep(0.8)
    dx(f"systemctl stop --no-block {UNIT}")
    gone = wait_for(lambda: not cam_rule(), 5, 0.1)
    during = protect_pull()
    wait_for(lambda: prop("ActiveState") == "inactive", 30)
    inflight = json.loads(dx("cat /root/inflight.json").stdout or "{}")
    check(
        "planned_stop_drains_inflight_and_bypasses_new",
        gone is not None
        and inflight.get("status_line") == "HTTP/1.1 200 OK"
        and during.get("status_line") is None
        and during.get("error") is None,
        redirect_removed_after_s=gone,
        inflight=inflight,
        new_during_stop=during,
    )
    dx(f"systemctl start {UNIT}")
    wait_for(cam_rule, 10)
    pid = prop("MainPID")

    # Crash: ExecStopPost removes the redirect at once; restart re-adds it.
    dx(f"kill -9 {pid}")
    removed = wait_for(lambda: not cam_rule(), 5, 0.1)
    restored = wait_for(lambda: cam_rule() and prop("MainPID") not in ("0", pid), 20, 0.2)
    check(
        "crash_fails_open_then_recovers",
        removed is not None and restored is not None,
        redirect_removed_after_s=removed,
        redirect_restored_after_s=restored,
        restarts=prop("NRestarts"),
    )

    # Hung event loop: the timer's heartbeat gate removes the redirect, and the
    # 30 s systemd watchdog restarts the process.
    pid = prop("MainPID")
    dx(f"kill -STOP {pid}")
    removed = wait_for(lambda: not cam_rule(), 60, 0.5)
    restored = wait_for(lambda: cam_rule() and prop("MainPID") not in ("0", pid), 60, 0.5)
    result = dx(f"journalctl -u {UNIT} --no-pager | grep -ciE 'watchdog'").stdout.strip()
    check(
        "hung_process_bypassed_and_watchdog_restarts",
        removed is not None and restored is not None,
        redirect_removed_after_s=removed,
        redirect_restored_after_s=restored,
        watchdog_journal_lines=result,
    )

    # Safety refusal (listener port taken): exit 78 -> no restart loop, alert, reset.
    # Pause the timer: it would (correctly) restart the stopped instance before the
    # squatter binds, which is the opposite race from the one under test.
    dx("systemctl stop onvif-shim-reconcile.timer onvif-shim-reconcile.service")
    dx(f"systemctl stop {UNIT}")
    squat = dx(
        "systemd-run --unit portsquatter python3 -c "
        '"import socket,time;s=socket.socket();'
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind(('127.0.0.1',18113));s.listen();"
        'time.sleep(600)"'
    )
    held = wait_for(
        lambda: (
            "127.0.0.1:18113" in dx("ss -ltnp").stdout
            and "python3" in dx("ss -ltnp 'sport = :18113'").stdout
            and prop("ActiveState") == "inactive"
        ),
        10,
        0.2,
    )
    assert held is not None, (squat.stdout, squat.stderr, dx("ss -ltnp").stdout)
    dx(f"systemctl start {UNIT}")
    time.sleep(8)
    reconcile = dx(f"{CTL} reconcile")
    check(
        "safety_refusal_is_not_restarted",
        prop("ActiveState") == "failed"
        and prop("NRestarts") == "0"
        and not cam_rule()
        and "unit_failed cam=parking_east" in reconcile.stdout,
        result=prop("Result"),
        squatter=prop("ActiveState", "portsquatter.service"),
        reconcile=reconcile.stdout.splitlines()[-3:],
        journal=dx(f"journalctl -u {UNIT} --no-pager -o cat -n 4").stdout.splitlines(),
    )
    dx("systemctl stop portsquatter")
    dx("systemctl start onvif-shim-reconcile.timer")
    reset = dx(f"{CTL} reset parking_east")
    check(
        "reset_recovers_after_fix",
        prop("ActiveState") == "active" and wait_for(cam_rule, 10) is not None,
        output=reset.stdout.splitlines()[-3:],
    )

    # Crash loop: StartLimitBurst bounds restarts; the unit ends failed, redirect off.
    kills = 0
    for _ in range(10):
        pid = prop("MainPID")
        if prop("ActiveState") == "failed" or pid == "0":
            break
        dx(f"kill -9 {pid}")
        kills += 1
        wait_for(
            lambda: prop("ActiveState") in ("active", "failed") and prop("MainPID") != pid, 15, 0.3
        )
    check(
        "crash_loop_is_bounded",
        prop("ActiveState") == "failed" and not cam_rule(),
        kills_until_failed=kills,
        restarts=prop("NRestarts"),
        result=prop("Result"),
    )
    dx(f"{CTL} reset parking_east")
    wait_for(cam_rule, 10)

    # Per-camera rollback and re-enable.
    disable = dx(f"{CTL} disable parking_east")
    disabled_ok = prop("ActiveState") == "inactive" and not cam_rule() and not chain_present()
    enable = dx(f"{CTL} enable parking_east")
    check(
        "disable_then_enable_one_camera",
        disabled_ok and prop("ActiveState") == "active" and wait_for(cam_rule, 10) is not None,
        disable=disable.stdout.splitlines()[-6:],
        enable=enable.stdout.splitlines()[-4:],
    )

    bypass = dx(f"{CTL} bypass-all")
    bypassed = not cam_rule()
    dx(f"{CTL} reconcile")
    still = not cam_rule()
    resume = dx(f"{CTL} resume")
    check(
        "bypass_all_and_resume",
        bypassed and still and cam_rule(),
        bypass=bypass.stdout.splitlines()[-3:],
        resume=resume.stdout.splitlines()[-3:],
    )

    # Reboot: kernel rules and /run vanish; enabled units must restore the path.
    host("docker", "restart", NAME)
    wait_for(
        lambda: dx("systemctl is-system-running").stdout.strip() in ("running", "degraded"), 90
    )
    after_boot = wait_for(cam_rule, 60)
    check(
        "redirect_restored_after_reboot",
        after_boot is not None
        and prop("ActiveState") == "active"
        and prop("ActiveState", "onvif-shim-reconcile.timer") == "active",
        seconds_after_boot=after_boot,
    )

    logs = dx(f"journalctl -u {UNIT} --no-pager -o cat | wc -l").stdout.strip()
    uninstall = dx(f"sh {BASE}/current/uninstall.sh")
    after = dx("iptables-save -t nat | grep -v '^#'").stdout
    second = dx(f"sh {BASE}/current/uninstall.sh")

    def rules(text):
        return [line for line in text.splitlines() if line.startswith("-")]

    check(
        "uninstall_clean_and_idempotent",
        uninstall.returncode == 0
        and not dx("ls /etc/systemd/system | grep onvif-shim").stdout
        and rules(after) == rules(pristine)
        and "nothing installed" in second.stdout
        and dx(f"test -f {BASE}/cameras.json && echo kept").stdout.strip() == "kept",
        output=uninstall.stdout.splitlines()[-10:],
        journal_lines_whole_test=logs,
    )
    host("docker", "rm", "-f", NAME, check=False)
    failed = [r["scenario"] for r in RESULTS if not r["passed"]]
    print(json.dumps({"total": len(RESULTS), "failed": failed}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
