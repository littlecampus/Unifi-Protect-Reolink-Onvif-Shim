"""Installer/reconciler lifecycle against fake systemd + iptables (idempotency, fail-open)."""

import json
import os
from pathlib import Path

import pytest

from shimlib import release, units
from shimlib.ctl import Ctl, CtlError, main
from shimlib.firewall import CHAIN
from shimlib.units import Paths
from tests.fakes import FakeHost

CAMERAS = [
    ("parking_east", "10.48.20.13", 18113),
    ("parking_north", "10.48.20.14", 18114),
    ("prog_room_int", "10.48.20.15", 18115),
]


def write_config(paths, enabled=("parking_east",), extra=None):
    cams = [
        {
            "id": cid,
            "camera_ip": ip,
            "onvif_port": 8000,
            "listen_port": port,
            "enabled": cid in enabled,
        }
        for cid, ip, port in CAMERAS
    ]
    raw = {"schema_version": 1, "cameras": cams + (extra or [])}
    os.makedirs(paths.base, exist_ok=True)
    with open(paths.config, "w") as out:
        json.dump(raw, out)


@pytest.fixture
def env(tmp_path):
    paths = Paths(
        base=str(tmp_path / "data"),
        unit_dir=str(tmp_path / "units"),
        run_dir=str(tmp_path / "run"),
        lock_file=str(tmp_path / "ctl.lock"),
    )
    os.makedirs(paths.unit_dir)
    host = FakeHost(paths.run_dir, paths.unit_dir)
    host.ports = {cid: port for cid, _, port in CAMERAS}
    release.stage(paths.releases, "0.1.0-gtest")
    write_config(paths)
    lines = []

    def ctl(dry_run=False):
        return Ctl(
            paths, runner=host, probe=host, out=lines.append, dry_run=dry_run, check_ownership=False
        )

    return paths, host, ctl, lines


def redirects(host):
    comments = [r[r.index("--comment") + 1] for r in host.ipt.chains.get(CHAIN, [])]
    return sorted(c.split(":")[-1] for c in comments if c.startswith("onvif-shim:cam:"))


def anchored(host):
    return any("onvif-shim:ct-anchor" in r for r in host.ipt.chains.get(CHAIN, []))


def test_dry_run_install_changes_nothing(env):
    paths, host, ctl, lines = env
    assert ctl(dry_run=True).install("0.1.0-gtest") == 0
    assert host.mutating_calls() == []
    assert not os.path.exists(paths.current)
    assert not os.listdir(paths.unit_dir)
    assert any("[dry-run] write" in line for line in lines)
    # Planned: chain, anchor and jump, but no camera DNAT (the instance is not serving yet).
    assert any("-I OUTPUT 1" in line for line in lines)
    assert not any("-j DNAT" in line for line in lines)


def test_install_is_complete_and_idempotent(env):
    paths, host, ctl, lines = env
    assert ctl().install("0.1.0-gtest") == 0
    assert os.readlink(paths.current) == "releases/0.1.0-gtest"
    for name in units.UNIT_FILES:
        assert os.path.exists(os.path.join(paths.unit_dir, name))
    assert host.units[units.instance("parking_east")]["ActiveState"] == "active"
    assert host.units[units.RECONCILE_TIMER]["UnitFileState"] == "enabled"
    assert redirects(host) == ["parking_east"]
    # Only Protect's uid is redirected.
    jump = host.ipt.chains["OUTPUT"][0]
    assert jump[jump.index("--uid-owner") + 1] == "996"
    assert (
        units.instance("parking_north") not in host.units
        or host.units[units.instance("parking_north")]["ActiveState"] == "inactive"
    )
    host.calls.clear()
    lines.clear()
    assert ctl().install() == 0
    assert host.mutating_calls() == []
    assert "no changes" in lines


def test_reconcile_is_idempotent_and_fail_open_on_stale_heartbeat(env):
    paths, host, ctl, lines = env
    ctl().install("0.1.0-gtest")
    host.calls.clear()
    assert ctl().report(ctl().reconcile(), quiet=True) == 0
    assert host.mutating_calls() == []
    pid = int(host.units[units.instance("parking_east")]["MainPID"])
    host.write_status("parking_east", pid=pid, heartbeat=host.now_value - 60)
    outcome = ctl().reconcile()
    # Redirect off, but the conntrack anchor stays so in-flight polls still drain.
    assert redirects(host) == [] and anchored(host)
    assert any("unhealthy cam=parking_east reason=heartbeat_stale" in a for a in outcome.alerts)
    host.write_status("parking_east", pid=pid)
    ctl().reconcile()
    assert redirects(host) == ["parking_east"]


@pytest.mark.parametrize(
    "breakage, reason",
    [
        (
            lambda host, pid: host.write_status(
                "parking_east", pid=pid, serviceable=False, reason="loop_detected"
            ),
            "loop_detected",
        ),
        (lambda host, pid: host.write_status("parking_east", pid=pid + 1), "stale_status"),
        (lambda host, pid: host.listening_ports.clear(), "not_listening"),
        (
            lambda host, pid: os.unlink(os.path.join(host.run_dir, "parking_east", "status.json")),
            "no_status",
        ),
    ],
)
def test_unhealthy_instance_is_bypassed(env, breakage, reason):
    paths, host, ctl, _ = env
    ctl().install("0.1.0-gtest")
    pid = int(host.units[units.instance("parking_east")]["MainPID"])
    breakage(host, pid)
    outcome = ctl().reconcile()
    assert redirects(host) == []
    assert any(reason in alert for alert in outcome.alerts)


def test_failed_unit_is_not_restarted_endlessly(env):
    paths, host, ctl, _ = env
    write_config(paths, enabled=("parking_east", "parking_north"))
    host.start_fails.add("parking_north")
    assert ctl().install("0.1.0-gtest") == 1
    assert redirects(host) == ["parking_east"]
    host.calls.clear()
    outcome = ctl().reconcile()
    assert any("unit_failed cam=parking_north" in a for a in outcome.alerts)
    assert ["systemctl", "start", "--no-block", units.instance("parking_north")] not in host.calls
    host.start_fails.clear()
    assert ctl().reset("parking_north") == 0
    assert redirects(host) == ["parking_east", "parking_north"]


def test_invalid_config_or_missing_user_fails_open(env):
    paths, host, ctl, _ = env
    ctl().install("0.1.0-gtest")
    with open(paths.config, "w") as out:
        out.write('{"schema_version": 1, "cameras": [}')
    outcome = ctl().reconcile()
    # An untrusted configuration removes everything, anchor included.
    assert CHAIN not in host.ipt.chains and any("config_invalid" in a for a in outcome.alerts)
    write_config(paths)
    ctl().reconcile()
    assert redirects(host) == ["parking_east"]
    host.protect_uid = None
    outcome = ctl().reconcile()
    assert CHAIN not in host.ipt.chains
    assert any("client_user_missing" in a for a in outcome.alerts)


def test_disable_removes_redirect_before_stopping_then_enable(env):
    paths, host, ctl, lines = env
    ctl().install("0.1.0-gtest")
    host.calls.clear()
    assert ctl().set_enabled("parking_east", False) == 0
    restore_at = next(i for i, c in enumerate(host.calls) if c[0] == "iptables-restore")
    stop_at = next(i for i, c in enumerate(host.calls) if c[:2] == ["systemctl", "disable"])
    assert restore_at < stop_at  # Protect goes direct before the shim stops
    # The anchor outlived the redirect until the instance had stopped (drained) ...
    first_restore = next(c for c in host.ipt.restores if "-F ONVIF_SHIM" in c)
    assert "ct-anchor" in first_restore and "-X ONVIF_SHIM" not in first_restore
    # ... and with no camera enabled the integration then leaves the nat table.
    assert CHAIN not in host.ipt.chains
    assert host.units[units.instance("parking_east")]["ActiveState"] == "inactive"
    raw = json.loads(Path(paths.config).read_text())
    assert raw["cameras"][0]["enabled"] is False
    assert len(os.listdir(paths.backups)) == 1
    assert ctl().set_enabled("parking_east", True) == 0
    assert redirects(host) == ["parking_east"]


def test_enable_dry_run_does_not_touch_config(env):
    paths, host, ctl, _ = env
    before = Path(paths.config).read_text()
    ctl(dry_run=True).set_enabled("parking_north", True)
    assert Path(paths.config).read_text() == before and host.mutating_calls() == []


def test_multi_camera_install_and_independent_isolation(env):
    paths, host, ctl, _ = env
    write_config(paths, enabled=("parking_east", "parking_north", "prog_room_int"))
    ctl().install("0.1.0-gtest")
    assert redirects(host) == ["parking_east", "parking_north", "prog_room_int"]
    host.listening_ports.discard(18114)
    ctl().reconcile()
    assert redirects(host) == ["parking_east", "prog_room_int"]


def test_conflicting_legacy_shim_rule_blocks_that_camera(env):
    paths, host, ctl, _ = env
    host.ipt.add_foreign(
        "OUTPUT",
        "-d 10.48.20.13/32 -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 "
        "-j DNAT --to-destination 127.0.0.1:18000",
    )
    ctl().install("0.1.0-gtest")
    assert redirects(host) == []
    outcome = ctl().reconcile()
    assert any("conflicting_dnat cam=parking_east" in a for a in outcome.alerts)


def test_bypass_all_and_resume(env):
    paths, host, ctl, _ = env
    ctl().install("0.1.0-gtest")
    assert ctl().bypass_all(True) == 1  # alert stays raised while bypassed
    assert redirects(host) == []
    ctl().reconcile()
    host.start_unit(units.instance("parking_east"))
    ctl().activate("parking_east")
    assert redirects(host) == []  # unit restarts cannot re-add while bypassed
    assert ctl().bypass_all(False) == 0
    assert redirects(host) == ["parking_east"]


def test_unit_hooks_affect_only_their_camera(env):
    paths, host, ctl, _ = env
    write_config(paths, enabled=("parking_east", "parking_north"))
    ctl().install("0.1.0-gtest")
    ctl().deactivate("parking_north")
    assert redirects(host) == ["parking_east"]
    ctl().activate("parking_north")
    assert redirects(host) == ["parking_east", "parking_north"]


def test_stale_instances_are_stopped(env):
    paths, host, ctl, _ = env
    ctl().install("0.1.0-gtest")
    host.start_unit(units.instance("removed_cam"))
    outcome = ctl().reconcile()
    assert f"stop+disable {units.instance('removed_cam')}" in outcome.changes
    assert host.units[units.instance("removed_cam")]["ActiveState"] == "inactive"


def test_uninstall_restores_pristine_state_and_is_idempotent(env):
    paths, host, ctl, lines = env
    host.ipt.add_foreign("OUTPUT", "-d 10.9.9.9/32 -p udp -j ACCEPT")
    pristine = host.ipt.save()
    write_config(paths, enabled=("parking_east", "parking_north"))
    ctl().install("0.1.0-gtest")
    assert ctl().uninstall() == 0
    assert host.ipt.save() == pristine
    assert not any(os.path.exists(os.path.join(paths.unit_dir, n)) for n in units.UNIT_FILES)
    assert all(u["ActiveState"] != "active" for u in host.units.values())
    assert os.path.exists(paths.config)  # configuration kept
    host.calls.clear()
    lines.clear()
    assert ctl().uninstall() == 0
    assert host.mutating_calls() == []
    assert any("nothing installed" in line for line in lines)


def test_preflight_catches_environment_problems(env):
    paths, host, ctl, lines = env
    open(os.path.join(paths.unit_dir, "onvif-shim.service"), "w").close()
    host.listening_ports.add(18113)
    host.owner_match = False
    write_config(
        paths,
        extra=[
            {
                "id": "nvr_itself",
                "camera_ip": "10.48.20.10",
                "onvif_port": 8000,
                "listen_port": 18110,
                "enabled": False,
            }
        ],
    )
    assert ctl().install("0.1.0-gtest") == 2
    text = "\n".join(lines)
    assert "legacy single-camera onvif-shim" in text
    assert "listen_port 18113 already in use" in text
    assert "owner match unavailable" in text
    assert "camera_ip is an address of this NVR" in text
    assert host.mutating_calls() == []


def test_requires_root(env):
    paths, host, ctl, _ = env
    host.root = False
    with pytest.raises(CtlError, match="root"):
        ctl().install("0.1.0-gtest")


def test_release_verification_and_rollback(env):
    paths, host, ctl, _ = env
    ctl().install("0.1.0-gtest")
    second = release.stage(paths.releases, "0.1.1-gtest")
    assert ctl().install("0.1.1-gtest") == 0
    assert os.readlink(paths.current) == "releases/0.1.1-gtest"
    assert ctl().rollback_release(None) == 0
    assert os.readlink(paths.current) == "releases/0.1.0-gtest"
    with open(os.path.join(second, "shimlib", "shim.py"), "a") as out:
        out.write("# tampered\n")
    with pytest.raises(CtlError, match="checksum mismatch"):
        ctl().install("0.1.1-gtest")
    open(os.path.join(paths.releases, "0.1.0-gtest", "shimlib", "planted.py"), "w").close()
    with pytest.raises(CtlError, match="unlisted python file"):
        ctl().install()


def test_ownership_check_rejects_writable_release(env):
    paths, host, ctl, _ = env
    checked = Ctl(paths, runner=host, probe=host, out=lambda _: None, check_ownership=True)
    # Group-writable code is rejected whoever owns it (holds when tests run as root).
    os.chmod(os.path.join(paths.releases, "0.1.0-gtest", "shimlib", "shim.py"), 0o664)
    with pytest.raises(CtlError, match="root-owned"):
        checked.verify_release(os.path.join(paths.releases, "0.1.0-gtest"))


def test_cli_validate_and_units(env, tmp_path):
    paths, host, ctl, lines = env
    out = []
    assert main(["validate", "--config", paths.config], out=out.append) == 0
    assert out[0].startswith("Valid configuration: 3 camera(s), 1 enabled")
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 1, "cameras": [{"id": "x"}]}')
    out.clear()
    assert main(["validate", "--config", str(bad)], out=out.append) == 2
    out.clear()
    assert main(["units", "--base", paths.base], out=out.append) == 0
    text = "\n".join(out)
    assert "DynamicUser=yes" in text and "CapabilityBoundingSet=\n" in text
    assert "password" not in text.lower() and "10.48.20.13" not in text


def test_status_reports_separate_health_dimensions(env):
    paths, host, ctl, lines = env
    ctl().install("0.1.0-gtest")
    lines.clear()
    out = []
    code = main(
        [
            "status",
            "--json",
            "--base",
            paths.base,
            "--unit-dir",
            paths.unit_dir,
            "--run-dir",
            paths.run_dir,
            "--lock-file",
            paths.lock_file,
        ],
        runner=host,
        probe=host,
        out=out.append,
        check_ownership=False,
    )
    assert code == 0
    summary = json.loads(out[0])
    row = summary["cameras"][0]
    assert row["process_healthy"] is True and row["redirect"] is True
    assert row["event_transport"] == "unobserved"
    assert row["detection_verified"] is False
    assert row["recording"].startswith("not_assessed")
