"""Camera onboarding: cameras / add / remove / setup against fake Protect, systemd, iptables."""

import json
import os
from pathlib import Path

import pytest

from shimlib import release, units
from shimlib.cameras import CameraError, CameraTool, slug
from shimlib.ctl import Ctl, Probe, main
from shimlib.firewall import CHAIN
from shimlib.units import Paths
from tests.fakes import FakeHost

PROTECT = [
    ("Parking East", "10.48.20.13", "EC71DBB619A3", "IPC-BO", True, "8000", "misconfigured"),
    ("Parking North", "10.48.20.11", "EC71DB000011", "IPC-BO", True, "8000", "misconfigured"),
    ("Front Door VTO", "10.48.20.51", "BC325F000051", "Dahua", True, "80", "misconfigured"),
    ("Lobby", "10.48.20.40", "EC71DB000040", "IPC-BO", True, "8000", "available"),
    (None, "10.48.20.101", "EC71DB000101", "IPC-BO", False, "8000", None),
]


def protect_json(rows=PROTECT):
    keys = ("name", "host", "mac", "type", "adopted", "onvif_port", "motion")
    return json.dumps([dict(zip(keys, row)) for row in rows])


@pytest.fixture
def env(tmp_path):
    paths = Paths(
        base=str(tmp_path / "data"),
        unit_dir=str(tmp_path / "units"),
        run_dir=str(tmp_path / "run"),
        lock_file=str(tmp_path / "ctl.lock"),
    )
    os.makedirs(paths.unit_dir)
    os.makedirs(paths.base)
    host = FakeHost(paths.run_dir, paths.unit_dir)
    host.config_path = paths.config
    host.protect_json = protect_json()
    release.stage(paths.releases, "2.0.0-gtest")
    Path(paths.config).write_text(json.dumps({"schema_version": 1, "cameras": []}))
    lines = []

    def ctl(dry_run=False):
        return Ctl(
            paths, runner=host, probe=host, out=lines.append, dry_run=dry_run, check_ownership=False
        )

    assert ctl().install("2.0.0-gtest") == 0  # empty inventory installs cleanly
    host.calls.clear()
    lines.clear()
    return paths, host, ctl, lines


def inventory(paths):
    return json.loads(Path(paths.config).read_text())["cameras"]


def redirects(host):
    comments = [r[r.index("--comment") + 1] for r in host.ipt.chains.get(CHAIN, [])]
    return sorted(c.split(":")[-1] for c in comments if c.startswith("onvif-shim:cam:"))


def run(paths, host, lines, *argv, input_fn=None):
    common = ["--base", paths.base, "--unit-dir", paths.unit_dir, "--run-dir", paths.run_dir]
    common += ["--lock-file", paths.lock_file]
    return main(
        [*argv, *common],
        runner=host,
        probe=host,
        out=lines.append,
        check_ownership=False,
        input_fn=input_fn,
    )


def test_slug():
    assert slug("Prog Room - Ext") == "prog_room_ext"
    assert slug("2nd Floor") == "cam_2nd_floor"
    assert slug("Ünïcode!!") == "n_code"
    assert len(slug("x" * 80)) == 32


def test_cameras_lists_needs_shim_and_hides_unadopted(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "cameras") == 0
    text = "\n".join(lines)
    for name in ("Parking East", "Parking North", "Front Door VTO", "Lobby"):
        assert name in text
    assert "10.48.20.101" not in text and "1 discovered but unadopted" in text
    assert text.count("NEEDS SHIM") == 3 and "ok without shim" in text
    lines.clear()
    assert run(paths, host, lines, "cameras", "--needs-shim", "--json") == 0
    rows = json.loads(lines[0])
    assert [r["ip"] for r in rows] == ["10.48.20.13", "10.48.20.11", "10.48.20.51"]
    assert rows[0]["vendor"] == "Reolink" and rows[2]["vendor"] == "Dahua"
    lines.clear()
    assert run(paths, host, lines, "cameras", "--all") == 0
    assert "10.48.20.101" in "\n".join(lines)


def test_add_by_ip_applies_immediately(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "10.48.20.13") == 0
    (entry,) = inventory(paths)
    assert entry == {
        "id": "parking_east",
        "name": "Parking East",
        "camera_ip": "10.48.20.13",
        "onvif_port": 8000,
        "listen_port": 18113,
        "enabled": True,
    }
    assert host.units[units.instance("parking_east")]["ActiveState"] == "active"
    assert host.units[units.instance("parking_east")]["UnitFileState"] == "enabled"
    assert redirects(host) == ["parking_east"]
    assert any("parking_east" in line and "healthy" in line for line in lines)
    lines.clear()
    assert run(paths, host, lines, "cameras") == 0
    assert any("parking_east:on" in line and "shimmed" in line for line in lines)


def test_add_by_name_and_mac_with_backup(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "parking north") == 0
    assert run(paths, host, lines, "add", "ec:71:db:b6:19:a3") == 0
    assert [e["id"] for e in inventory(paths)] == ["parking_north", "parking_east"]
    assert [e["listen_port"] for e in inventory(paths)] == [18111, 18113]
    assert len(os.listdir(paths.backups)) >= 1
    assert redirects(host) == ["parking_east", "parking_north"]


def test_add_dahua_on_port_80_sets_acknowledgement_and_warns(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "Front Door VTO") == 0
    (entry,) = inventory(paths)
    assert entry["onvif_port"] == 80 and entry["onvif_port_shared_with_http"] is True
    text = "\n".join(lines)
    assert "shares the camera's web port 80" in text and "proven only for Reolink" in text


def test_listen_port_skips_ports_in_use(env):
    paths, host, ctl, lines = env
    host.listening_ports.update({18113, 18100})
    assert run(paths, host, lines, "add", "10.48.20.13") == 0
    assert inventory(paths)[0]["listen_port"] == 18101


def test_options_are_applied(env):
    paths, host, ctl, lines = env
    code = run(
        paths, host, lines, "add", "10.48.20.11", "--id", "north", "--listen-port", "18500",
        "--mode", "ai_motion", "--wsa", "To,Action,MessageID", "--no-must-understand",
    )  # fmt: skip
    assert code == 0
    (entry,) = inventory(paths)
    assert entry["id"] == "north" and entry["listen_port"] == 18500
    assert entry["mode"] == "ai_motion" and entry["wsa_must_understand"] is False
    assert entry["wsa_repair"] == ["To", "Action", "MessageID"]


def test_duplicate_unknown_and_invalid_are_refused_without_writing(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "10.48.20.13") == 0
    before = Path(paths.config).read_text()
    assert run(paths, host, lines, "add", "Parking East") == 2
    assert "already in the inventory as 'parking_east'" in lines[-1]
    assert run(paths, host, lines, "add", "No Such Camera") == 2
    assert "no Protect camera matches" in lines[-1]
    assert run(paths, host, lines, "add", "10.48.20.11", "--listen-port", "18113") == 2
    assert "duplicate listener" in lines[-1]
    assert run(paths, host, lines, "add", "10.48.20.11", "--onvif-port", "554") == 2
    assert "video transport" in lines[-1]
    assert Path(paths.config).read_text() == before


def test_ip_unknown_to_protect_or_protect_unavailable(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "10.48.20.99") == 0
    assert "not a third-party camera in Protect" in "\n".join(lines)
    assert inventory(paths)[0]["id"] == "cam_10_48_20_99"
    host.protect_json = None
    lines.clear()
    assert run(paths, host, lines, "add", "10.48.20.98", "--onvif-port", "8000") == 0
    assert "cannot read Protect's camera list" in lines[0]
    assert run(paths, host, lines, "add", "Parking East") == 2
    assert "use the camera IP" in lines[-1]


def test_stage_dry_run_and_not_installed(env):
    paths, host, ctl, lines = env
    host.calls.clear()
    assert run(paths, host, lines, "add", "10.48.20.13", "--dry-run") == 0
    assert inventory(paths) == [] and host.mutating_calls() == []
    assert run(paths, host, lines, "add", "10.48.20.13", "--stage") == 0
    assert inventory(paths)[0]["enabled"] is False
    assert units.instance("parking_east") not in host.units or (
        host.units[units.instance("parking_east")]["ActiveState"] == "inactive"
    )
    assert run(paths, host, lines, "enable", "parking_east") == 0
    assert redirects(host) == ["parking_east"]
    for name in units.UNIT_FILES:
        os.unlink(os.path.join(paths.unit_dir, name))
    assert run(paths, host, lines, "add", "10.48.20.11") == 2
    assert "not installed yet" in lines[-1]
    assert run(paths, host, lines, "add", "10.48.20.11", "--stage") == 0


def test_add_aborts_on_preflight_problem(env):
    paths, host, ctl, lines = env
    host.owner_match = False
    assert run(paths, host, lines, "add", "10.48.20.13") == 2
    assert any("owner match unavailable" in line for line in lines)
    assert inventory(paths) == []


def test_remove_turns_redirect_off_first_and_handles_last_camera(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "10.48.20.13") == 0
    assert run(paths, host, lines, "add", "10.48.20.11") == 0
    host.calls.clear()
    assert run(paths, host, lines, "remove", "parking_north") == 0
    restore_at = next(i for i, c in enumerate(host.calls) if c[0] == "iptables-restore")
    stop_at = next(i for i, c in enumerate(host.calls) if c[:2] == ["systemctl", "disable"])
    assert restore_at < stop_at
    assert [e["id"] for e in inventory(paths)] == ["parking_east"]
    assert redirects(host) == ["parking_east"]
    assert host.units[units.instance("parking_north")]["ActiveState"] == "inactive"
    assert run(paths, host, lines, "remove", "parking_east") == 0
    assert inventory(paths) == [] and CHAIN not in host.ipt.chains
    assert run(paths, host, lines, "remove", "parking_east") == 2


def test_setup_interactive(env):
    paths, host, ctl, lines = env
    answers = iter(["1, 2", "y"])
    assert run(paths, host, lines, "setup", input_fn=lambda prompt: next(answers)) == 0
    text = "\n".join(lines)
    # Reolink cameras needing a shim are listed first; Dahua next; healthy Lobby last.
    order = [text.index(n) for n in ("Parking East", "Parking North", "Front Door VTO", "Lobby")]
    assert order == sorted(order)
    assert sorted(e["id"] for e in inventory(paths)) == ["parking_east", "parking_north"]
    assert redirects(host) == ["parking_east", "parking_north"]
    lines.clear()
    assert run(paths, host, lines, "setup", input_fn=lambda prompt: "") == 0
    assert lines[-1] == "cancelled"
    answers = iter(["1", "n"])
    assert run(paths, host, lines, "setup", input_fn=lambda prompt: next(answers)) == 0
    assert len(inventory(paths)) == 2
    assert run(paths, host, lines, "setup", input_fn=lambda prompt: "9") == 2
    assert "invalid selection" in lines[-1]


def test_setup_refuses_without_terminal(env, monkeypatch):
    paths, host, ctl, lines = env
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert run(paths, host, lines, "setup") == 2
    assert "setup is interactive" in lines[-1]


def test_uninstall_removes_instances_dropped_from_inventory(env):
    paths, host, ctl, lines = env
    assert run(paths, host, lines, "add", "10.48.20.13") == 0
    assert run(paths, host, lines, "add", "10.48.20.11") == 0
    raw = json.loads(Path(paths.config).read_text())
    raw["cameras"] = [c for c in raw["cameras"] if c["id"] == "parking_east"]
    Path(paths.config).write_text(json.dumps(raw))  # edited by hand, nothing re-run
    assert host.units[units.instance("parking_north")]["ActiveState"] == "active"
    assert ctl().uninstall() == 0
    assert all(u["ActiveState"] != "active" for u in host.units.values())
    assert not os.listdir(os.path.join(paths.unit_dir, "multi-user.target.wants"))
    assert CHAIN not in host.ipt.chains


def test_probe_listening_reads_ipv4_and_ipv6_tables(tmp_path):
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    header = "  sl  local_address rem_address   st\n"
    tcp.write_text(header + "   0: 0100007F:4713 00000000:0000 0A\n")  # 127.0.0.1:18195
    tcp6.write_text(
        header
        + "   0: 00000000000000000000000000000000:4714 00000000000000000000000000000000:0000 0A\n"
        + "   1: 00000000000000000000000001000000:4715 00000000000000000000000000000000:0000 0A\n"
        + "   2: 20010DB8000000000000000000000001:4716 00000000000000000000000000000000:0000 0A\n"
        + "   3: 00000000000000000000000000000000:4717 00000000000000000000000000000000:0000 01\n"
    )
    probe = Probe()
    probe.proc_tables = (str(tcp), str(tcp6))
    assert probe.listening(0x4713) and probe.listening(0x4714) and probe.listening(0x4715)
    assert not probe.listening(0x4716)  # specific global IPv6 address does not block 127.0.0.1
    assert not probe.listening(0x4717)  # not LISTEN
    assert not probe.listening(0x4718)


def test_tool_requires_root(env):
    paths, host, ctl, lines = env
    host.root = False
    with pytest.raises(Exception, match="root"):
        CameraTool(ctl()).add("10.48.20.13", {})
    with pytest.raises(CameraError):
        CameraTool(ctl()).plan("nobody", [], {"cameras": []}, {})


def test_first_install_creates_empty_inventory(tmp_path):
    paths = Paths(
        base=str(tmp_path / "data"),
        unit_dir=str(tmp_path / "units"),
        run_dir=str(tmp_path / "run"),
        lock_file=str(tmp_path / "ctl.lock"),
    )
    os.makedirs(paths.unit_dir)
    host = FakeHost(paths.run_dir, paths.unit_dir)
    release.stage(paths.releases, "2.0.0-gtest")
    ctl = Ctl(paths, runner=host, probe=host, out=lambda _: None, check_ownership=False)
    assert Ctl(paths, runner=host, probe=host, out=lambda _: None, dry_run=True,
               check_ownership=False).install("2.0.0-gtest") == 0  # fmt: skip
    assert not os.path.exists(paths.config)
    assert ctl.install("2.0.0-gtest") == 0
    assert json.loads(Path(paths.config).read_text()) == {
        "schema_version": 1,
        "client_user": "unifi-protect",
        "cameras": [],
    }
    assert CHAIN not in host.ipt.chains  # no camera, no firewall footprint
