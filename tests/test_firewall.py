"""Rule generation, scoping and convergence against the in-memory iptables model."""

import pytest

from shimlib import firewall
from shimlib.firewall import CHAIN, Firewall, FirewallError, Redirect
from tests.fakes import FakeHost

PE = Redirect("parking_east", "10.48.20.13", 8000, 18113)
PN = Redirect("parking_north", "10.48.20.14", 8000, 18114)
UID = 996


@pytest.fixture
def host(tmp_path):
    return FakeHost(str(tmp_path / "run"), str(tmp_path / "units"))


def test_rule_shapes_are_narrow():
    args = PE.args()
    assert args[args.index("-d") + 1] == "10.48.20.13/32"
    assert args[args.index("--dport") + 1] == "8000"
    assert args[args.index("--to-destination") + 1] == "127.0.0.1:18113"
    assert args[args.index("-p") + 1] == "tcp"
    jump = firewall.jump_args(UID)
    assert jump[jump.index("--uid-owner") + 1] == "996" and jump[-1] == CHAIN
    # Never a port range, never video/RTSP, never a source-less wildcard redirect.
    joined = " ".join(args + jump)
    assert "554" not in joined and ":" not in args[args.index("--dport") + 1]


def test_install_from_empty_then_idempotent(host):
    fw = Firewall(host)
    lines, state = fw.converge({PE}, UID)
    assert lines[0] == "*nat" and lines[-1] == "COMMIT"
    assert f":{CHAIN} - [0:0]" in lines
    assert any(line.startswith("-I OUTPUT 1 ") for line in lines)
    assert state.redirects == {PE} and len(state.jumps) == 1
    again, _ = fw.converge({PE}, UID)
    assert again == []
    assert len(host.ipt.restores) == 1


def test_add_second_camera_rewrites_only_our_chain(host):
    host.ipt.add_foreign("OUTPUT", "-d 10.9.9.9/32 -p udp -j ACCEPT")
    host.ipt.add_foreign("POSTROUTING", "-o eth0 -j MASQUERADE")
    fw = Firewall(host)
    fw.converge({PE}, UID)
    fw.converge({PE, PN}, UID)
    state = fw.read()
    assert state.redirects == {PE, PN}
    assert ["-d", "10.9.9.9/32", "-p", "udp", "-j", "ACCEPT"] in host.ipt.chains["OUTPUT"]
    assert host.ipt.chains["POSTROUTING"] == [["-o", "eth0", "-j", "MASQUERADE"]]
    assert not any("-F OUTPUT" in r or "-F POSTROUTING" in r for r in host.ipt.restores)


def test_remove_all_restores_pristine_table(host):
    host.ipt.add_foreign("OUTPUT", "-d 10.9.9.9/32 -p udp -j ACCEPT")
    before = host.ipt.save()
    fw = Firewall(host)
    fw.converge({PE, PN}, UID)
    fw.converge(set(), UID, anchor=False)
    assert host.ipt.save() == before
    assert fw.remove_all()[0] == []  # nothing left to do


def test_last_redirect_removal_keeps_conntrack_anchor(host):
    # Removing the last DNAT rule would deactivate conntrack and strand in-flight
    # redirected connections (verified in tests/kernel); the anchor prevents it.
    fw = Firewall(host)
    fw.converge({PE}, UID)
    state = fw.read()
    assert state.rules[0] == firewall.ANCHOR
    fw.converge(set(), UID)
    state = fw.read()
    assert state.anchor and state.redirects == set() and len(state.jumps) == 1
    assert state.rules == [firewall.ANCHOR]


def test_partial_removal_keeps_other_camera(host):
    fw = Firewall(host)
    fw.converge({PE, PN}, UID)
    fw.converge({PN}, UID)
    assert fw.read().redirects == {PN}


def test_stale_uid_jump_is_replaced_and_duplicates_removed(host):
    fw = Firewall(host)
    fw.converge({PE}, 995)
    host.ipt.chains["OUTPUT"].append(firewall.jump_args(UID))
    fw.converge({PE}, UID)
    jumps = fw.read().jumps
    assert [j.uid for j in jumps] == [UID]


def test_foreign_rule_inside_our_chain_is_replaced(host):
    fw = Firewall(host)
    fw.converge({PE}, UID)
    host.ipt.chains[CHAIN].append(["-p", "tcp", "-j", "RETURN"])
    state = fw.read()
    assert state.foreign_in_chain
    fw.converge({PE}, UID)
    assert fw.read().foreign_in_chain == []


def test_detects_conflicting_legacy_shim_rule(host):
    host.ipt.add_foreign(
        "OUTPUT",
        "-d 10.48.20.13/32 -p tcp -m tcp --dport 8000 -m mark ! --mark 0x40000000/0x40000000 "
        "-j DNAT --to-destination 127.0.0.1:18000",
    )
    assert ("10.48.20.13", 8000) in Firewall(host).read().foreign_dnat


def test_failed_restore_is_reported_and_changes_nothing(host):
    fw = Firewall(host)
    host.ipt.fail_restore = True
    before = host.ipt.save()
    with pytest.raises(FirewallError):
        fw.converge({PE}, UID)
    assert host.ipt.save() == before


def test_dry_run_plans_without_applying(host):
    fw = Firewall(host)
    lines, _ = fw.converge({PE}, UID, dry_run=True)
    assert lines and host.ipt.restores == []


def test_no_uid_means_no_redirects(host):
    fw = Firewall(host)
    fw.converge({PE}, UID)
    fw.converge({PE}, None)
    assert not fw.read().installed


def test_parse_real_iptables_s_output():
    # Format produced by iptables-legacy 1.8.x `-t nat -S` for these rules.
    text = "\n".join(
        [
            "-P PREROUTING ACCEPT",
            "-P INPUT ACCEPT",
            "-P OUTPUT ACCEPT",
            "-P POSTROUTING ACCEPT",
            "-N ONVIF_SHIM",
            "-A OUTPUT -p tcp -m owner --uid-owner 996 -m comment "
            '--comment "onvif-shim:jump" -j ONVIF_SHIM',
            "-A ONVIF_SHIM -m conntrack --ctstate INVALID -m comment "
            '--comment "onvif-shim:ct-anchor" -j RETURN',
            "-A ONVIF_SHIM -d 10.48.20.13/32 -p tcp -m tcp --dport 8000 -m comment "
            '--comment "onvif-shim:cam:parking_east" -j DNAT --to-destination 127.0.0.1:18113',
        ]
    )
    state = firewall.parse_state(text)
    assert state.chain_exists and state.redirects == {PE} and state.anchor
    assert state.jumps[0].uid == UID and state.jumps[0].tokens == firewall.jump_args(UID)
    assert firewall.plan(state, {PE}, UID) == []


def test_refuses_to_emit_unexpected_tokens():
    state = firewall.State(chain_exists=True)
    state.jumps.append(firewall.Jump(["-m", "comment", "--comment", "evil; rm", "-j", CHAIN], 1))
    with pytest.raises(FirewallError):
        firewall.plan(state, set(), None)
