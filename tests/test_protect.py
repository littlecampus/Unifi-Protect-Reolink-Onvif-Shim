"""Read-only Protect camera inventory (query shape and parsing)."""

import json

import pytest

from shimlib import protect
from shimlib.protect import ProtectUnavailable
from tests.fakes import FakeHost


def sample():
    return json.dumps(
        [
            {
                "name": "Parking East",
                "host": "10.48.20.13",
                "mac": "EC71DBB619A3",
                "type": "IPC-BO",
                "adopted": True,
                "onvif_port": "8000",
                "motion": "misconfigured",
            },
            {
                "name": "Front Door VTO",
                "host": "10.48.20.51",
                "mac": "BC325F000001",
                "type": "Dahua",
                "adopted": True,
                "onvif_port": "80",
                "motion": "misconfigured",
            },
            {
                "name": None,
                "host": "10.48.20.101",
                "mac": "ec71db000002",
                "type": "IPC-BO",
                "adopted": False,
                "onvif_port": "bogus",
                "motion": None,
            },
        ]
    )


def test_parse_identity_vendor_and_ports():
    pe, vto, unadopted = protect.parse(sample())
    assert (pe.label, pe.vendor, pe.onvif_port, pe.motion, pe.adopted) == (
        "Parking East",
        "Reolink",
        8000,
        "misconfigured",
        True,
    )
    assert vto.vendor == "Dahua" and vto.onvif_port == 80 and not vto.is_reolink
    assert unadopted.label == "10.48.20.101" and unadopted.mac == "EC71DB000002"
    assert unadopted.is_reolink and unadopted.onvif_port is None and not unadopted.adopted


@pytest.mark.parametrize("output", ["not json", '{"a": 1}'])
def test_unexpected_output_is_unavailable(output):
    with pytest.raises(ProtectUnavailable):
        protect.parse(output)


def test_query_is_read_only_and_never_selects_credentials(tmp_path):
    host = FakeHost(str(tmp_path), str(tmp_path))
    host.protect_json = sample()
    assert len(protect.query(host)) == 3
    argv = next(c for c in host.calls if c[0] == "runuser")
    assert argv[:5] == ["runuser", "-u", "postgres", "--", "psql"]
    assert "-p" in argv and "5433" in argv and "unifi-protect" in argv
    sql = host.protect_queries[-1]
    assert sql.startswith("BEGIN READ ONLY;") and sql.rstrip().endswith("ROLLBACK;")
    lowered = sql.lower()
    for forbidden in ("password", "username", "rtsp", "snapshot", "insert", "update", "delete"):
        assert forbidden not in lowered


def test_query_failure_is_unavailable(tmp_path):
    host = FakeHost(str(tmp_path), str(tmp_path))
    with pytest.raises(ProtectUnavailable, match="schema changed"):
        protect.query(host)
