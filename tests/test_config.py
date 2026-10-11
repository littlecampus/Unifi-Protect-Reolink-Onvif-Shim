import copy
import json
from pathlib import Path

import pytest

from shimlib import config
from shimlib.config import ConfigError

ROOT = Path(__file__).resolve().parent.parent


def camera(index: int = 13, **overrides):
    item = {
        "id": f"cam_{index}",
        "camera_ip": f"10.48.20.{index}",
        "onvif_port": 8000,
        "listen_port": 18100 + index,
        "enabled": True,
    }
    item.update(overrides)
    return item


def doc(*cameras, **top):
    raw = {"schema_version": 1, "cameras": list(cameras) or [camera()]}
    raw.update(top)
    return raw


def test_parking_east_example_is_single_header_only_camera():
    cfg = config.load(str(ROOT / "examples/parking-east.json"))
    (cam,) = cfg.cameras
    assert (cam.id, cam.camera_ip, cam.onvif_port) == ("parking_east", "10.48.20.13", 8000)
    assert cam.mode == "passthrough" and cam.ai_motion is None
    assert cam.wsa_repair == ("To", "Action") and cam.enabled
    assert cfg.client_user == "unifi-protect"


def test_multi_camera_example_and_overrides():
    cfg = config.load(str(ROOT / "cameras.example.json"))
    assert len(cfg.cameras) == 4 and [c.id for c in cfg.enabled] == ["parking_east"]
    b = cfg.camera("batch_camera_b")
    assert set(b.wsa_repair) == {"MessageID", "To", "Action"}
    assert b.limits.response_timeout == 90 and b.limits.max_active_requests == 4
    ai = cfg.camera("ai_camera_example")
    assert ai.mode == "ai_motion" and ai.ai_motion.off_hold_seconds == 10


def test_fifty_cameras_validate():
    cfg = config.from_dict(doc(*[camera(i) for i in range(1, 51)]))
    assert len(cfg.cameras) == 50
    assert len({c.listen_port for c in cfg.cameras}) == 50


def test_defaults_are_header_only_and_bounded():
    cam = config.from_dict(doc()).cameras[0]
    assert cam.mode == "passthrough"
    assert cam.limits == config.Limits()
    assert cam.wsa_must_understand is True


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d["cameras"].append(camera(14, id="cam_13")), "duplicate camera id"),
        (lambda d: d["cameras"].append(camera(14, listen_port=18113)), "duplicate listener"),
        (lambda d: d["cameras"].append(camera(14, camera_ip="10.48.20.13")), "duplicate camera_ip"),
        (lambda d: d["cameras"][0].update(onvif_port=554), "video transport"),
        (lambda d: d["cameras"][0].update(onvif_port=1935), "video transport"),
        (lambda d: d["cameras"][0].update(onvif_port=80), "web/snapshot"),
        (lambda d: d["cameras"][0].update(onvif_port=443), "TLS"),
        (lambda d: d["cameras"][0].update(listen_port=80), "listen_port"),
        (lambda d: d["cameras"][0].update(listen_port=True), "listen_port"),
        (lambda d: d["cameras"][0].update(camera_ip="127.0.0.1"), "unicast"),
        (lambda d: d["cameras"][0].update(camera_ip="224.0.0.1"), "unicast"),
        (lambda d: d["cameras"][0].update(camera_ip="010.48.20.13"), "IPv4"),
        (lambda d: d["cameras"][0].update(camera_ip="camera.local"), "IPv4"),
        (lambda d: d["cameras"][0].update(camera_ip="fe80::1"), "IPv4"),
        (lambda d: d["cameras"][0].update(id="Parking-East"), "id must match"),
        (lambda d: d["cameras"][0].update(id="x" * 40), "id must match"),
        (lambda d: d["cameras"][0].update(enabled="yes"), "true or false"),
        (lambda d: d["cameras"][0].pop("enabled"), "missing"),
        (lambda d: d["cameras"][0].update(surprise=1), "unknown field"),
        (lambda d: d["cameras"][0].update(mode="ai"), "mode must be"),
        (lambda d: d["cameras"][0].update(ai_motion={}), "only valid with mode"),
        (lambda d: d["cameras"][0].update(snapshots={"enabled": True}), "not implemented"),
        (lambda d: d["cameras"][0].update(wsa_repair=["Action"]), "must include 'To'"),
        (lambda d: d["cameras"][0].update(wsa_repair=["To", "To"]), "unique"),
        (lambda d: d["cameras"][0].update(limits={"response_timeout": 0}), "response_timeout"),
        (lambda d: d["cameras"][0].update(limits={"max_active_requests": 1000}), "integer"),
        (
            lambda d: d["cameras"][0].update(
                limits={"connect_timeout": 30, "response_timeout": 10}
            ),
            "below response_timeout",
        ),
        (lambda d: d["cameras"][0].update(limits={"bogus": 1}), "unknown field"),
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.update(schema_version=True), "schema_version"),
        (lambda d: d.update(client_user="root; rm"), "client_user"),
        (lambda d: d.update(cameras=[]), "1..128"),
        (lambda d: d.update(extra=True), "unknown field"),
    ],
)
def test_rejects_invalid_or_ambiguous(mutate, message):
    raw = doc()
    mutate(raw)
    with pytest.raises(ConfigError, match=message):
        config.from_dict(raw)


def test_same_ip_port_on_second_camera_is_ambiguous_upstream():
    raw = doc(camera(13), camera(14))
    raw["cameras"][1]["camera_ip"] = "10.48.20.13"
    with pytest.raises(ConfigError, match="duplicate"):
        config.from_dict(raw)


def test_listener_equal_to_some_onvif_port_rejected():
    raw = doc(camera(13), camera(14, onvif_port=18113, listen_port=18200))
    with pytest.raises(ConfigError, match="collides"):
        config.from_dict(raw)


def test_duplicate_json_keys_and_nan_rejected():
    text = '{"schema_version": 1, "schema_version": 1, "cameras": []}'
    with pytest.raises(ConfigError, match="duplicate JSON key"):
        config.parse_json(text)
    with pytest.raises(ConfigError, match="invalid number"):
        config.parse_json('{"a": NaN}')
    with pytest.raises(ConfigError, match="invalid JSON"):
        config.parse_json("{")


def test_shared_http_port_requires_explicit_acknowledgement():
    raw = doc(camera(onvif_port=80, onvif_port_shared_with_http=True))
    assert config.from_dict(raw).cameras[0].onvif_port == 80


def test_snapshots_disabled_is_accepted_and_ai_explicit_only():
    raw = doc(camera(snapshots={"enabled": False}))
    assert config.from_dict(raw).cameras[0].mode == "passthrough"
    raw = doc(camera(mode="ai_motion", ai_motion={"off_hold_seconds": 5}))
    cam = config.from_dict(raw).cameras[0]
    assert cam.ai_motion.off_hold_seconds == 5 and cam.ai_motion.max_motion_seconds == 900
    with pytest.raises(ConfigError, match="0 or >= 30"):
        config.from_dict(doc(camera(mode="ai_motion", ai_motion={"max_motion_seconds": 5})))


def test_config_never_contains_credentials_fields():
    raw = doc(camera(password="secret"))
    with pytest.raises(ConfigError) as excinfo:
        config.from_dict(raw)
    assert "secret" not in str(excinfo.value)


def test_load_roundtrip_from_file(tmp_path):
    path = tmp_path / "cameras.json"
    raw = doc(camera(13), camera(14, enabled=False))
    path.write_text(json.dumps(raw))
    cfg = config.load(str(path))
    assert [c.enabled for c in cfg.cameras] == [True, False]
    assert config.load_raw(str(path)) == copy.deepcopy(raw)
