"""Validated camera inventory for the NVR-local shim.

One JSON file describes every camera. Unknown keys, duplicate JSON keys, wrong
types and out-of-range values are rejected rather than defaulted, so a typo can
never silently intercept the wrong destination. The file holds no credentials.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field, fields, replace

SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 1 << 20
MAX_CAMERAS = 128
ID_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
MODES = ("passthrough", "ai_motion")
WSA_ELEMENTS = ("To", "Action", "MessageID", "ReplyTo")
# Never intercept video transport or TLS.
VIDEO_PORTS = frozenset({322, 554, 1935, 7441, 7447, 8554})
TLS_PORTS = frozenset({443, 8443})
HTTP_PORTS = frozenset({80, 8080})


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    max_active_requests: int = 4
    max_request_bytes: int = 262144
    max_response_bytes: int = 4194304
    max_header_bytes: int = 32768
    connect_timeout: float = 5.0
    client_timeout: float = 10.0
    response_timeout: float = 120.0
    drain_timeout: float = 20.0


# name -> (kind, minimum, maximum)
LIMIT_BOUNDS = {
    "max_active_requests": (int, 1, 32),
    "max_request_bytes": (int, 1024, 1 << 20),
    "max_response_bytes": (int, 4096, 16 << 20),
    "max_header_bytes": (int, 4096, 65536),
    "connect_timeout": (float, 0.5, 30.0),
    "client_timeout": (float, 1.0, 60.0),
    "response_timeout": (float, 5.0, 600.0),
    "drain_timeout": (float, 1.0, 120.0),
}


@dataclass(frozen=True)
class AiMotion:
    off_hold_seconds: float = 10.0
    max_motion_seconds: float = 900.0  # 0 disables the stuck-motion guard


@dataclass(frozen=True)
class Camera:
    id: str
    camera_ip: str
    onvif_port: int
    listen_port: int
    enabled: bool
    mode: str = "passthrough"
    name: str | None = None
    limits: Limits = field(default_factory=Limits)
    wsa_repair: tuple[str, ...] = ("To", "Action")
    wsa_must_understand: bool = True
    ai_motion: AiMotion | None = None
    onvif_port_shared_with_http: bool = False

    @property
    def upstream(self) -> tuple[str, int]:
        return self.camera_ip, self.onvif_port


@dataclass(frozen=True)
class StatusSettings:
    heartbeat_seconds: float = 5.0
    summary_log_seconds: float = 900.0
    log_lines_per_minute: int = 30


@dataclass(frozen=True)
class Config:
    cameras: tuple[Camera, ...]
    client_user: str = "unifi-protect"
    status: StatusSettings = field(default_factory=StatusSettings)
    schema_version: int = SCHEMA_VERSION

    def camera(self, camera_id: str) -> Camera:
        for camera in self.cameras:
            if camera.id == camera_id:
                return camera
        raise ConfigError(f"unknown camera id {camera_id!r}")

    @property
    def enabled(self) -> tuple[Camera, ...]:
        return tuple(c for c in self.cameras if c.enabled)


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ConfigError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_constant(name):
    raise ConfigError(f"invalid number {name}")


def parse_json(text: str | bytes) -> dict:
    if len(text) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file too large")
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON at line {exc.lineno} column {exc.colno}") from None
    if not isinstance(raw, dict):
        raise ConfigError("configuration must be a JSON object")
    return raw


def _keys(obj, where: str, allowed: set[str], required: set[str] = frozenset()):
    if not isinstance(obj, dict):
        raise ConfigError(f"{where} must be an object")
    unknown = set(obj) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown field(s) {sorted(unknown)}")
    missing = required - set(obj)
    if missing:
        raise ConfigError(f"{where}: missing field(s) {sorted(missing)}")


def _int(value, where: str, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigError(f"{where} must be an integer in {lo}..{hi}")
    return value


def _number(value, where: str, lo: float, hi: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not lo <= value <= hi
    ):
        raise ConfigError(f"{where} must be a number in {lo}..{hi}")
    return float(value)


def _bool(value, where: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{where} must be true or false")
    return value


def _limits(obj, where: str, base: Limits) -> Limits:
    _keys(obj, where, set(LIMIT_BOUNDS))
    values = {}
    for key, value in obj.items():
        kind, lo, hi = LIMIT_BOUNDS[key]
        check = _int if kind is int else _number
        values[key] = check(value, f"{where}.{key}", lo, hi)
    limits = replace(base, **values)
    if limits.connect_timeout >= limits.response_timeout:
        raise ConfigError(f"{where}: connect_timeout must be below response_timeout")
    return limits


def _wsa(value, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where} must be a non-empty list")
    if any(item not in WSA_ELEMENTS for item in value) or len(set(value)) != len(value):
        raise ConfigError(f"{where} entries must be unique values from {list(WSA_ELEMENTS)}")
    if "To" not in value:
        raise ConfigError(f"{where} must include 'To' (the evidenced Reolink requirement)")
    return tuple(item for item in WSA_ELEMENTS if item in value)


def _ipv4(value, where: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be an IPv4 address string")
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise ConfigError(f"{where} must be a literal IPv4 address") from None
    if str(ip) != value:
        raise ConfigError(f"{where} must be in canonical dotted-quad form")
    if (
        ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_link_local
        or ip.is_reserved
        or value == "255.255.255.255"
    ):
        raise ConfigError(f"{where} must be a unicast camera address")
    return value


def _camera(obj, index: int, defaults: dict) -> Camera:
    where = f"cameras[{index}]"
    allowed = {
        "id",
        "name",
        "camera_ip",
        "onvif_port",
        "listen_port",
        "enabled",
        "mode",
        "limits",
        "wsa_repair",
        "wsa_must_understand",
        "ai_motion",
        "snapshots",
        "onvif_port_shared_with_http",
    }
    required = {"id", "camera_ip", "onvif_port", "listen_port", "enabled"}
    _keys(obj, where, allowed, required)
    camera_id = obj["id"]
    if not isinstance(camera_id, str) or not ID_RE.fullmatch(camera_id):
        raise ConfigError(f"{where}.id must match {ID_RE.pattern}")
    where = f"camera {camera_id!r}"
    name = obj.get("name")
    if name is not None and (
        not isinstance(name, str)
        or not 1 <= len(name) <= 64
        or any(not ch.isprintable() for ch in name)
    ):
        raise ConfigError(f"{where}.name must be 1..64 printable characters")
    shared_http = _bool(obj.get("onvif_port_shared_with_http", False), f"{where}.shared flag")
    port = _int(obj["onvif_port"], f"{where}.onvif_port", 1, 65535)
    if port in VIDEO_PORTS:
        raise ConfigError(f"{where}.onvif_port {port} is a video transport port")
    if port in TLS_PORTS:
        raise ConfigError(f"{where}.onvif_port {port} is TLS; the shim cannot repair TLS")
    if port in HTTP_PORTS and not shared_http:
        raise ConfigError(
            f"{where}.onvif_port {port} is the camera web/snapshot port; set "
            "onvif_port_shared_with_http only if ONVIF genuinely shares it"
        )
    listen = _int(obj["listen_port"], f"{where}.listen_port", 1024, 65535)
    mode = obj.get("mode", "passthrough")
    if mode not in MODES:
        raise ConfigError(f"{where}.mode must be one of {list(MODES)}")
    ai = None
    if "ai_motion" in obj:
        if mode != "ai_motion":
            raise ConfigError(f"{where}.ai_motion is only valid with mode 'ai_motion'")
        _keys(obj["ai_motion"], f"{where}.ai_motion", {"off_hold_seconds", "max_motion_seconds"})
        hold = obj["ai_motion"].get("off_hold_seconds", AiMotion.off_hold_seconds)
        longest = obj["ai_motion"].get("max_motion_seconds", AiMotion.max_motion_seconds)
        ai = AiMotion(
            _number(hold, f"{where}.ai_motion.off_hold_seconds", 0, 120),
            _number(longest, f"{where}.ai_motion.max_motion_seconds", 0, 86400),
        )
        if 0 < ai.max_motion_seconds < 30:
            raise ConfigError(f"{where}.ai_motion.max_motion_seconds must be 0 or >= 30")
    elif mode == "ai_motion":
        ai = AiMotion()
    if "snapshots" in obj:
        _keys(obj["snapshots"], f"{where}.snapshots", {"enabled"}, {"enabled"})
        if _bool(obj["snapshots"]["enabled"], f"{where}.snapshots.enabled"):
            raise ConfigError(
                f"{where}: snapshot/thumbnail interception is not implemented by the "
                "NVR-local shim (out of scope; it would intercept camera HTTP)"
            )
    limits = defaults["limits"]
    if "limits" in obj:
        limits = _limits(obj["limits"], f"{where}.limits", limits)
    wsa = defaults["wsa_repair"]
    if "wsa_repair" in obj:
        wsa = _wsa(obj["wsa_repair"], f"{where}.wsa_repair")
    must = defaults["wsa_must_understand"]
    if "wsa_must_understand" in obj:
        must = _bool(obj["wsa_must_understand"], f"{where}.wsa_must_understand")
    return Camera(
        id=camera_id,
        name=name,
        camera_ip=_ipv4(obj["camera_ip"], f"{where}.camera_ip"),
        onvif_port=port,
        listen_port=listen,
        enabled=_bool(obj["enabled"], f"{where}.enabled"),
        mode=mode,
        limits=limits,
        wsa_repair=wsa,
        wsa_must_understand=must,
        ai_motion=ai,
        onvif_port_shared_with_http=shared_http,
    )


def from_dict(raw: dict) -> Config:
    _keys(
        raw,
        "configuration",
        {"schema_version", "client_user", "defaults", "status", "cameras"},
        {"schema_version", "cameras"},
    )
    if raw["schema_version"] != SCHEMA_VERSION or type(raw["schema_version"]) is not int:
        raise ConfigError(f"schema_version must be {SCHEMA_VERSION}")
    client_user = raw.get("client_user", "unifi-protect")
    if not isinstance(client_user, str) or not USER_RE.fullmatch(client_user):
        raise ConfigError("client_user must be a POSIX user name")
    defaults = {
        "limits": Limits(),
        "wsa_repair": Camera.wsa_repair,
        "wsa_must_understand": True,
    }
    if "defaults" in raw:
        d = raw["defaults"]
        _keys(d, "defaults", {"limits", "wsa_repair", "wsa_must_understand"})
        if "limits" in d:
            defaults["limits"] = _limits(d["limits"], "defaults.limits", Limits())
        if "wsa_repair" in d:
            defaults["wsa_repair"] = _wsa(d["wsa_repair"], "defaults.wsa_repair")
        if "wsa_must_understand" in d:
            defaults["wsa_must_understand"] = _bool(
                d["wsa_must_understand"], "defaults.wsa_must_understand"
            )
    status = StatusSettings()
    if "status" in raw:
        s = raw["status"]
        _keys(s, "status", {f.name for f in fields(StatusSettings)})
        status = StatusSettings(
            heartbeat_seconds=_number(
                s.get("heartbeat_seconds", status.heartbeat_seconds), "status.heartbeat", 1, 30
            ),
            summary_log_seconds=_number(
                s.get("summary_log_seconds", status.summary_log_seconds),
                "status.summary_log_seconds",
                60,
                86400,
            ),
            log_lines_per_minute=_int(
                s.get("log_lines_per_minute", status.log_lines_per_minute),
                "status.log_lines_per_minute",
                1,
                600,
            ),
        )
    items = raw["cameras"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_CAMERAS:
        raise ConfigError(f"cameras must be a list of 1..{MAX_CAMERAS} entries")
    cameras = tuple(_camera(item, i, defaults) for i, item in enumerate(items))
    seen: dict[str, dict] = {"id": {}, "listen_port": {}, "camera_ip": {}, "upstream": {}}
    for camera in cameras:
        for key, value, what in (
            ("id", camera.id, "camera id"),
            ("listen_port", camera.listen_port, "listener endpoint 127.0.0.1"),
            ("camera_ip", camera.camera_ip, "camera_ip (one entry per camera)"),
            ("upstream", camera.upstream, "upstream mapping"),
        ):
            if value in seen[key]:
                raise ConfigError(
                    f"duplicate {what}: {value!r} used by {seen[key][value]!r} and {camera.id!r}"
                )
            seen[key][value] = camera.id
    for camera in cameras:
        if camera.listen_port in {c.onvif_port for c in cameras}:
            # A camera port that equals a listener would make the redirect ambiguous to read.
            raise ConfigError(f"listen_port {camera.listen_port} collides with an ONVIF port")
    return Config(
        cameras=cameras,
        client_user=client_user,
        status=status,
        schema_version=SCHEMA_VERSION,
    )


def load(path: str) -> Config:
    with open(path, "rb") as source:
        data = source.read(MAX_CONFIG_BYTES + 1)
    return from_dict(parse_json(data))


def load_raw(path: str) -> dict:
    with open(path, "rb") as source:
        return parse_json(source.read(MAX_CONFIG_BYTES + 1))
