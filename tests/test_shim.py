"""End-to-end behavior of one/many shim instances against mock Reolink cameras."""

import asyncio
import dataclasses
import json
import time

import pytest

from shimlib import config as cfgmod
from shimlib import soap
from shimlib.shim import CameraShim, RateLimitedLog
from tests.support import (
    WSSE,
    MockCamera,
    ai,
    build_request,
    create_body,
    motion,
    pull_body,
    send,
)

SECRET_AUTH = 'Digest username="admin", response="0123456789abcdef"'


def make_config(**camera_overrides):
    raw = {
        "schema_version": 1,
        "cameras": [
            {
                "id": "parking_east",
                "camera_ip": "10.48.20.13",
                "onvif_port": 8000,
                "listen_port": 18113,
                "enabled": True,
                **camera_overrides,
            }
        ],
    }
    return cfgmod.from_dict(raw)


class Harness:
    def __init__(self):
        self.cleanup = []
        self.lines = []

    async def camera(self, **kw):
        cam = await MockCamera(**kw).start()
        self.cleanup.append(cam.stop)
        return cam

    async def shim(
        self,
        cam_port,
        *,
        camera_id="parking_east",
        status_dir=None,
        limits=None,
        config=None,
        **overrides,
    ):
        config = config or make_config(**overrides)
        camera = config.cameras[0]
        camera = dataclasses.replace(
            camera, id=camera_id, camera_ip="127.0.0.1", onvif_port=cam_port, listen_port=0
        )
        if limits:
            camera = dataclasses.replace(
                camera, limits=dataclasses.replace(camera.limits, **limits)
            )
        log = RateLimitedLog(camera_id, 600, sink=self.lines.append)
        # Tests connect straight to loopback, which Linux classifies as "direct".
        shim = CameraShim(camera, config, status_dir, log=log, direct_budget=10_000)
        await shim.start()
        self.cleanup.append(shim.close)
        return shim

    async def close(self):
        for fn in reversed(self.cleanup):
            await fn()


@pytest.fixture
async def h():
    harness = Harness()
    yield harness
    await harness.close()


def pull(cam, **kw):
    return build_request(pull_body(**kw.pop("body_kw", {})), host=f"127.0.0.1:{cam.port}", **kw)


@pytest.mark.parametrize("missing_to", ["close", "400"])
async def test_direct_pull_fails_but_shimmed_pull_succeeds(h, missing_to):
    cam = await h.camera(missing_to=missing_to)
    shim = await h.shim(cam.port)
    direct = await send(cam.port, pull(cam))
    assert direct.status in (None, 400)  # the production failure mode
    via = await send(shim.port, pull(cam))
    assert via.status == 200
    snap = shim.snapshot()
    assert snap["repairs"] == {"repaired": 1} and snap["wsa_added"] == {"To": 1, "Action": 1}
    assert snap["pulls"]["ok"] == 1 and snap["event_transport"] == "healthy"


async def test_long_poll_sequence_is_continuous_not_one_request(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    statuses = []
    for i in range(6):
        if i == 3:
            cam.push(motion(True))
        statuses.append((await send(shim.port, pull(cam, body_kw={"timeout": "PT0.2S"}))).status)
    assert statuses == [200] * 6
    assert shim.pulls.ok == 6 and shim.pulls.consecutive_failures == 0
    assert shim.pulls.motion_true == 1


@pytest.mark.parametrize("chunked", [False, True])
async def test_notifications_pass_through_byte_identical(h, chunked):
    cam = await h.camera(chunked=chunked, initial=[])
    shim = await h.shim(cam.port)
    cam.push(motion(True), ai("PeopleDetect", True), motion(False))
    reply = await send(shim.port, pull(cam))
    assert reply.status == 200
    assert reply.body == cam.responses[-1]  # passthrough never rewrites events
    assert shim.pulls.motion_true == 1 and shim.pulls.motion_false == 1


async def test_authentication_and_headers_preserved(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    raw = pull(cam, extra=[("X-Custom", "kept")])
    await send(shim.port, raw)
    got = cam.received[-1]
    assert got.headers[b"authorization"].startswith(b"Digest username=")
    assert got.headers[b"authorization"] in raw
    assert got.headers[b"host"] == f"127.0.0.1:{cam.port}".encode()
    assert got.headers[b"x-custom"] == b"kept"
    assert b"PullMessagesRequest" in got.headers[b"content-type"]
    assert WSSE.encode() in got.body  # WS-Security token untouched
    assert got.headers[b"connection"] == b"close"
    assert int(got.headers[b"content-length"]) == len(got.body)


async def test_to_is_the_request_url_including_query(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    await send(shim.port, pull(cam, target="/onvif/PullSubManager?Idx=00_7&sub=a%20b"))
    env = soap.parse_envelope(cam.received[-1].body)
    to = next(n for n in env.header.children if n.name[1] == "To")
    assert to.text == f"http://127.0.0.1:{cam.port}/onvif/PullSubManager?Idx=00_7&sub=a%20b"
    assert cam.received[-1].target == b"/onvif/PullSubManager?Idx=00_7&sub=a%20b"


async def test_foreign_host_header_does_not_steer_to(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    raw = build_request(pull_body(), host="evil.example:1")
    await send(shim.port, raw)
    env = soap.parse_envelope(cam.received[-1].body)
    to = next(n for n in env.header.children if n.name[1] == "To")
    assert to.text.startswith(f"http://127.0.0.1:{cam.port}/")
    assert shim.counters.host_mismatch == 1


async def test_other_operations_forwarded_unchanged(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    body = create_body()
    reply = await send(shim.port, build_request(body, host="x", target="/onvif/event_service"))
    assert reply.status == 200 and cam.received[-1].body == body
    assert shim.counters.repairs == {"not_applicable": 1}


@pytest.mark.parametrize(
    "header",
    [("Content-Digest", "sha-256=:abc=:"), ("Content-MD5", "abc"), ("Content-Encoding", "gzip")],
)
async def test_integrity_or_encoded_bodies_are_never_modified(h, header):
    cam = await h.camera(missing_to="accept")
    shim = await h.shim(cam.port)
    body = pull_body()
    await send(shim.port, build_request(body, host="x", extra=[header]))
    assert cam.received[-1].body == body
    outcome = "skipped_encoding" if header[0] == "Content-Encoding" else "skipped_integrity"
    assert shim.counters.repairs == {outcome: 1}


async def test_auth_int_digest_not_modified(h):
    cam = await h.camera(missing_to="accept")
    shim = await h.shim(cam.port)
    body = pull_body()
    raw = build_request(body, host="x").replace(
        b"Digest username", b"Digest qop=auth-int, username"
    )
    await send(shim.port, raw)
    assert cam.received[-1].body == body
    assert shim.counters.repairs == {"skipped_integrity": 1}


async def test_signed_and_malformed_xml_forwarded_untouched(h):
    cam = await h.camera(missing_to="accept")
    shim = await h.shim(cam.port)
    sig = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
    signed = pull_body(header=WSSE + sig)
    await send(shim.port, build_request(signed, host="x"))
    assert cam.received[-1].body == signed
    assert shim.counters.repairs["skipped_signed"] == 1


@pytest.mark.parametrize(
    "raw, status",
    [
        (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n\r\n", 413),
        (b"POST / HTTP/1.1\r\nHost: x\r\n" + b"X-A: " + b"a" * 40000 + b"\r\n\r\n", 431),
        (
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", 400),
        (b"PUT / HTTP/1.1\r\nHost: x\r\n\r\n", 405),
        (b"CONNECT a:1 HTTP/1.1\r\nHost: x\r\n\r\n", 405),
        (b"GET http://a/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", 400),
        (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
    ],
)
async def test_malformed_and_oversized_requests_rejected_before_camera(h, raw, status):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    reply = await send(shim.port, raw)
    assert reply.status == status
    assert cam.received == []
    assert shim.counters.rejected_invalid == 1


async def test_chunked_request_and_expect_continue(h):
    cam = await h.camera()
    shim = await h.shim(cam.port)
    body = pull_body()
    raw = (
        b"POST /onvif/PullSubManager?Idx=00_0 HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n" + b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    )
    reply = await send(shim.port, raw)
    assert reply.raw.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200")
    got = cam.received[-1]
    assert b"expect" not in got.headers and b"transfer-encoding" not in got.headers
    assert b"<wsa:To" in got.body


async def test_client_slowloris_times_out(h):
    cam = await h.camera()
    shim = await h.shim(cam.port, limits={"client_timeout": 0.3})
    reader, writer = await asyncio.open_connection("127.0.0.1", shim.port)
    writer.write(b"POST / HTTP/1.1\r\nHost: x\r\n")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 2) == b""
    writer.close()
    assert shim.counters.client_timeout == 1 and cam.received == []


async def test_camera_outage_then_recovery(h):
    cam = await h.camera()
    port = cam.port
    await cam.stop()
    shim = await h.shim(port)
    for _ in range(3):
        reply = await send(shim.port, build_request(pull_body(), host="x"))
        assert reply.status is None  # mirrors an unreachable camera, no synthesized HTTP
    assert shim.transport_state() == "outage" and shim.upstream.outages == 1
    revived = await h.camera(port=port)
    reply = await send(shim.port, pull(revived))
    assert reply.status == 200
    assert shim.upstream.recoveries == 1 and shim.transport_state() == "healthy"


async def test_response_timeout_and_size_bound(h):
    hung = await h.camera(hang=True)
    shim = await h.shim(hung.port, limits={"response_timeout": 0.4})
    started = time.monotonic()
    reply = await send(shim.port, pull(hung))
    assert reply.status is None and time.monotonic() - started < 2
    assert shim.upstream.last_error == "response_timeout"
    big = await h.camera(initial=[motion(True)] * 200)
    small = await h.shim(big.port, limits={"max_response_bytes": 4096})
    reply = await send(small.port, pull(big))
    assert reply.status is None or len(reply.body) < len(big.responses[-1])
    assert small.counters.response_too_large == 1


async def test_fifty_cameras_long_poll_concurrently(h):
    cams = [await h.camera(initial=[]) for _ in range(50)]
    shims = [await h.shim(c.port, camera_id=f"cam_{i}") for i, c in enumerate(cams)]
    started = time.monotonic()
    replies = await asyncio.gather(
        *(
            send(s.port, pull(c, body_kw={"timeout": "PT1S"}))
            for s, c in zip(shims, cams)
            for _ in range(2)
        )
    )
    elapsed = time.monotonic() - started
    assert [r.status for r in replies] == [200] * 100
    # 100 one-second long polls finish in ~1 s: nothing serializes them globally.
    assert elapsed < 3, elapsed
    assert all(c.max_active == 2 for c in cams)


async def test_one_stalled_camera_does_not_starve_others(h):
    stalled = await h.camera(hang=True)
    healthy = await h.camera()
    s1 = await h.shim(stalled.port, camera_id="stalled", limits={"response_timeout": 5})
    s2 = await h.shim(healthy.port, camera_id="healthy")
    blocked = [asyncio.create_task(send(s1.port, pull(stalled))) for _ in range(6)]
    await asyncio.sleep(0.2)
    started = time.monotonic()
    replies = await asyncio.gather(
        *(send(s2.port, pull(healthy, body_kw={"timeout": "PT0.1S"})) for _ in range(4))
    )
    assert [r.status for r in replies] == [200] * 4
    assert time.monotonic() - started < 1
    assert s1.counters.rejected_busy == 2  # 4 active + 2 refused, never queued unbounded
    for task in blocked:
        task.cancel()
    await asyncio.gather(*blocked, return_exceptions=True)


async def test_overload_is_bounded(h):
    cam = await h.camera(delay=0.3, missing_to="accept")
    shim = await h.shim(cam.port, limits={"max_active_requests": 4})
    # 60 concurrent clients stay inside the listen backlog (64), so every connection
    # reaches the shim and its own admission control decides (no kernel resets).
    replies = await asyncio.gather(*(send(shim.port, pull(cam)) for _ in range(60)))
    statuses = [r.status for r in replies]
    assert statuses.count(200) >= 4 and set(statuses) <= {200, 503}
    assert statuses.count(503) >= 40
    assert cam.max_active <= 4
    assert shim.counters.active == 0 and not shim._tasks
    busy = next(r for r in replies if r.status == 503)
    assert busy.headers[b"retry-after"] == b"1"


async def test_loop_is_detected_and_fails_open(h):
    # Point the shim's upstream at its own listener: the situation a rule matching the
    # shim's uid would create. It must refuse instead of recursing.
    cam = await h.camera()
    shim = await h.shim(cam.port)
    shim.camera = dataclasses.replace(shim.camera, onvif_port=shim.port)
    reply = await send(shim.port, build_request(pull_body(), host="x"), timeout=5)
    assert reply.status in (None, 503)
    assert shim.counters.loop_detected >= 1 and shim.unsafe_reason == "loop_detected"
    assert shim.snapshot()["process"]["serviceable"] is False
    assert shim._fatal.is_set()


async def test_graceful_drain_completes_in_flight_long_poll(h):
    cam = await h.camera(initial=[])
    shim = await h.shim(cam.port, limits={"drain_timeout": 5})
    task = asyncio.create_task(send(shim.port, pull(cam, body_kw={"timeout": "PT1S"})))
    await asyncio.sleep(0.2)
    await shim.close()
    reply = await task
    assert reply.status == 200
    refused = await send(shim.port, pull(cam))  # listener closed: connection refused
    assert refused.status is None and refused.raw == b""


async def test_restart_keeps_subscription_routing_stateless(h, tmp_path):
    cam = await h.camera()
    first = await h.shim(cam.port, status_dir=str(tmp_path))
    port = first.port
    assert (await send(port, pull(cam))).status == 200
    await first.close()
    config = make_config()
    camera = dataclasses.replace(
        config.cameras[0], camera_ip="127.0.0.1", onvif_port=cam.port, listen_port=port
    )
    second = CameraShim(
        camera,
        config,
        str(tmp_path),
        log=RateLimitedLog("x", 600, sink=h.lines.append),
        direct_budget=10_000,
    )
    await second.start()
    h.cleanup.append(second.close)
    cam.push(motion(True))
    reply = await send(port, pull(cam))
    assert reply.status == 200 and b'Value="true"' in reply.body
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["pid"] and status["process"]["serviceable"] is True


async def test_status_and_logs_are_sanitized(h, tmp_path):
    cam = await h.camera()
    shim = await h.shim(cam.port, status_dir=str(tmp_path))
    raw = pull(
        cam,
        target="/onvif/PullSubManager?Idx=00_0&token=SECRETTOKEN",
        extra=[("Cookie", "session=COOKIESECRET")],
    )
    await send(shim.port, raw)
    await send(shim.port, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n\r\n")
    shim.write_status()
    text = (tmp_path / "status.json").read_text() + "\n".join(h.lines)
    for secret in (
        "0123456789abcdef",
        "COOKIESECRET",
        "SECRETTOKEN",
        "q2Vr0Y3RkCc5r",
        "Zm9vYmFyYmF6",
        "PullSubManager",
        "admin",
    ):
        assert secret not in text, secret
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["detection_verified"] is False and status["recording"] == "not_assessed"


async def test_log_rate_limit_bounds_output():
    lines = []
    clock = [0.0]
    log = RateLimitedLog("cam", 5, clock=lambda: clock[0], sink=lines.append)
    for _ in range(100):
        log("warn", "x")
    assert len(lines) == 5 and log.suppressed == 95
    clock[0] += 60
    log("warn", "x")
    assert len(lines) == 6


async def test_ai_mode_disabled_by_default_preserves_raw_motion(h):
    cam = await h.camera(initial=[])
    shim = await h.shim(cam.port)
    assert shim.translator is None
    cam.push(ai("PeopleDetect", True), motion(True))
    reply = await send(shim.port, pull(cam))
    assert reply.body == cam.responses[-1]


async def test_ai_mode_end_to_end_is_explicit(h):
    cam = await h.camera()
    shim = await h.shim(cam.port, mode="ai_motion", ai_motion={"off_hold_seconds": 0})
    first = await send(shim.port, pull(cam))
    assert first.status == 200 and int(first.headers[b"content-length"]) == len(first.body)
    cam.push(ai("PeopleDetect", True), motion(True))
    reply = await send(shim.port, pull(cam))
    parsed = soap.parse_pull_response(reply.body)
    values = [
        soap.motion_value(n) for n in parsed.notifications if soap.motion_value(n) is not None
    ]
    assert values == [True]  # raw pixel motion dropped, one synthetic on
    assert reply.body != cam.responses[-1]


async def test_direct_connections_cannot_starve_redirected_traffic(h):
    cam = await h.camera(hang=True)
    shim = await h.shim(cam.port, limits={"drain_timeout": 1})
    shim.direct_budget = 1
    shim._origin = lambda sock: "direct"
    first = asyncio.create_task(send(shim.port, pull(cam), timeout=3))
    await asyncio.sleep(0.2)
    second = await send(shim.port, pull(cam))
    assert second.status == 503 and shim.counters.rejected_busy == 1
    shim._origin = lambda sock: "redirected"
    third = asyncio.create_task(send(shim.port, pull(cam), timeout=3))
    await asyncio.sleep(0.2)
    assert shim.counters.active == 2  # redirected traffic still admitted
    for task in (first, third):
        task.cancel()
    await asyncio.gather(first, third, return_exceptions=True)
