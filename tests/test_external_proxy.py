"""Integration tests against LOCAL MOCK ONVIF cameras; not hardware acceptance."""

import asyncio
import json
import socket
import time
from contextlib import asynccontextmanager

import aiohttp
import pytest
from aiohttp import web
from yarl import URL

from external_proxy import EVENTS, WSA, Camera, Config, Proxy, parse_xml

S = "http://www.w3.org/2003/05/soap-envelope"
N = "http://docs.oasis-open.org/wsn/b-2"
T = "http://www.onvif.org/ver10/schema"


def envelope(body="<e:PullMessages/>", header="", declarations=""):
    return (
        f'<s:Envelope xmlns:s="{S}" xmlns:e="{EVENTS}" xmlns:n="{N}" '
        f'xmlns:t="{T}" xmlns:w="{WSA}" {declarations}>'
        f"{header}<s:Body>{body}</s:Body></s:Envelope>"
    ).encode()


SECURITY = (
    '<z:Security xmlns:z="urn:test:security"><z:UsernameToken>'
    '<z:Username>admin</z:Username><z:Password Type="digest">abc&amp;xyz</z:Password>'
    "<z:Nonce>credential-do-not-log</z:Nonce></z:UsernameToken></z:Security>"
)


def free_ports(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


@asynccontextmanager
async def harness(count=1, callback=None, **limits):
    runners = []
    seen = [[] for _ in range(count)]
    proxy = None
    try:
        upstreams = []
        for index in range(count):

            async def handler(request, index=index):
                body = await request.read()
                seen[index].append((request.raw_path, request.headers.copy(), body))
                if callback:
                    return await callback(index, request, body)
                return web.Response(
                    body=envelope("<e:PullMessagesResponse/>"), content_type="application/soap+xml"
                )

            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            runners.append(runner)
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            upstreams.append(f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}")
        ports = free_ports(count + 1)
        cameras = tuple(
            Camera(f"cam_{i}", "127.0.0.1", ports[i], upstreams[i], f"http://127.0.0.1:{ports[i]}")
            for i in range(count)
        )
        config = Config(cameras, health_port=ports[-1], **limits)
        proxy = Proxy(config)
        await proxy.start()
        async with aiohttp.ClientSession() as client:
            yield proxy, cameras, seen, client
    finally:
        if proxy:
            await proxy.close()
        await asyncio.gather(*(runner.cleanup() for runner in runners))


def elements(data, name):
    return [n for n in parse_xml(data)[1] if n.name == (WSA, name)]


@pytest.mark.parametrize(
    "header",
    [
        "",
        "<s:Header/>",
        "<s:Header>" + SECURITY + "</s:Header>",
        "<s:Header><w:Action>original-action</w:Action></s:Header>",
        "<s:Header><w:ReplyTo><w:Address>anonymous</w:Address></w:ReplyTo></s:Header>",
    ],
)
async def test_forward_selective_repair_and_auth_bytes(header):
    async with harness() as (_, cameras, seen, client):
        cam = cameras[0]
        path = "/onvif/PullSubManager?subscription=42%2F7&x=a%2Bb"
        async with client.post(
            URL(cam.public + path, encoded=True),
            data=envelope(header=header),
            headers={
                "Authorization": 'Digest username="admin", qop="auth"',
                "SOAPAction": '"original-soap-action"',
                "Content-Type": "application/soap+xml",
            },
        ) as response:
            assert response.status == 200
        raw_path, headers, forwarded = seen[0][0]
        assert raw_path == path
        assert headers["Authorization"] == 'Digest username="admin", qop="auth"'
        assert headers["SOAPAction"] == '"original-soap-action"'
        assert headers["Host"] == cam.upstream.removeprefix("http://")
        assert len(elements(forwarded, "To")) == 1
        assert elements(forwarded, "To")[0].text == cam.upstream + path
        assert len(elements(forwarded, "Action")) == 1
        expected = (
            "original-action"
            if "original-action" in header
            else EVENTS + "/PullPointSubscription/PullMessagesRequest"
        )
        assert elements(forwarded, "Action")[0].text == expected
        if SECURITY in header:
            assert SECURITY.encode() in forwarded


@pytest.mark.parametrize(
    "operation, namespace",
    [
        ("PullMessages", EVENTS),
        ("SetSynchronizationPoint", EVENTS),
        ("Renew", N),
        ("Unsubscribe", N),
    ],
)
async def test_all_upstream_operation_mappings(operation, namespace):
    async with harness() as (_, cameras, seen, client):
        data = envelope(f'<o:{operation} xmlns:o="{namespace}"/>')
        async with client.post(cameras[0].public + "/subscription/42", data=data) as response:
            assert response.status == 200
        assert elements(seen[0][0][2], "Action")[0].text.endswith(operation + "Request")


async def test_complete_headers_target_translation_and_qname_preservation():
    async with harness() as (_, cameras, seen, client):
        cam = cameras[0]
        data = envelope(
            "<e:PullMessages><t:Topic>tns:Motion</t:Topic></e:PullMessages>",
            "<s:Header>" + SECURITY + f"<w:To>{cam.public}/sub?id=3</w:To>"
            "<w:Action>existing</w:Action></s:Header>",
            'xmlns:tns="urn:qname-declaration-not-used-in-element-name"',
        )
        async with client.post(cam.public + "/sub?id=3", data=data) as response:
            assert response.status == 200
        forwarded = seen[0][0][2]
        assert forwarded == data.replace(cam.public.encode(), cam.upstream.encode())
        # Already-real target and complete headers must be byte-for-byte unchanged.
        async with client.post(cam.public + "/sub?id=3", data=forwarded) as response:
            assert response.status == 200
        assert seen[0][1][2] == forwarded


async def test_unknown_operation_and_camera_identity_unchanged():
    output = envelope(
        "<t:GetDeviceInformationResponse><t:SerialNumber>unique-123</t:SerialNumber>"
        "<t:HardwareId>IPC_51516M5M</t:HardwareId></t:GetDeviceInformationResponse>"
    )

    async def camera(index, request, body):
        return web.Response(body=output, content_type="application/soap+xml")

    async with harness(callback=camera) as (_, cameras, seen, client):
        data = envelope("<t:GetDeviceInformation/>", "<s:Header>" + SECURITY + "</s:Header>")
        async with client.post(cameras[0].public + "/onvif/device_service", data=data) as response:
            assert await response.read() == output
        assert seen[0][0][2] == data


async def test_rewrite_control_urls_preserve_rtsp_snapshots_and_restart():
    upstream = None

    async def camera(index, request, body):
        output = envelope(
            f'<d:GetCapabilitiesResponse xmlns:d="http://www.onvif.org/ver10/device/wsdl">'
            f"<d:Capabilities><t:Events><t:XAddr>{upstream}/onvif/events?channel=1&amp;x=2</t:XAddr>"
            f"</t:Events></d:Capabilities></d:GetCapabilitiesResponse><e:SubscriptionReference>"
            f"<w:Address>{upstream}/onvif/PullSubManager?sid=42%2F9&amp;k=7</w:Address>"
            "<w:ReferenceParameters><t:Token>opaque-secret-token</t:Token></w:ReferenceParameters>"
            "</e:SubscriptionReference><t:MediaUri><t:Uri>rtsp://10.0.0.1:554/main</t:Uri>"
            "</t:MediaUri><t:Snapshot><t:Uri>http://10.0.0.1:80/snap?token=secret</t:Uri>"
            "</t:Snapshot>"
        )
        return web.Response(body=output, content_type="application/soap+xml")

    async with harness(callback=camera) as (proxy, cameras, seen, client):
        cam = cameras[0]
        upstream = cam.upstream
        async with client.post(
            cam.public + "/events", data=envelope("<e:CreatePullPointSubscription/>")
        ) as response:
            output = await response.read()
            assert response.status == 200
        assert (cam.public + "/onvif/events?channel=1&amp;x=2").encode() in output
        assert (cam.public + "/onvif/PullSubManager?sid=42%2F9&amp;k=7").encode() in output
        assert b"rtsp://10.0.0.1:554/main" in output
        assert b"http://10.0.0.1:80/snap?token=secret" in output
        assert b"opaque-secret-token" in output
        await proxy.close()
        await proxy.start()
        # Old subscription URL still routes after restart; no dynamic target cache.
        path = "/onvif/PullSubManager?sid=42%2F9&k=7"
        data = envelope(header="<s:Header><t:Token>opaque-secret-token</t:Token></s:Header>")
        async with client.post(URL(cam.public + path, encoded=True), data=data) as response:
            assert response.status == 200
        assert seen[0][-1][0] == path
        assert b"opaque-secret-token" in seen[0][-1][2]
        async with client.post(
            cam.public + "/events", data=envelope("<e:CreatePullPointSubscription/>")
        ) as response:
            assert response.status == 200  # Re-subscription also forwarded, never synthesized.


async def test_challenges_duplicate_headers_no_cookie_storage_or_redirects():
    calls = 0

    async def camera(index, request, body):
        nonlocal calls
        calls += 1
        if calls == 1:
            return web.Response(
                status=401,
                body=b"challenge",
                headers=[
                    ("WWW-Authenticate", 'Digest realm="mock", nonce="sensitive", qop="auth"'),
                    ("WWW-Authenticate", 'Basic realm="mock"'),
                    ("Set-Cookie", "sid=secret"),
                    ("Connection", "keep-alive"),
                ],
            )
        assert "Cookie" not in request.headers
        return web.Response(status=302, headers={"Location": "/relative-not-supported"})

    async with harness(callback=camera) as (_, cameras, seen, client):
        async with client.post(cameras[0].public + "/onvif", data=envelope()) as response:
            assert response.status == 401
            assert len(response.headers.getall("WWW-Authenticate")) == 2
            assert response.headers["Set-Cookie"] == "sid=secret"
            assert await response.read() == b"challenge"
        async with client.post(
            cameras[0].public + "/onvif",
            data=envelope(),
            headers={"Authorization": "Basic YWRtaW46"},
        ) as response:
            assert response.status == 502
        assert calls == 2  # No redirects followed (SSRF).
        assert seen[0][-1][1]["Authorization"] == "Basic YWRtaW46"


@pytest.mark.parametrize(
    "payload",
    [
        b"<broken",
        b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>',
        envelope(header="<s:Header><w:To>http://169.254.169.254:80/latest</w:To></s:Header>"),
        envelope(header="<s:Header><w:To>http://127.0.0.1:1/</w:To><w:To>bad</w:To></s:Header>"),
        envelope(header="<s:Header><w:Action/></s:Header>"),
        envelope().replace(b"<s:Body>", b"<s:Body><e:Extra/>"),
        envelope(declarations='xmlns:a="urn:a"').replace(b"<e:PullMessages/>", b"<a:PullMessages/>")
        + b"extra",
    ],
)
async def test_malformed_and_ssrf_request_rejected(payload):
    async with harness() as (_, cameras, seen, client):
        async with client.post(cameras[0].public + "/onvif", data=payload) as response:
            assert response.status == 400
        assert not seen[0]


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254:80/",
        "http://user:pass@127.0.0.1:8000/x",
        "http://example.com:8000/x",
        "file:///etc/passwd",
        "http://127.0.0.1:1/x",
    ],
)
async def test_returned_control_url_allowlist(url):
    async def camera(index, request, body):
        return web.Response(
            body=envelope(
                f"<e:SubscriptionReference><w:Address>{url}</w:Address></e:SubscriptionReference>"
            ),
            content_type="application/soap+xml",
        )

    async with harness(callback=camera) as (_, cameras, seen, client):
        async with client.post(cameras[0].public + "/onvif", data=envelope()) as response:
            assert response.status == 502
        assert len(seen[0]) == 1


async def test_size_encoding_limits_and_signed_xml():
    async with harness(max_bytes=1000) as (_, cameras, seen, client):
        cam = cameras[0]
        async with client.post(cam.public + "/onvif", data=b"x" * 1001) as response:
            assert response.status == 413
        data = envelope(
            header='<s:Header><d:Signature xmlns:d="http://www.w3.org/2000/09/xmldsig#"/></s:Header>'
        )
        async with client.post(cam.public + "/onvif", data=data) as response:
            assert response.status == 400
        async with client.post(
            cam.public + "/onvif",
            data=envelope(),
            headers={"Authorization": 'Digest qop="auth-int"'},
        ) as response:
            assert response.status == 400
        async with client.post(
            cam.public + "/onvif", data=b"gzip", headers={"Content-Encoding": "gzip"}
        ) as response:
            assert response.status == 415
        assert not seen[0]


@pytest.mark.parametrize("kind", ["oversized", "malformed", "signed"])
async def test_bad_upstream_response_limits(kind):
    async def camera(index, request, body):
        output = b"x" * 1001 if kind == "oversized" else b"<broken"
        if kind == "signed":
            output = envelope(
                f"<e:SubscriptionReference><w:Address>http://{request.host}/sub</w:Address>"
                "</e:SubscriptionReference>",
                '<s:Header><d:Signature xmlns:d="http://www.w3.org/2000/09/xmldsig#"/></s:Header>',
            )
        return web.Response(body=output, content_type="application/soap+xml")

    async with harness(callback=camera, max_bytes=1000) as (_, cameras, seen, client):
        async with client.post(cameras[0].public + "/onvif", data=envelope()) as response:
            assert response.status == 502


async def test_50_concurrent_cameras_slow_broken_isolation_and_health(caplog):
    arrived = set()
    barrier = asyncio.Event()

    async def camera(index, request, body):
        arrived.add(index)
        if len(arrived) == 50:
            barrier.set()
        await barrier.wait()
        if index == 0:
            await asyncio.sleep(0.7)
        if index == 1:
            request.transport.close()
            return web.Response()
        return web.Response(
            body=envelope(f"<t:SerialNumber>camera-{index}</t:SerialNumber>"),
            content_type="application/soap+xml",
        )

    async with harness(50, camera, request_timeout=0.4, shutdown_timeout=1) as (
        proxy,
        cams,
        seen,
        client,
    ):

        async def call(cam):
            async with client.post(cam.public + "/sub?secret=do-not-log", data=envelope()) as r:
                return r.status, await r.read(), time.monotonic()

        started = time.monotonic()
        tasks = [asyncio.create_task(call(cam)) for cam in cams]
        result = await asyncio.gather(*tasks)
        assert result[0][0] == 504
        assert result[1][0] == 502
        assert all(
            status == 200 and f"camera-{i}".encode() in body
            for i, (status, body, _) in enumerate(result)
            if i >= 2
        )
        assert max(end - started for _, _, end in result[2:]) < 0.35
        assert len(arrived) == 50
        async with client.get(f"http://127.0.0.1:{proxy.config.health_port}/health") as r:
            health = await r.json()
        assert len(health["cameras"]) == 50
        assert health["cameras"]["cam_0"]["last_error"] == "timeout"
        assert health["cameras"]["cam_2"]["transport"] == "responding"
        assert not any(c["detection_verified"] for c in health["cameras"].values())
        assert "do-not-log" not in caplog.text
        assert all(len(requests) == 1 for requests in seen)


async def test_bounded_concurrency_and_reconnect():
    entered = asyncio.Event()
    release = asyncio.Event()

    async def camera(index, request, body):
        if index == 0 and not release.is_set():
            entered.set()
            await release.wait()
        return web.Response(
            body=envelope("<e:PullMessagesResponse/>"), content_type="application/soap+xml"
        )

    async with harness(2, camera, per_camera_concurrency=1) as (_, cams, seen, client):
        first = asyncio.create_task(client.post(cams[0].public + "/sub", data=envelope()))
        await entered.wait()
        async with client.post(cams[0].public + "/sub", data=envelope()) as r:
            assert r.status == 503
        async with client.post(cams[1].public + "/sub", data=envelope()) as r:
            assert r.status == 200
        release.set()
        r = await first
        assert r.status == 200
        await r.read()
        r.release()
        # Closing client connections must not lose subscription routing.
        async with aiohttp.ClientSession() as reconnect:
            async with reconnect.post(cams[0].public + "/sub", data=envelope()) as r:
                assert r.status == 200


def test_validated_50_camera_example_and_invalid_config(tmp_path):
    config = Config.load("config.example.json")
    assert len(config.cameras) == 50
    raw = json.loads(open("config.example.json").read())
    for change in (
        lambda r: r["cameras"][0].update(upstream="http://example.org:8000"),
        lambda r: r["cameras"][1].update(id=r["cameras"][0]["id"]),
        lambda r: r.update(request_timeout=-1),
        lambda r: r.update(global_concurrency=True),
        lambda r: r.update(health_port=r["cameras"][0]["listen_port"]),
        lambda r: r.update(unknown_setting=True),
    ):
        copy = json.loads(json.dumps(raw))
        change(copy)
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(copy))
        with pytest.raises(ValueError):
            Config.load(str(path))
