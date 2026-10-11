"""Regression/security tests against LOCAL MOCK cameras, not hardware."""

import asyncio
import base64
import hashlib
import logging
import re
import threading
import time

import pytest
from aiohttp import web

from external_proxy import DEVICE, EVENTS, WSA, WSNT, parse_xml
from tests.test_external_proxy import SECURITY, elements, envelope, harness


@pytest.mark.parametrize("namespace", [EVENTS, WSNT])
async def test_real_subscription_reference_namespaces(namespace):
    async def camera(index, request, body):
        return web.Response(
            body=envelope(
                f'<r:CreatePullPointSubscriptionResponse xmlns:r="{namespace}">'
                f"<r:SubscriptionReference><w:Address>http://{request.host}/sub?opaque=4%2F2</w:Address>"
                "</r:SubscriptionReference></r:CreatePullPointSubscriptionResponse>"
            ),
            content_type="application/soap+xml",
        )

    async with harness(callback=camera) as (_, cams, _, client):
        async with client.post(cams[0].public + "/events", data=envelope()) as r:
            assert r.status == 200
            assert (cams[0].public + "/sub?opaque=4%2F2").encode() in await r.read()


async def test_getservices_and_unrelated_vendor_xaddr():
    async def camera(index, request, body):
        return web.Response(
            body=envelope(
                f'<d:GetServicesResponse xmlns:d="{DEVICE}"><d:Service>'
                f"<d:Namespace>{EVENTS}</d:Namespace><d:XAddr>http://{request.host}/events</d:XAddr>"
                "</d:Service></d:GetServicesResponse>"
                '<v:XAddr xmlns:v="http://www.onvif.org/vendor/private">http://foreign.invalid:80/x</v:XAddr>'
            ),
            content_type="application/soap+xml",
        )

    async with harness(callback=camera) as (_, cams, _, client):
        async with client.post(cams[0].public + "/onvif", data=envelope()) as r:
            output = await r.read()
            assert r.status == 200
            assert (cams[0].public + "/events").encode() in output
            assert b"http://foreign.invalid:80/x" in output


@pytest.mark.parametrize(
    "header, value",
    [
        ("Authentication-Info", 'qop="auth-int", rspauth="signed-digest"'),
        ("Content-Digest", "sha-256=:hash:"),
        ("Repr-Digest", "sha-256=:hash:"),
        ("Content-MD5", "hash"),
        ("Digest", "SHA-256=hash"),
        ("Signature-Input", 'sig=("@status" "content-digest")'),
        ("Signature", "sig=:hash:"),
    ],
)
async def test_response_integrity_never_silently_invalidated(header, value):
    async def camera(index, request, body):
        return web.Response(
            body=envelope(
                f"<e:SubscriptionReference><w:Address>http://{request.host}/sub</w:Address>"
                "</e:SubscriptionReference>"
            ),
            headers={header: value},
            content_type="application/soap+xml",
        )

    async with harness(callback=camera) as (_, cams, _, client):
        async with client.post(cams[0].public + "/onvif", data=envelope()) as r:
            assert r.status == 502


@pytest.mark.parametrize("header", ["Content-Digest", "Repr-Digest", "Signature-Input"])
async def test_request_modern_integrity_rejected(header):
    async with harness() as (_, cams, seen, client):
        async with client.post(
            cams[0].public + "/sub", data=envelope(), headers={header: "integrity"}
        ) as r:
            assert r.status == 400
        assert not seen[0]


async def test_signed_noop_request_and_response_passthrough():
    signature = '<d:Signature xmlns:d="http://www.w3.org/2000/09/xmldsig#"/>'
    data = envelope("<e:GetEventProperties/>", "<s:Header>" + signature + "</s:Header>")
    output = envelope("<e:GetEventPropertiesResponse/>", "<s:Header>" + signature + "</s:Header>")

    async def camera(index, request, body):
        assert body == data
        return web.Response(
            body=output,
            headers={"Content-Digest": "opaque-hash"},
            content_type="application/soap+xml",
        )

    async with harness(callback=camera) as (_, cams, _, client):
        async with client.post(cams[0].public + "/events", data=data) as r:
            assert r.status == 200
            assert await r.read() == output
            assert r.headers["Content-Digest"] == "opaque-hash"


async def test_to_only_and_old_wsa_namespace_and_soap11():
    async with harness() as (_, cams, seen, client):
        data = envelope(
            header="<s:Header>" + SECURITY + f"<w:To>{cams[0].public}/sub</w:To></s:Header>"
        )
        data = data.replace(WSA.encode(), b"http://schemas.xmlsoap.org/ws/2004/08/addressing")
        data = data.replace(
            b"http://www.w3.org/2003/05/soap-envelope", b"http://schemas.xmlsoap.org/soap/envelope/"
        )
        async with client.post(cams[0].public + "/sub", data=data) as r:
            assert r.status == 200
        nodes = parse_xml(seen[0][0][2])[1]
        assert (
            len(
                [
                    n
                    for n in nodes
                    if n.name == ("http://schemas.xmlsoap.org/ws/2004/08/addressing", "Action")
                ]
            )
            == 1
        )
        assert SECURITY.encode() in seen[0][0][2]


async def test_wrong_operation_namespace_does_not_trigger_repair():
    data = envelope('<f:PullMessages xmlns:f="urn:not-onvif"/>')
    async with harness() as (_, cams, seen, client):
        async with client.post(cams[0].public + "/sub", data=data) as r:
            assert r.status == 200
        assert seen[0][0][2] == data


async def test_authenticated_http_digest_and_wsse_passwordless_roundtrip():
    # Mock verifies both actual digest mechanisms using an explicitly empty password.
    nonce = b"local-mock-nonce"
    created = "2026-01-01T00:00:00Z"
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode()).digest()).decode()
    security = (
        f'<z:Security xmlns:z="urn:mock"><z:UsernameToken><z:Username>admin</z:Username>'
        f"<z:Password>{digest}</z:Password><z:Nonce>{base64.b64encode(nonce).decode()}</z:Nonce>"
        f"<z:Created>{created}</z:Created></z:UsernameToken></z:Security>"
    )
    path = "/sub?sid=42"

    def md5(value):
        return hashlib.md5(value.encode()).hexdigest()

    ha1, ha2 = md5("admin:local-mock:"), md5("POST:" + path)
    expected = md5(ha1 + ":local-nonce:00000001:client-nonce:auth:" + ha2)

    async def camera(index, request, body):
        if "Authorization" not in request.headers:
            return web.Response(
                status=401,
                headers={
                    "WWW-Authenticate": 'Digest realm="local-mock", nonce="local-nonce", qop="auth"'
                },
            )
        fields = dict(re.findall(r'(\w+)="([^"]*)"', request.headers["Authorization"]))
        assert fields["response"] == expected and fields["uri"] == request.raw_path
        assert security.encode() in body
        assert elements(body, "To")[0].text == "http://" + request.host + path
        return web.Response(
            body=envelope("<e:PullMessagesResponse/>"), content_type="application/soap+xml"
        )

    async with harness(callback=camera) as (_, cams, _, client):
        data = envelope(header="<s:Header>" + security + "</s:Header>")
        async with client.post(cams[0].public + path, data=data) as r:
            assert r.status == 401
        auth = (
            f'Digest username="admin", realm="local-mock", nonce="local-nonce", '
            f'uri="{path}", response="{expected}", qop="auth", '
            'nc="00000001", cnonce="client-nonce"'
        )
        async with client.post(
            cams[0].public + path, data=data, headers={"Authorization": auth}
        ) as r:
            assert r.status == 200


async def test_long_poll_drains_on_graceful_shutdown():
    entered = asyncio.Event()

    async def camera(index, request, body):
        entered.set()
        await asyncio.sleep(0.1)
        return web.Response(
            body=envelope("<e:PullMessagesResponse/>"), content_type="application/soap+xml"
        )

    async with harness(callback=camera, shutdown_timeout=2) as (proxy, cams, _, client):
        task = asyncio.create_task(client.post(cams[0].public + "/sub", data=envelope()))
        await entered.wait()
        await proxy.close()
        r = await task
        assert r.status == 200
        await r.read()
        r.release()
        assert proxy.active == 0 and not proxy.sessions


async def test_complex_xml_does_not_starve_other_camera_or_health(caplog):
    caplog.set_level(logging.INFO, logger="external_onvif")
    async with harness(2) as (proxy, cams, _, client):
        large = envelope("<e:PullMessages>" + "<t:Item>data</t:Item>" * 19000 + "</e:PullMessages>")
        task = asyncio.create_task(client.post(cams[0].public + "/sub?token=secret", data=large))
        started = time.monotonic()
        async with client.get(f"http://127.0.0.1:{proxy.config.health_port}/health") as r:
            assert r.status == 200
        async with client.post(cams[1].public + "/sub", data=envelope()) as r:
            assert r.status == 200
        assert time.monotonic() - started < 0.8
        r = await task
        assert r.status == 200
        await r.read()
        r.release()
        assert "secret" not in caplog.text
        assert '"camera": "cam_0"' in caplog.text


async def test_repeated_predefined_entities_roundtrip():
    async with harness() as (_, cams, seen, client):
        data = envelope(
            "<e:PullMessages><t:Topic>" + "&amp;" * 180000 + "</t:Topic></e:PullMessages>"
        )
        async with client.post(cams[0].public + "/sub", data=data) as r:
            assert r.status == 200
        assert (b"&amp;" * 180000) in seen[0][0][2]


async def test_timed_out_xml_work_does_not_grow_executor_queue():
    release = threading.Event()
    started = []

    def blocked():
        started.append(True)
        release.wait(2)
        return b"ok"

    async with harness(body_timeout=0.05) as (proxy, _, _, _client):
        try:
            for _ in range(3):
                result = await asyncio.gather(
                    *(proxy.transform(blocked) for _ in range(8)), return_exceptions=True
                )
                assert all(isinstance(item, TimeoutError) for item in result)
                assert len(started) == 4
                assert proxy.executor._work_queue.qsize() == 0
        finally:
            release.set()
        deadline = time.monotonic() + 2
        while proxy.xml_slots._value != 4 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        assert proxy.xml_slots._value == 4
