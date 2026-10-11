"""Opt-in identity metadata; local mocks, not Protect adoption acceptance."""

import json
from dataclasses import replace

import pytest
from aiohttp import web

from external_proxy import (
    DEVICE,
    Camera,
    Config,
    UnsafeXML,
    VirtualIdentity,
    rewrite_response,
)
from tests.test_external_proxy import SECURITY, envelope, harness

IDENTITY = VirtualIdentity("02:00:00:00:00:13", "proxy-parking-east")
CAMERA = Camera(
    "east", "127.0.0.1", 18013, "http://192.0.2.13:8000", "http://192.0.2.8:80", IDENTITY
)


def device(body, header=""):
    return envelope(body, header, f'xmlns:d="{DEVICE}" xmlns:v="urn:vendor"')


def information():
    return device(
        "<d:GetDeviceInformationResponse><d:Manufacturer>Reolink</d:Manufacturer>"
        "<d:Model>RLC410</d:Model><d:FirmwareVersion>real-version</d:FirmwareVersion>"
        "<d:SerialNumber>physical-serial</d:SerialNumber>"
        "<d:HardwareId>IPC51516M5M</d:HardwareId></d:GetDeviceInformationResponse>",
        "<s:Header>" + SECURITY + "</s:Header>",
    )


def interfaces():
    return device(
        '<d:GetNetworkInterfacesResponse><d:NetworkInterfaces token="eth0">'
        "<t:Enabled>true</t:Enabled><t:Info><t:Name>eth0</t:Name>"
        "<t:HwAddress>EC:71:DB:B6:19:A3</t:HwAddress><t:MTU>1500</t:MTU></t:Info>"
        "<t:IPv4><t:Enabled>true</t:Enabled><t:Config>"
        "<t:Manual><t:Address>192.0.2.13</t:Address><t:PrefixLength>24</t:PrefixLength></t:Manual>"
        "<t:FromDHCP><t:Address>192.0.2.13</t:Address><t:PrefixLength>24</t:PrefixLength></t:FromDHCP>"
        "<t:LinkLocal><t:Address>169.254.1.13</t:Address><t:PrefixLength>16</t:PrefixLength></t:LinkLocal>"
        "<t:DHCP>false</t:DHCP></t:Config></t:IPv4>"
        "<t:IPv6><t:Config><t:Manual><t:Address>fe80::13</t:Address></t:Manual>"
        "</t:Config></t:IPv6></d:NetworkInterfaces></d:GetNetworkInterfacesResponse>"
    )


def test_identity_disabled_is_byte_exact():
    cam = replace(CAMERA, virtual_identity=None)
    for data in (information(), interfaces()):
        assert rewrite_response(data, cam) == data


def test_virtual_serial_preserves_model_auth_and_hardware_bytes():
    data = information()
    assert rewrite_response(data, CAMERA) == data.replace(b"physical-serial", b"proxy-parking-east")


def test_network_metadata_uses_public_not_container_ip():
    data = interfaces()
    expected = data.replace(b"EC:71:DB:B6:19:A3", IDENTITY.mac.encode())
    expected = expected.replace(b">192.0.2.13<", b">192.0.2.8<")
    assert rewrite_response(data, CAMERA) == expected


@pytest.mark.parametrize(
    "soap", ["http://www.w3.org/2003/05/soap-envelope", "http://schemas.xmlsoap.org/soap/envelope/"]
)
def test_namespace_aliases_and_default_namespace(soap):
    data = (
        f'<Envelope xmlns="{soap}"><Body><GetDeviceInformationResponse xmlns="{DEVICE}">'
        "<SerialNumber><![CDATA[physical]]></SerialNumber></GetDeviceInformationResponse>"
        "</Body></Envelope>"
    ).encode()
    result = rewrite_response(data, CAMERA)
    assert b"<SerialNumber>proxy-parking-east</SerialNumber>" in result


def test_only_exact_metadata_paths_are_changed():
    body = (
        "<d:GetDeviceInformationResponse><v:SerialNumber>vendor</v:SerialNumber>"
        "<d:Extension><d:SerialNumber>nested</d:SerialNumber></d:Extension>"
        "</d:GetDeviceInformationResponse>"
    )
    data = device(body, "<s:Header><d:SerialNumber>header</d:SerialNumber></s:Header>")
    assert rewrite_response(data, CAMERA) == data
    for wrapper in ("s:Fault", "v:GetDeviceInformationResponse", "e:PullMessagesResponse"):
        data = device(
            f"<{wrapper}><d:GetDeviceInformationResponse>"
            "<d:SerialNumber>physical</d:SerialNumber>"
            f"</d:GetDeviceInformationResponse></{wrapper}>"
        )
        assert rewrite_response(data, CAMERA) == data


def test_events_video_and_requests_are_not_identity_adapted():
    data = device(
        '<e:PullMessagesResponse><t:Message><t:Source><t:SimpleItem Name="MAC" '
        'Value="EC71DBB619A3"/></t:Source></t:Message></e:PullMessagesResponse>'
        "<t:MediaUri><t:Uri>rtsp://192.0.2.13:554/main</t:Uri></t:MediaUri>"
        "<t:SnapshotUri><t:Uri>http://192.0.2.13/snap</t:Uri></t:SnapshotUri>"
        "<d:SetNetworkInterfaces><t:Info><t:HwAddress>physical</t:HwAddress></t:Info>"
        "</d:SetNetworkInterfaces>"
    )
    assert rewrite_response(data, CAMERA) == data


@pytest.mark.parametrize("value", ["<d:SerialNumber/>", "<d:SerialNumber><v:x/></d:SerialNumber>"])
def test_unexpected_leaf_structure_fails_closed(value):
    with pytest.raises(UnsafeXML):
        rewrite_response(
            device(f"<d:GetDeviceInformationResponse>{value}</d:GetDeviceInformationResponse>"),
            CAMERA,
        )


def test_identity_edits_respect_xml_signatures():
    signed = information().replace(
        b"<s:Header>", b'<s:Header><sig:Signature xmlns:sig="http://www.w3.org/2000/09/xmldsig#"/>'
    )
    with pytest.raises(UnsafeXML, match="Signed XML"):
        rewrite_response(signed, CAMERA)
    assert rewrite_response(signed, replace(CAMERA, virtual_identity=None)) == signed
    already_virtual = signed.replace(b"physical-serial", IDENTITY.serial.encode())
    assert rewrite_response(already_virtual, CAMERA) == already_virtual


async def test_network_metadata_over_http():
    async def callback(index, request, body):
        return web.Response(body=interfaces(), content_type="application/soap+xml")

    async with harness(callback=callback, identities={0: IDENTITY}) as (_, cameras, seen, client):
        request = device("<d:GetNetworkInterfaces/>")
        async with client.post(cameras[0].public + "/onvif", data=request) as response:
            assert response.status == 200
            expected = interfaces().replace(b"EC:71:DB:B6:19:A3", IDENTITY.mac.encode())
            expected = expected.replace(b">192.0.2.13<", b">127.0.0.1<")
            assert await response.read() == expected
        assert seen[0][0][2] == request


def test_network_namespace_aliases_and_soap11():
    data = interfaces().replace(b"t:", b"tt:").replace(b"xmlns:t=", b"xmlns:tt=")
    data = data.replace(
        b"http://www.w3.org/2003/05/soap-envelope",
        b"http://schemas.xmlsoap.org/soap/envelope/",
    )
    expected = data.replace(b"EC:71:DB:B6:19:A3", IDENTITY.mac.encode())
    expected = expected.replace(b">192.0.2.13<", b">192.0.2.8<")
    assert rewrite_response(data, CAMERA) == expected


def config_file(tmp_path, identity):
    raw = {
        "cameras": [
            {
                "id": "east",
                "listen_host": "0.0.0.0",
                "listen_port": 18013,
                "upstream": CAMERA.upstream,
                "public": CAMERA.public,
                "virtual_identity": identity,
            }
        ]
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw))
    return path, raw


def test_config_identity_roundtrip_and_restart_stability(tmp_path):
    path, _ = config_file(tmp_path, {"mac": IDENTITY.mac, "serial": IDENTITY.serial})
    first = Config.load(str(path))
    second = Config.load(str(path))
    assert first == second
    assert first.cameras[0].virtual_identity == IDENTITY
    assert rewrite_response(information(), first.cameras[0]) == rewrite_response(
        information(), second.cameras[0]
    )


@pytest.mark.parametrize(
    "identity",
    [
        None,
        True,
        {},
        {"mac": IDENTITY.mac},
        {"mac": "EC:71:DB:B6:19:A3", "serial": "proxy"},  # globally administered
        {"mac": "03:00:00:00:00:13", "serial": "proxy"},  # multicast
        {"mac": "020000000013", "serial": "proxy"},
        {"mac": 13, "serial": "proxy"},
        {"mac": IDENTITY.mac, "serial": ""},
        {"mac": IDENTITY.mac, "serial": "unsafe\nserial"},
        {"mac": IDENTITY.mac, "serial": "x" * 65},
        {"mac": IDENTITY.mac, "serial": "proxy", "ip": "192.0.2.99"},
    ],
)
def test_invalid_identity_config(tmp_path, identity):
    path, _ = config_file(tmp_path, identity)
    with pytest.raises(ValueError):
        Config.load(str(path))


@pytest.mark.parametrize("field", ["mac", "serial"])
def test_duplicate_virtual_identities_rejected(tmp_path, field):
    path, raw = config_file(tmp_path, {"mac": IDENTITY.mac, "serial": IDENTITY.serial})
    other = dict(
        raw["cameras"][0],
        id="west",
        listen_port=18014,
        public="http://192.0.2.9:80",
        virtual_identity={"mac": "02:00:00:00:00:14", "serial": "proxy-west"},
    )
    other["virtual_identity"][field] = raw["cameras"][0]["virtual_identity"][field].lower()
    raw["cameras"].append(other)
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="Duplicate virtual"):
        Config.load(str(path))


def test_virtual_identity_requires_ipv4_public_origin(tmp_path):
    path, raw = config_file(tmp_path, {"mac": IDENTITY.mac, "serial": IDENTITY.serial})
    raw["cameras"][0]["public"] = "http://[2001:db8::8]:80"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="IPv4"):
        Config.load(str(path))


@pytest.mark.parametrize(
    "integrity", [None, {"Authentication-Info": 'qop="auth-int"'}, {"Content-Digest": "protected"}]
)
async def test_http_identity_response_and_integrity_guard(integrity):
    async def callback(index, request, body):
        return web.Response(
            body=information(), content_type="application/soap+xml", headers=integrity
        )

    async with harness(callback=callback, identities={0: IDENTITY}) as (_, cameras, seen, client):
        request = device("<d:GetDeviceInformation/>", "<s:Header>" + SECURITY + "</s:Header>")
        async with client.post(
            cameras[0].public + "/onvif/device_service",
            data=request,
            headers={"Authorization": 'Digest qop="auth"'},
        ) as response:
            assert response.status == (502 if integrity else 200)
            if not integrity:
                assert await response.read() == information().replace(
                    b"physical-serial", IDENTITY.serial.encode()
                )
        assert seen[0][0][2] == request
        assert seen[0][0][1]["Authorization"] == 'Digest qop="auth"'


async def test_mixed_identity_mapping_isolation_and_restart():
    async def callback(index, request, body):
        return web.Response(body=information(), content_type="application/soap+xml")

    async with harness(2, callback, identities={0: IDENTITY}) as (proxy, cameras, _, client):
        for _ in range(2):
            for index, cam in enumerate(cameras):
                async with client.post(
                    cam.public + "/onvif", data=device("<d:GetDeviceInformation/>")
                ) as response:
                    assert response.status == 200
                    expected = (
                        information().replace(b"physical-serial", IDENTITY.serial.encode())
                        if index == 0
                        else information()
                    )
                    assert await response.read() == expected
            await proxy.close()
            await proxy.start()
