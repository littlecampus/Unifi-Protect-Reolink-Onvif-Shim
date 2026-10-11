#!/usr/bin/env python3
"""External ONVIF header-only proxy. MIT; operation mappings from Casey Clifton's shim.

XML is parsed for namespace-aware selection, but edited by byte ranges, never
serialized: WS-Security, QName prefix declarations and unrelated bytes stay intact.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import math
import re
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from xml.parsers import expat
from xml.sax.saxutils import escape

import aiohttp
from aiohttp import web
from multidict import CIMultiDict
from yarl import URL

SOAP = {"http://www.w3.org/2003/05/soap-envelope", "http://schemas.xmlsoap.org/soap/envelope/"}
WSA = "http://www.w3.org/2005/08/addressing"
WSAS = {WSA, "http://schemas.xmlsoap.org/ws/2004/08/addressing"}
EVENTS = "http://www.onvif.org/ver10/events/wsdl"
WSNT = "http://docs.oasis-open.org/wsn/b-2"
SCHEMA = "http://www.onvif.org/ver10/schema"
DEVICE = "http://www.onvif.org/ver10/device/wsdl"
TAG_NAME = re.compile(rb"<([^\s/>]+)")
INTEGRITY = {"Content-MD5", "Digest", "Content-Digest", "Repr-Digest"}
HTTP_SIGNATURE = {"Signature", "Signature-Input"}
# Reused from onvif_shim.py ACTIONS; no AI or snapshot code is imported/executed.
ACTIONS = {
    (EVENTS, "PullMessages"): EVENTS + "/PullPointSubscription/PullMessagesRequest",
    (EVENTS, "SetSynchronizationPoint"): EVENTS
    + "/PullPointSubscription/SetSynchronizationPointRequest",
    (WSNT, "Renew"): "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest",
    (
        WSNT,
        "Unsubscribe",
    ): "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
}
LOG = logging.getLogger("external_onvif")
HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


class UnsafeXML(ValueError):
    pass


@dataclass
class Node:
    name: tuple[str, str]
    start: int
    open_end: int
    parent: Node | None
    raw_name: bytes
    empty: bool
    close_start: int = 0
    end: int = 0
    text_parts: list[str] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)

    @property
    def text(self):
        return "".join(self.text_parts)


def parse_xml(data: bytes) -> tuple[Node, list[Node]]:
    """Bounded, DTD-free UTF-8 XML parse with namespace-aware byte spans."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data:
        raise UnsafeXML("UTF-8 required")
    try:
        data.decode("utf-8")
    except UnicodeError as exc:
        raise UnsafeXML("UTF-8 required") from exc
    parser = expat.ParserCreate(namespace_separator="|")
    stack: list[Node] = []
    nodes: list[Node] = []

    def forbidden(*_):
        raise UnsafeXML("DTD/entities prohibited")

    def declaration(version, encoding, standalone):
        if encoding and encoding.lower() not in {"utf-8", "utf8", "us-ascii"}:
            raise UnsafeXML("UTF-8 required")

    def start(name, attrs):
        if len(stack) >= 64 or len(nodes) >= 20000:
            raise UnsafeXML("XML complexity exceeded")
        offset = parser.CurrentByteIndex
        # Find the opening tag end respecting quoted attributes.
        quote = None
        end = offset
        while end < len(data):
            char = data[end]
            if quote:
                if char == quote:
                    quote = None
            elif char in (34, 39):
                quote = char
            elif char == 62:
                break
            end += 1
        match = TAG_NAME.match(data, offset)
        if match is None:
            raise UnsafeXML("Invalid tag")
        raw_name = match.group(1)
        ns, sep, local = name.rpartition("|")
        node = Node(
            (ns if sep else "", local),
            offset,
            end + 1,
            stack[-1] if stack else None,
            raw_name,
            data[end - 1 : end] == b"/",
        )
        if stack:
            stack[-1].children.append(node)
        nodes.append(node)
        stack.append(node)

    def finish(name):
        node = stack.pop()
        node.close_start = parser.CurrentByteIndex
        node.end = node.open_end if node.empty else data.index(b">", node.close_start) + 1

    def text(value):
        if stack:
            stack[-1].text_parts.append(value)

    parser.StartElementHandler = start
    parser.EndElementHandler = finish
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.XmlDeclHandler = declaration
    try:
        parser.Parse(data, True)
    except (expat.ExpatError, ValueError, AttributeError) as exc:
        raise UnsafeXML("Invalid XML") from exc
    if not nodes or nodes[0].name[0] not in SOAP or nodes[0].name[1] != "Envelope":
        raise UnsafeXML("SOAP Envelope required")
    return nodes[0], nodes


def apply_edits(data: bytes, nodes: list[Node], edits: list[tuple[int, int, bytes]]) -> bytes:
    if not edits:
        return data
    if any(n.name == ("http://www.w3.org/2000/09/xmldsig#", "Signature") for n in nodes):
        raise UnsafeXML("Signed XML cannot be changed")
    chunks = []
    position = 0
    for start, end, replacement in sorted(edits):
        if start < position:
            raise UnsafeXML("Overlapping XML edits")
        chunks.extend((data[position:start], replacement))
        position = end
    chunks.append(data[position:])
    return b"".join(chunks)


def replace_text(node: Node, value: str) -> tuple[int, int, bytes]:
    if node.children:
        raise UnsafeXML("Unexpected nested address")
    encoded = escape(value).encode()
    if node.empty:
        raise UnsafeXML("Empty control address")
    return node.open_end, node.close_start, encoded


def origin(value: str) -> str:
    try:
        if not isinstance(value, str) or any(ord(c) <= 32 for c in value) or "\\" in value:
            raise ValueError
        parts = urlsplit(value)
        ipaddress.ip_address(parts.hostname or "")
        if (
            parts.scheme != "http"
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or not parts.port
        ):
            raise ValueError
        return f"http://{parts.netloc}"
    except ValueError as exc:
        raise ValueError(
            "URL must use http, a literal IP and explicit port, without credentials"
        ) from exc


@dataclass(frozen=True)
class Camera:
    id: str
    listen_host: str
    listen_port: int
    upstream: str
    public: str

    def to_upstream(self, value: str) -> str:
        if origin(value) not in {self.upstream, self.public}:
            raise UnsafeXML("Address outside camera allowlist")
        parts = urlsplit(value)
        return self.upstream + (parts.path or "/") + ("?" + parts.query if parts.query else "")

    def to_public(self, value: str) -> str:
        if origin(value) != self.upstream:
            raise UnsafeXML("Returned control address outside camera allowlist")
        parts = urlsplit(value)
        return self.public + (parts.path or "/") + ("?" + parts.query if parts.query else "")


@dataclass(frozen=True)
class Config:
    cameras: tuple[Camera, ...]
    health_host: str = "127.0.0.1"
    health_port: int = 19000
    max_bytes: int = 1048576
    per_camera_concurrency: int = 8
    global_concurrency: int = 512
    request_timeout: float = 100
    connect_timeout: float = 5
    body_timeout: float = 10
    shutdown_timeout: float = 110

    @classmethod
    def load(cls, path: str) -> Config:
        raw = json.loads(Path(path).read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get("cameras"), list):
            raise ValueError("Configuration needs a camera list")
        if set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("Unknown configuration fields")
        cameras = []
        for item in raw.pop("cameras"):
            if not isinstance(item, dict):
                raise ValueError("Camera must be an object")
            if set(item) != {"id", "listen_host", "listen_port", "upstream", "public"}:
                raise ValueError("Camera fields missing or unknown")
            cam = Camera(**item)
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cam.id):
                raise ValueError("Invalid camera id")
            if not isinstance(cam.listen_host, str):
                raise ValueError("Listener host must be a literal IP string")
            ipaddress.ip_address(cam.listen_host)
            if type(cam.listen_port) is not int or not 1024 <= cam.listen_port <= 65535:
                raise ValueError("Use an unprivileged listener port")
            for value in (cam.upstream, cam.public):
                if origin(value) != value:
                    raise ValueError("Endpoints must be origins only (no trailing slash)")
            if cam.upstream == cam.public:
                raise ValueError("Proxy endpoint cannot equal upstream")
            cameras.append(cam)
        if not 1 <= len(cameras) <= 1024 or len({c.id for c in cameras}) != len(cameras):
            raise ValueError("Need 1..1024 uniquely named cameras")
        listeners = [(c.listen_host, c.listen_port) for c in cameras]
        if len(set(listeners)) != len(listeners) or len({c.public for c in cameras}) != len(
            cameras
        ):
            raise ValueError("Duplicate camera endpoint")
        config = cls(tuple(cameras), **raw)
        if {c.upstream for c in cameras} & {c.public for c in cameras}:
            raise ValueError("Upstreams cannot be public proxy endpoints")
        if not isinstance(config.health_host, str):
            raise ValueError("Health host must be a literal IP string")
        ipaddress.ip_address(config.health_host)
        if type(config.health_port) is not int or not 1024 <= config.health_port <= 65535:
            raise ValueError("Invalid health port")
        all_listeners = listeners + [(config.health_host, config.health_port)]
        for i, (host, port) in enumerate(all_listeners):
            for other_host, other_port in all_listeners[i + 1 :]:
                if port == other_port and (
                    host == other_host
                    or host in {"0.0.0.0", "::"}
                    or other_host in {"0.0.0.0", "::"}
                ):
                    raise ValueError("Overlapping listeners")
        for key in ("max_bytes", "per_camera_concurrency", "global_concurrency"):
            value = getattr(config, key)
            if type(value) is not int or not 1 <= value <= 16777216:
                raise ValueError("Invalid resource limit")
        for key in ("request_timeout", "connect_timeout", "body_timeout", "shutdown_timeout"):
            value = getattr(config, key)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("Invalid timeout")
        return config


def repair_request(data: bytes, camera: Camera, path: str) -> bytes:
    envelope, nodes = parse_xml(data)
    headers = [n for n in envelope.children if n.name == (envelope.name[0], "Header")]
    bodies = [n for n in envelope.children if n.name == (envelope.name[0], "Body")]
    if len(headers) > 1 or len(bodies) != 1 or len(bodies[0].children) != 1:
        raise UnsafeXML("Ambiguous SOAP structure")
    action = ACTIONS.get(bodies[0].children[0].name)
    target = camera.upstream + path
    edits = []
    additions = b""
    children = headers[0].children if headers else []
    addressing = [n for n in children if n.name[0] in WSAS]
    namespaces = {n.name[0] for n in addressing}
    if len(namespaces) > 1:
        raise UnsafeXML("Mixed WS-Addressing versions")
    namespace = next(iter(namespaces), WSA)
    for local, value in (("To", target), ("Action", action)):
        existing = [n for n in addressing if n.name[1] == local]
        if len(existing) > 1:
            raise UnsafeXML("Duplicate addressing header")
        if existing and (existing[0].children or not existing[0].text.strip()):
            raise UnsafeXML("Invalid addressing header")
        if existing and local == "To":
            try:
                camera.to_upstream(existing[0].text.strip())
            except ValueError as exc:
                raise UnsafeXML("Invalid addressing target") from exc
            if existing[0].text != target:
                edits.append(replace_text(existing[0], target))
        elif not existing and value and action:
            additions += (
                f'<w:{local} xmlns:w="{namespace}" xmlns:s="{envelope.name[0]}" '
                f's:mustUnderstand="1">{escape(value)}</w:{local}>'
            ).encode()
    if additions:
        if headers:
            header = headers[0]
            if header.empty:
                opening = data[header.start : header.open_end - 2] + b">"
                edits.append(
                    (header.start, header.end, opening + additions + b"</" + header.raw_name + b">")
                )
            else:
                edits.append((header.open_end, header.open_end, additions))
        else:
            fragment = (
                f'<s:Header xmlns:s="{envelope.name[0]}">'.encode() + additions + b"</s:Header>"
            )
            edits.append((bodies[0].start, bodies[0].start, fragment))
    return apply_edits(data, nodes, edits)


def rewrite_response(data: bytes, camera: Camera) -> bytes:
    _, nodes = parse_xml(data)
    edits = []
    for node in nodes:
        ns, local = node.name
        ancestors = []
        parent = node.parent
        while parent is not None:
            ancestors.append(parent.name)
            parent = parent.parent
        service = local == "XAddr" and (
            (
                ns == DEVICE
                and ancestors[:2] == [(DEVICE, "Service"), (DEVICE, "GetServicesResponse")]
            )
            or (
                ns == SCHEMA
                and node.parent is not None
                and node.parent.name[0] == SCHEMA
                and node.parent.name[1]
                in {
                    "Device",
                    "Events",
                    "Media",
                    "PTZ",
                    "Imaging",
                    "Analytics",
                    "DeviceIO",
                    "Recording",
                    "Search",
                    "Replay",
                    "Receiver",
                    "Display",
                }
                and (DEVICE, "GetCapabilitiesResponse") in ancestors
            )
        )
        subscription = (
            local == "Address"
            and ns in WSAS
            and node.parent is not None
            and node.parent.name
            in {(WSNT, "SubscriptionReference"), (EVENTS, "SubscriptionReference")}
        )
        if service or subscription:
            try:
                value = camera.to_public(node.text.strip())
            except ValueError as exc:
                raise UnsafeXML("Invalid control address") from exc
            edits.append(replace_text(node, value))
    return apply_edits(data, nodes, edits)


def has_integrity(headers, auth_header):
    return "auth-int" in headers.get(auth_header, "").lower() or any(
        k in headers for k in INTEGRITY | HTTP_SIGNATURE
    )


def forward_headers(headers, *, changed=False):
    removed = HOP | {x.strip().lower() for x in headers.get("Connection", "").split(",")}
    if changed:
        removed |= {"etag", "content-md5", "digest"}
    return CIMultiDict((k, v) for k, v in headers.items() if k.lower() not in removed)


@dataclass
class Transport:
    active: int = 0
    requests: int = 0
    responses: int = 0
    failures: int = 0
    repaired: int = 0
    last_status: int | None = None
    last_response: float | None = None
    last_error: str | None = None


class Proxy:
    def __init__(self, config: Config):
        self.config = config
        self.states = {c.id: Transport() for c in config.cameras}
        self.sessions: dict[str, aiohttp.ClientSession] = {}
        self.runners: list[web.AppRunner] = []
        self.active = 0
        self.executor = None

    async def start(self):
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="onvif-xml")
        self.xml_slots = asyncio.Semaphore(4)
        try:
            for camera in self.config.cameras:
                self.sessions[camera.id] = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(limit=self.config.per_camera_concurrency),
                    timeout=aiohttp.ClientTimeout(
                        total=self.config.request_timeout, connect=self.config.connect_timeout
                    ),
                    auto_decompress=False,
                    trust_env=False,
                    cookie_jar=aiohttp.DummyCookieJar(),
                    skip_auto_headers={"User-Agent", "Accept-Encoding", "Content-Type"},
                )
                app = web.Application(client_max_size=self.config.max_bytes)
                app.router.add_route("*", "/{tail:.*}", self.handler(camera))
                await self.listen(app, camera.listen_host, camera.listen_port)
            health = web.Application()
            health.router.add_get("/health", self.health)
            await self.listen(health, self.config.health_host, self.config.health_port)
        except BaseException:
            await self.close()
            raise

    async def listen(self, app, host, port):
        runner = web.AppRunner(app, access_log=None, shutdown_timeout=self.config.shutdown_timeout)
        await runner.setup()
        self.runners.append(runner)
        await web.TCPSite(runner, host, port).start()

    async def close(self):
        await asyncio.gather(*(r.cleanup() for r in self.runners))
        await asyncio.gather(*(s.close() for s in self.sessions.values()))
        self.runners.clear()
        self.sessions.clear()
        if self.executor is not None:
            await asyncio.to_thread(self.executor.shutdown, wait=True, cancel_futures=True)
            self.executor = None

    async def transform(self, function, *args):
        # Do not enqueue canceled work faster than XML workers can consume it.
        async with asyncio.timeout(self.config.body_timeout):
            await self.xml_slots.acquire()
            future = asyncio.get_running_loop().run_in_executor(self.executor, function, *args)

            def finished(done):
                self.xml_slots.release()
                if not done.cancelled():
                    done.exception()  # Retrieve errors even if the caller timed out/disconnected.

            future.add_done_callback(finished)
            return await asyncio.shield(future)

    async def health(self, request):
        now = time.time()
        states = {}
        for key, state in self.states.items():
            age = None if state.last_response is None else round(now - state.last_response, 1)
            states[key] = {
                "active": state.active,
                "requests": state.requests,
                "responses": state.responses,
                "failures": state.failures,
                "repaired": state.repaired,
                "last_http_status": state.last_status,
                "last_response_age_seconds": age,
                "last_error": state.last_error,
                "transport": "degraded"
                if state.last_error
                else "unobserved"
                if age is None
                else "degraded"
                if age > self.config.request_timeout * 2
                else "responding",
                "detection_verified": False,
            }
        return web.json_response({"service": "running", "cameras": states})

    def handler(self, camera):
        async def handle(request):
            state = self.states[camera.id]
            if (
                state.active >= self.config.per_camera_concurrency
                or self.active >= self.config.global_concurrency
            ):
                return web.Response(status=503, text="Proxy busy", headers={"Retry-After": "1"})
            state.active += 1
            self.active += 1
            state.requests += 1
            status = 500
            error = None
            started = time.monotonic()
            try:
                if request.method not in {"POST", "GET"}:
                    raise web.HTTPMethodNotAllowed(request.method, ["POST", "GET"])
                path = request.raw_path
                if not path.startswith("/") or path.startswith("//") or "#" in path or "\\" in path:
                    raise web.HTTPBadRequest(text="Invalid request target")
                if request.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise web.HTTPUnsupportedMediaType(text="Encoded request unsupported")
                if any(k in request.headers for k in HTTP_SIGNATURE):
                    raise UnsafeXML("HTTP signed requests unsupported")
                async with asyncio.timeout(self.config.body_timeout):
                    body = await request.read()
                original = body
                if body:
                    body = await self.transform(repair_request, body, camera, path)
                if body != original and has_integrity(request.headers, "Authorization"):
                    raise UnsafeXML("Body integrity authentication cannot be changed")
                headers = forward_headers(request.headers, changed=body != original)
                headers["Accept-Encoding"] = "identity"
                async with self.sessions[camera.id].request(
                    request.method,
                    URL(camera.upstream + path, encoded=True),
                    data=body,
                    headers=headers,
                    allow_redirects=False,
                ) as response:
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise UnsafeXML("Encoded upstream response unsupported")
                    chunks = []
                    size = 0
                    async for chunk in response.content.iter_chunked(65536):
                        size += len(chunk)
                        if size > self.config.max_bytes:
                            raise UnsafeXML("Upstream response too large")
                        chunks.append(chunk)
                    output = b"".join(chunks)
                    raw_output = output
                    if output and (
                        "xml" in response.headers.get("Content-Type", "").lower()
                        or output.lstrip().startswith(b"<")
                    ):
                        output = await self.transform(rewrite_response, output, camera)
                    if output != raw_output and has_integrity(
                        response.headers, "Authentication-Info"
                    ):
                        raise UnsafeXML("Response integrity authentication cannot be changed")
                    outgoing = forward_headers(response.headers, changed=output != raw_output)
                    if "Location" in outgoing:
                        if any(k in response.headers for k in HTTP_SIGNATURE):
                            raise UnsafeXML("Signed redirect cannot be changed")
                        outgoing["Location"] = camera.to_public(outgoing["Location"])
                    status = response.status
                    state.responses += 1
                    state.last_status = status
                    state.last_response = time.time()
                    state.last_error = None if status < 400 else "upstream_http_error"
                    state.repaired += body != original
                    return web.Response(status=status, headers=outgoing, body=output)
            except UnsafeXML:
                status, error = (
                    (502, "unsafe_upstream") if "response" in locals() else (400, "unsafe_request")
                )
            except ValueError:
                status, error = 502, "unsafe_address"
            except TimeoutError:
                status, error = 504, "timeout"
            except (aiohttp.ClientError, OSError):
                status, error = 502, "upstream_transport"
            except web.HTTPException as exc:
                status, error = exc.status, "request_rejected"
                return exc
            finally:
                if error:
                    state.failures += 1
                    state.last_error = error
                state.active -= 1
                self.active -= 1
                LOG.info(
                    json.dumps(
                        {
                            "camera": camera.id,
                            "status": status,
                            "error": error,
                            "elapsed_ms": round((time.monotonic() - started) * 1000),
                        }
                    )
                )
            return web.Response(status=status, text="Proxy rejected request or upstream response")

        return handle


async def run(config):
    proxy = Proxy(config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await proxy.start()
    LOG.info(json.dumps({"event": "started", "camera_count": len(config.cameras)}))
    try:
        await stop.wait()
    finally:
        await proxy.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(2, "Invalid configuration (values withheld); see external deployment guide\n")
    if args.validate:
        print(f"Valid configuration: {len(config.cameras)} cameras")
        return
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # Protocol/debug exceptions can include raw requests. Only our sanitized logs are emitted.
    logging.getLogger("aiohttp").setLevel(logging.CRITICAL)
    asyncio.run(run(config))


if __name__ == "__main__":
    main()
