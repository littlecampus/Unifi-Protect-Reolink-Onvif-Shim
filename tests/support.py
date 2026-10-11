"""Test doubles for the NVR-local shim: a mock Reolink ONVIF camera and a raw client.

The mock reproduces the behavior established on Parking East: authenticated
PullMessages without wsa:To closes the connection with no response; adding
To yields HTTP 200. `missing_to="400"` reproduces the upstream README behavior.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

from shimlib import soap

ENV = "http://www.w3.org/2003/05/soap-envelope"
WSSE = (
    '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">'
    "<wsse:UsernameToken><wsse:Username>admin</wsse:Username>"
    '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
    "q2Vr0Y3RkCc5r+5L1n2vWw0aZ2o=</wsse:Password>"
    "<wsse:Nonce>Zm9vYmFyYmF6</wsse:Nonce>"
    '<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-10-11T12:00:00Z</wsu:Created>'
    "</wsse:UsernameToken></wsse:Security>"
)


def pull_body(timeout: str = "PT2S", limit: int = 10, header: str | None = WSSE) -> bytes:
    """A PullMessages request shaped like Protect's: WS-Security, no WS-Addressing."""
    head = f"<s:Header>{header}</s:Header>" if header is not None else ""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="{ENV}" '
        'xmlns:tev="http://www.onvif.org/ver10/events/wsdl">'
        f"{head}<s:Body><tev:PullMessages><tev:Timeout>{timeout}</tev:Timeout>"
        f"<tev:MessageLimit>{limit}</tev:MessageLimit></tev:PullMessages></s:Body></s:Envelope>"
    ).encode()


def create_body() -> bytes:
    return (
        f'<s:Envelope xmlns:s="{ENV}"><s:Header>{WSSE}</s:Header><s:Body>'
        '<tev:CreatePullPointSubscription xmlns:tev="http://www.onvif.org/ver10/events/wsdl">'
        "<tev:InitialTerminationTime>PT60S</tev:InitialTerminationTime>"
        "</tev:CreatePullPointSubscription></s:Body></s:Envelope>"
    ).encode()


def renew_body() -> bytes:
    return (
        f'<s:Envelope xmlns:s="{ENV}"><s:Header>{WSSE}</s:Header><s:Body>'
        '<wsnt:Renew xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">'
        "<wsnt:TerminationTime>PT60S</wsnt:TerminationTime></wsnt:Renew></s:Body></s:Envelope>"
    ).encode()


def notification(topic: str, item: str, value: str, operation: str = "Changed") -> str:
    return (
        "<wsnt:NotificationMessage>"
        f'<wsnt:Topic Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">'
        f"tns1:{topic}</wsnt:Topic>"
        f'<wsnt:Message><tt:Message UtcTime="2026-10-11T12:00:00Z" '
        f'PropertyOperation="{operation}">'
        '<tt:Source><tt:SimpleItem Name="VideoSourceConfigurationToken" Value="000"/>'
        '<tt:SimpleItem Name="Rule" Value="MyMotionDetectorRule"/></tt:Source>'
        f'<tt:Data><tt:SimpleItem Name="{item}" Value="{value}"/></tt:Data>'
        "</tt:Message></wsnt:Message></wsnt:NotificationMessage>"
    )


def motion(value: bool, operation: str = "Changed") -> str:
    return notification(
        "RuleEngine/CellMotionDetector/Motion", "IsMotion", str(value).lower(), operation
    )


def ai(kind: str, value: bool, operation: str = "Changed") -> str:
    return notification(f"RuleEngine/MyRuleDetector/{kind}", "State", str(value).lower(), operation)


def pull_response(messages: list[str]) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="{ENV}" '
        'xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" '
        'xmlns:tev="http://www.onvif.org/ver10/events/wsdl" '
        'xmlns:tt="http://www.onvif.org/ver10/schema" '
        'xmlns:tns1="http://www.onvif.org/ver10/topics">'
        "<SOAP-ENV:Header/><SOAP-ENV:Body><tev:PullMessagesResponse>"
        "<tev:CurrentTime>2026-10-11T12:00:00Z</tev:CurrentTime>"
        "<tev:TerminationTime>2026-10-11T12:01:00Z</tev:TerminationTime>"
        + "".join(messages)
        + "</tev:PullMessagesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    ).encode()


@dataclass
class Received:
    method: bytes
    target: bytes
    headers: dict[bytes, bytes]
    raw_headers: bytes
    body: bytes


@dataclass
class MockCamera:
    host: str = "127.0.0.1"
    port: int = 0
    missing_to: str = "close"  # "close" | "400" | "accept"
    chunked: bool = False
    hang: bool = False
    delay: float = 0.0
    initial: list[str] = field(default_factory=lambda: [motion(False, "Initialized")])
    received: list[Received] = field(default_factory=list)
    responses: list[bytes] = field(default_factory=list)
    server: asyncio.base_events.Server | None = None
    events: asyncio.Queue | None = None
    _initialized: set[bytes] = field(default_factory=set)
    _tasks: set = field(default_factory=set)
    connections: int = 0
    active: int = 0
    max_active: int = 0

    async def start(self):
        self.events = asyncio.Queue()
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        if self.server:
            self.server.close()
            # Python 3.12's wait_closed() waits for handlers; cancel hung ones first.
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            await asyncio.wait_for(self.server.wait_closed(), 5)

    def push(self, *messages: str):
        self.events.put_nowait(list(messages))

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._handle_inner(reader, writer)
        finally:
            self._tasks.discard(task)

    async def _handle_inner(self, reader, writer):
        self.connections += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await self._serve(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.active -= 1
            writer.close()

    async def _serve(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head[:-4].split(b"\r\n")
        method, target, _ = lines[0].split(b" ")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get(b"content-length", b"0"))
        body = await reader.readexactly(length)
        self.received.append(Received(method, target, headers, head, body))
        if self.hang:
            await asyncio.sleep(3600)
        if self.delay:
            await asyncio.sleep(self.delay)
        if b"PullMessages" in body:
            await self._pull(target, body, writer)
        elif b"CreatePullPointSubscription" in body:
            address = f"http://{self.host}:{self.port}/onvif/PullSubManager?Idx=00_{len(self._initialized)}"
            self._send(
                writer,
                (
                    f'<s:Envelope xmlns:s="{ENV}"><s:Body><tev:CreatePullPointSubscriptionResponse '
                    'xmlns:tev="http://www.onvif.org/ver10/events/wsdl" '
                    'xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" '
                    'xmlns:wsa="http://www.w3.org/2005/08/addressing">'
                    f"<tev:SubscriptionReference><wsa:Address>{address.replace('&', '&amp;')}"
                    "</wsa:Address></tev:SubscriptionReference>"
                    "</tev:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>"
                ).encode(),
            )
        else:
            self._send(
                writer, f'<s:Envelope xmlns:s="{ENV}"><s:Body><ok/></s:Body></s:Envelope>'.encode()
            )
        await writer.drain()

    def _has_to(self, body: bytes) -> bool:
        env = soap.parse_envelope(body)
        if env.header is None:
            return False
        return any(n.name[1] == "To" and n.name[0] in soap.ANONYMOUS for n in env.header.children)

    async def _pull(self, target, body, writer):
        if not self._has_to(body):
            if self.missing_to == "close":
                return  # the observed Reolink behavior: connection closed, no response
            if self.missing_to == "400":
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
        match = re.search(rb"<tev:Timeout>PT(\d+(?:\.\d+)?)S</tev:Timeout>", body)
        timeout = float(match.group(1)) if match else 2.0
        messages: list[str] = []
        if target not in self._initialized:
            self._initialized.add(target)
            messages.extend(self.initial)
        if not messages:
            try:
                messages = await asyncio.wait_for(self.events.get(), timeout)
            except TimeoutError:
                messages = []
        self._send(writer, pull_response(messages))

    def _send(self, writer, payload: bytes):
        self.responses.append(payload)
        if self.chunked:
            middle = len(payload) // 2
            chunks = [payload[:middle], payload[middle:]]
            body = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in chunks) + b"0\r\n\r\n"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" + body
            )
        else:
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
            )


@dataclass
class Reply:
    status: int | None
    headers: dict[bytes, bytes]
    body: bytes
    raw: bytes
    elapsed: float


def build_request(
    body: bytes,
    *,
    host: str,
    target: str = "/onvif/PullSubManager?Idx=00_0",
    extra: list[tuple[str, str]] = (),
    method: str = "POST",
) -> bytes:
    lines = [
        f"{method} {target} HTTP/1.1",
        f"Host: {host}",
        'Content-Type: application/soap+xml; charset=utf-8; action="http://www.onvif.org/'
        'ver10/events/wsdl/PullPointSubscription/PullMessagesRequest"',
        'Authorization: Digest username="admin", realm="x", nonce="n", uri="/onvif", '
        'response="0123456789abcdef"',
    ]
    lines += [f"{k}: {v}" for k, v in extra]
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def send(port: int, raw: bytes, *, host: str = "127.0.0.1", timeout: float = 30) -> Reply:
    started = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(raw)
        await writer.drain()
    except OSError:
        # Listen backlog overflow (kernel-level admission) or an early close.
        return Reply(None, {}, b"", b"", time.monotonic() - started)
    data = b""
    try:
        async with asyncio.timeout(timeout):
            while chunk := await reader.read(65536):
                data += chunk
    except (ConnectionResetError, ConnectionError):
        pass
    finally:
        writer.close()
    elapsed = time.monotonic() - started
    if not data:
        return Reply(None, {}, b"", data, elapsed)
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        headers[k.strip().lower()] = v.strip()
    if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
        decoded, rest = b"", body
        while True:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line, 16)
            if size == 0:
                break
            decoded += rest[:size]
            rest = rest[size + 2 :]
        body = decoded
    return Reply(status, headers, body, data, elapsed)
