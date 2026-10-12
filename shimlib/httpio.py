"""Strict, bounded HTTP/1.x framing helpers for the shim (asyncio streams).

The shim handles exactly one request per client connection and always tells
both sides `Connection: close`, so response framing is only parsed to know when
the camera has finished and to bound sizes; payload bytes are relayed verbatim.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
REQUEST_LINE = re.compile(rb"([!#$%&'*+\-.^_`|~0-9A-Za-z]+) (\S+) (HTTP/1\.[01])")
STATUS_LINE = re.compile(rb"(HTTP/1\.[01]) ([0-9]{3})(?: ([^\r\n]*))?")
HOP_BY_HOP = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
        b"content-length",
        b"expect",
    }
)
# Request headers whose presence means body bytes are integrity-protected.
INTEGRITY_HEADERS = frozenset(
    {b"content-md5", b"digest", b"content-digest", b"repr-digest", b"signature", b"signature-input"}
)
MAX_HEADERS = 100
MAX_CHUNK_LINE = 4096
ALLOWED_METHODS = frozenset({b"GET", b"POST", b"HEAD"})


class HttpError(Exception):
    """Client protocol error answered with an HTTP status (never echoes input)."""

    def __init__(self, status: int, category: str):
        super().__init__(category)
        self.status = status
        self.category = category


class ClientGone(Exception):
    pass


class UpstreamProtocolError(Exception):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


@dataclass
class Head:
    start_line: bytes
    headers: list[tuple[bytes, bytes]]

    def values(self, name: bytes) -> list[bytes]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def first(self, name: bytes) -> bytes | None:
        found = self.values(name)
        return found[0] if found else None

    def connection_tokens(self) -> set[bytes]:
        tokens = set()
        for value in self.values(b"connection"):
            tokens.update(t.strip().lower() for t in value.split(b",") if t.strip())
        return tokens


@dataclass
class Request(Head):
    method: bytes = b""
    target: bytes = b""
    version: bytes = b""


@dataclass
class Response(Head):
    version: bytes = b""
    status: int = 0


def _parse_headers(lines: list[bytes], error) -> list[tuple[bytes, bytes]]:
    if len(lines) > MAX_HEADERS:
        raise error("too_many_headers")
    headers = []
    for line in lines:
        if not line or line[:1] in (b" ", b"\t"):
            raise error("obsolete_folding")
        name, sep, value = line.partition(b":")
        if not sep or not TOKEN.fullmatch(name):
            raise error("bad_header")
        value = value.strip(b" \t")
        if any(c < 32 and c != 9 or c == 127 for c in value):
            raise error("bad_header")
        headers.append((name, value))
    return headers


def parse_request(raw: bytes) -> Request:
    def error(category):
        return HttpError(400, category)

    text = raw.lstrip(b"\r\n")
    if not text.endswith(b"\r\n\r\n"):
        raise error("bad_head")
    lines = text[:-4].split(b"\r\n")
    match = REQUEST_LINE.fullmatch(lines[0])
    if not match:
        raise error("bad_request_line")
    method, target, version = match.groups()
    if method not in ALLOWED_METHODS:
        raise HttpError(405, "method_not_allowed")
    if not target.startswith(b"/") or target.startswith(b"//") or b"#" in target:
        raise error("bad_target")
    if any(c < 33 or c > 126 for c in target):
        raise error("bad_target")
    headers = _parse_headers(lines[1:], error)
    request = Request(lines[0], headers, method=method, target=target, version=version)
    hosts = request.values(b"host")
    if len(hosts) > 1 or (version == b"HTTP/1.1" and not hosts):
        raise error("bad_host")
    return request


def parse_response(raw: bytes) -> Response:
    def error(category):
        return UpstreamProtocolError(category)

    if not raw.endswith(b"\r\n\r\n"):
        raise error("bad_head")
    lines = raw[:-4].split(b"\r\n")
    match = STATUS_LINE.fullmatch(lines[0])
    if not match:
        raise error("bad_status_line")
    headers = _parse_headers(lines[1:], error)
    return Response(lines[0], headers, version=match.group(1), status=int(match.group(2)))


async def read_head(reader: asyncio.StreamReader, limit: int, *, client: bool) -> bytes:
    """Read through the blank line; reader must have been created with limit >= `limit`."""
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError:
        if client:
            raise HttpError(431, "head_too_large") from None
        raise UpstreamProtocolError("head_too_large") from None
    except asyncio.IncompleteReadError as exc:
        if client:
            raise ClientGone() from None
        raise UpstreamProtocolError(
            "closed_without_response" if not exc.partial else "truncated_head"
        ) from None
    if len(raw) > limit:
        if client:
            raise HttpError(431, "head_too_large")
        raise UpstreamProtocolError("head_too_large")
    return raw


def _content_length(head: Head, error) -> int | None:
    values = head.values(b"content-length")
    if not values:
        return None
    parts = {p.strip() for v in values for p in v.split(b",")}
    if len(parts) != 1:
        raise error("conflicting_length")
    value = parts.pop()
    if not value.isdigit() or len(value) > 12:
        raise error("bad_length")
    return int(value)


def request_framing(request: Request) -> tuple[str, int]:
    def error(category):
        return HttpError(400, category)

    te = request.values(b"transfer-encoding")
    length = _content_length(request, error)
    if te:
        if length is not None:
            raise error("length_and_chunked")
        codings = [c.strip().lower() for v in te for c in v.split(b",") if c.strip()]
        if codings != [b"chunked"]:
            raise HttpError(501, "unsupported_transfer_encoding")
        return "chunked", 0
    return ("length", length) if length else ("none", 0)


async def read_chunked(
    reader: asyncio.StreamReader, max_bytes: int, *, writer=None, error=None
) -> bytes:
    """Decode a chunked body. If `writer` is given, raw bytes are relayed verbatim."""
    error = error or (lambda category: HttpError(400, category))
    payload = bytearray()
    while True:
        line = await reader.readuntil(b"\r\n")
        if len(line) > MAX_CHUNK_LINE:
            raise error("bad_chunk")
        size_text = line[:-2].split(b";", 1)[0].strip()
        if (
            not size_text
            or len(size_text) > 8
            or any(c not in b"0123456789abcdefABCDEF" for c in size_text)
        ):
            raise error("bad_chunk")
        size = int(size_text, 16)
        if writer is not None:
            writer.write(line)
        if size == 0:
            break
        if len(payload) + size > max_bytes:
            raise error("too_large")
        chunk = await reader.readexactly(size + 2)
        if chunk[-2:] != b"\r\n":
            raise error("bad_chunk")
        payload += chunk[:-2]
        if writer is not None:
            writer.write(chunk)
            await writer.drain()
    trailers = 0
    while True:
        line = await reader.readuntil(b"\r\n")
        if writer is not None:
            writer.write(line)
        if line == b"\r\n":
            break
        trailers += 1
        if trailers > MAX_HEADERS or len(line) > MAX_CHUNK_LINE:
            raise error("bad_chunk")
    if writer is not None:
        await writer.drain()
    return bytes(payload)


async def read_request_body(
    reader: asyncio.StreamReader, request: Request, max_bytes: int
) -> bytes:
    kind, length = request_framing(request)
    try:
        if kind == "chunked":
            return await read_chunked(reader, max_bytes)
        if kind == "length":
            if length > max_bytes:
                raise HttpError(413, "request_too_large")
            return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise ClientGone() from None
    except asyncio.LimitOverrunError:
        raise HttpError(400, "bad_chunk") from None
    except HttpError as exc:
        if exc.category == "too_large":
            raise HttpError(413, "request_too_large") from None
        raise
    return b""


def integrity_blocker(request: Request) -> str | None:
    """Why the body must not be edited (HTTP-level integrity/encoding), or None."""
    for name, _ in request.headers:
        if name.lower() in INTEGRITY_HEADERS:
            return "skipped_integrity"
    for value in request.values(b"authorization"):
        if b"auth-int" in value.lower():
            return "skipped_integrity"
    for value in request.values(b"content-encoding"):
        if value.strip().lower() not in (b"", b"identity"):
            return "skipped_encoding"
    for value in request.values(b"content-type"):
        match = re.search(rb"charset\s*=\s*\"?([A-Za-z0-9._-]+)", value, re.I)
        if match and match.group(1).lower() not in (b"utf-8", b"utf8", b"us-ascii"):
            return "skipped_encoding"
    return None


def upstream_request(request: Request, body: bytes) -> bytes:
    """Re-frame the request for the camera: same line and headers, explicit length, close."""
    drop = HOP_BY_HOP | request.connection_tokens()
    lines = [request.start_line]
    lines.extend(
        name + b": " + value for name, value in request.headers if name.lower() not in drop
    )
    if body or request.method == b"POST":
        lines.append(b"Content-Length: " + str(len(body)).encode())
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def response_framing(method: bytes, response: Response) -> tuple[str, int]:
    def error(category):
        return UpstreamProtocolError(category)

    if method == b"HEAD" or response.status in (204, 304) or 100 <= response.status < 200:
        return "none", 0
    te = response.values(b"transfer-encoding")
    if te:
        codings = [c.strip().lower() for v in te for c in v.split(b",") if c.strip()]
        if codings and codings[-1] == b"chunked":
            if codings != [b"chunked"]:
                raise error("unsupported_transfer_encoding")
            return "chunked", 0
        return "eof", 0
    length = _content_length(response, error)
    if length is not None:
        return "length", length
    return "eof", 0


def client_response_head(
    response: Response, *, content_length: int | None = None, keep_chunked: bool = True
) -> bytes:
    """Camera's status line and headers, with only connection management changed."""
    drop = {b"connection", b"keep-alive", b"proxy-connection"} | response.connection_tokens()
    if content_length is not None or not keep_chunked:
        drop |= {b"content-length", b"transfer-encoding"}
    lines = [response.start_line]
    lines.extend(n + b": " + v for n, v in response.headers if n.lower() not in drop)
    if content_length is not None:
        lines.append(b"Content-Length: " + str(content_length).encode())
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n"


def simple_response(status: int, reason: str, *, retry_after: int | None = None) -> bytes:
    body = f"{status} {reason}\n".encode()
    lines = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: text/plain",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if retry_after is not None:
        lines.append(f"Retry-After: {retry_after}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


REASONS = {
    400: "Bad Request",
    405: "Method Not Allowed",
    413: "Content Too Large",
    431: "Request Header Fields Too Large",
    501: "Not Implemented",
    503: "Service Unavailable",
}
