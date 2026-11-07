"""One camera's ONVIF shim process: 127.0.0.1:listen_port -> camera_ip:onvif_port.

Each camera runs in its own process (systemd template instance), so a stalled
camera, crash or bug is confined to that camera. Inside the process asyncio
handles long polls without one thread per request, and every phase is bounded:
admission, header/body size, client read time, connect time, total exchange
time and response size.

The process needs no privileges: loop prevention comes from the firewall rule
matching only Protect's uid (this process must run as a different uid), not
from SO_MARK.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pwd
import signal
import socket
import sys
import time
from dataclasses import dataclass, field

from . import __version__, events, httpio, soap
from .config import Camera, Config, ConfigError
from .config import load as load_config

SO_ORIGINAL_DST = 80
EX_CONFIG = 78  # systemd RestartPreventExitStatus: configuration/safety refusal
PULL = "PullMessages"
STATUS_FILE = "status.json"


def original_destination(sock) -> tuple[str, int] | None:
    """Pre-DNAT destination from conntrack (Linux); None if unavailable."""
    if sock is None or not sys.platform.startswith("linux"):
        return None
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    return socket.inet_ntoa(raw[4:8]), int.from_bytes(raw[2:4], "big")


def sd_notify(message: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError:
        pass


class RateLimitedLog:
    """Token bucket so 50 instances cannot flood the NVR's 80 MB journal."""

    def __init__(self, camera_id: str, per_minute: int, clock=time.monotonic, sink=None):
        self.camera_id = camera_id
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.rate = per_minute / 60.0
        self.clock = clock
        self.updated = clock()
        self.suppressed = 0
        self.sink = sink or (lambda line: print(line, flush=True))

    def __call__(self, level: str, event: str, *, force: bool = False, **fields):
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1 and not force:
            self.suppressed += 1
            return
        self.tokens = max(0.0, self.tokens - 1)
        parts = [f"{level} cam={self.camera_id} event={event}"]
        parts.extend(f"{k}={v}" for k, v in fields.items())
        self.sink(" ".join(parts))


@dataclass
class Counters:
    accepted: int = 0
    active: int = 0
    completed: int = 0
    failed: int = 0
    rejected_busy: int = 0
    rejected_invalid: int = 0
    client_timeout: int = 0
    client_gone: int = 0
    redirected: int = 0
    direct: int = 0
    unknown_origin: int = 0
    misrouted: int = 0
    loop_detected: int = 0
    host_mismatch: int = 0
    response_too_large: int = 0
    repairs: dict[str, int] = field(default_factory=dict)
    added: dict[str, int] = field(default_factory=dict)
    operations: dict[str, int] = field(default_factory=dict)


@dataclass
class Upstream:
    last_success_at: float | None = None  # wall clock of last complete camera response
    last_status: int | None = None
    last_error: str | None = None
    last_error_at: float | None = None
    consecutive_failures: int = 0
    consecutive_connect_failures: int = 0
    outage_since: float | None = None
    outages: int = 0
    recoveries: int = 0


@dataclass
class Pulls:
    ok: int = 0
    failed: int = 0
    faults: int = 0
    consecutive_failures: int = 0
    last_ok_at: float | None = None
    last_failure: str | None = None
    notifications: int = 0
    motion_true: int = 0
    motion_false: int = 0
    last_motion_true_at: float | None = None
    last_motion_false_at: float | None = None
    unparsed: int = 0


class CameraShim:
    def __init__(
        self,
        camera: Camera,
        config: Config,
        status_dir: str | None,
        *,
        listen_host: str = "127.0.0.1",
        log: RateLimitedLog | None = None,
        wall=time.time,
        clock=time.monotonic,
        direct_budget: int | None = None,
    ):
        self.camera = camera
        self.config = config
        self.limits = camera.limits
        self.status_dir = status_dir
        self.listen_host = listen_host
        self.wall = wall
        self.clock = clock
        self.log = log or RateLimitedLog(camera.id, config.status.log_lines_per_minute)
        self.counters = Counters()
        self.upstream = Upstream()
        self.pulls = Pulls()
        self.server: asyncio.base_events.Server | None = None
        self.listening = False
        self.bound_port = 0
        self.stopping = False
        self.unsafe_reason: str | None = None
        self.started_at = wall()
        self.direct_active = 0
        # Non-redirected local connections get a small separate budget so they can
        # never starve Protect's redirected traffic (tests override it).
        self.direct_budget = direct_budget or max(1, camera.limits.max_active_requests // 4)
        self._upstream_locals: set[tuple[str, int]] = set()
        self._tasks: set[asyncio.Task] = set()
        self._last_transport: str | None = None
        self._fatal = asyncio.Event()
        self.translator = None
        if camera.mode == "ai_motion" and camera.ai_motion is not None:
            self.translator = events.MotionTranslator(
                camera.ai_motion.off_hold_seconds, camera.ai_motion.max_motion_seconds
            )

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        limit = max(self.limits.max_header_bytes, httpio.MAX_CHUNK_LINE) + 1024
        self.server = await asyncio.start_server(
            self._accept,
            host=self.listen_host,
            port=self.camera.listen_port,
            limit=limit,
            backlog=64,
            reuse_address=True,
        )
        self.bound_port = self.server.sockets[0].getsockname()[1]
        self.listening = True
        self.log(
            "info",
            "listening",
            force=True,
            port=self.port,
            mode=self.camera.mode,
            version=__version__,
        )
        self.write_status()

    @property
    def port(self) -> int:
        return self.bound_port

    async def close(self) -> None:
        """Stop accepting, drain in-flight requests (bounded), then cancel the rest."""
        self.stopping = True
        if self.server is not None:
            self.server.close()
            self.listening = False
        deadline = self.clock() + self.limits.drain_timeout
        while self._tasks and self.clock() < deadline:
            await asyncio.sleep(0.05)
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), 5)
            except TimeoutError:
                self.log("warn", "close_timeout")
        self.write_status()

    # --- request handling ----------------------------------------------------

    def _origin(self, sock) -> str:
        destination = original_destination(sock)
        if destination is None:
            return "unknown" if not sys.platform.startswith("linux") else "direct"
        if destination == self.camera.upstream:
            return "redirected"
        if destination[1] == self.bound_port and destination[0].startswith("127."):
            return "direct"
        return "misrouted"

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        finally:
            self._tasks.discard(task)

    async def _serve(self, reader, writer):
        c = self.counters
        c.accepted += 1
        if self._looped(writer):
            return
        origin = self._origin(writer.get_extra_info("socket"))
        if origin == "misrouted":
            c.misrouted += 1
            self.log("warn", "misrouted_connection")
            writer.transport.abort()
            return
        if origin == "redirected":
            c.redirected += 1
        elif origin == "direct":
            c.direct += 1
        else:
            c.unknown_origin += 1
        direct = origin == "direct"
        if (
            self.stopping
            or c.active >= self.limits.max_active_requests
            or (direct and self.direct_active >= self.direct_budget)
        ):
            c.rejected_busy += 1
            self.log("warn", "busy", active=c.active)
            await self._finish(
                writer, httpio.simple_response(503, "Service Unavailable", retry_after=1)
            )
            return
        c.active += 1
        self.direct_active += direct
        try:
            await self._exchange(reader, writer)
        finally:
            c.active -= 1
            self.direct_active -= direct

    def _looped(self, writer) -> bool:
        """True (and fail open) if this connection is one of our own upstream sockets.

        Checked at accept and again after the request head, because the accept
        callback can run before open_connection() returns and records the address.
        """
        peer = writer.get_extra_info("peername")
        if not peer or (peer[0], peer[1]) not in self._upstream_locals:
            return False
        self.counters.loop_detected += 1
        self.unsafe_reason = "loop_detected"
        self.log("error", "loop_detected", force=True)
        writer.transport.abort()
        self._fatal.set()
        return True

    async def _finish(self, writer, data: bytes = b"") -> None:
        try:
            if data:
                writer.write(data)
                await asyncio.wait_for(writer.drain(), 5)
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 5)
        except (OSError, TimeoutError, asyncio.CancelledError):
            writer.transport.abort()

    async def _exchange(self, reader, writer):
        c = self.counters
        try:
            async with asyncio.timeout(self.limits.client_timeout):
                raw = await httpio.read_head(reader, self.limits.max_header_bytes, client=True)
                request = httpio.parse_request(raw)
                if (
                    b"100-continue" in (request.first(b"expect") or b"").lower()
                    and request.version == b"HTTP/1.1"
                ):
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                    await writer.drain()
                body = await httpio.read_request_body(
                    reader, request, self.limits.max_request_bytes
                )
        except httpio.HttpError as exc:
            c.rejected_invalid += 1
            self.log("warn", "client_rejected", reason=exc.category)
            reason = httpio.REASONS.get(exc.status, "Bad Request")
            await self._finish(writer, httpio.simple_response(exc.status, reason))
            return
        except httpio.ClientGone:
            c.client_gone += 1
            await self._finish(writer)
            return
        except TimeoutError:
            c.client_timeout += 1
            await self._finish(writer)
            return
        if self._looped(writer):
            return
        result = self._repair(request, body)
        c.repairs[result.outcome] = c.repairs.get(result.outcome, 0) + 1
        for name in result.added:
            c.added[name] = c.added.get(name, 0) + 1
        if result.operation:
            c.operations[result.operation] = c.operations.get(result.operation, 0) + 1
        if result.outcome.startswith("skipped_") and result.operation in (
            "PullMessages",
            "Renew",
            "Unsubscribe",
            "SetSynchronizationPoint",
        ):
            self.log("warn", "repair_skipped", op=result.operation, reason=result.outcome)
        await self._forward(request, result, writer)

    def _host(self, request: httpio.Request) -> str:
        ip, port = self.camera.upstream
        allowed = {ip, f"{ip}:{port}"}
        value = (request.first(b"host") or b"").decode("latin-1").strip().lower()
        if value in allowed:
            return value
        self.counters.host_mismatch += 1
        return f"{ip}:{port}"

    def _repair(self, request: httpio.Request, body: bytes) -> soap.RepairResult:
        if request.method != b"POST" or not body:
            return soap.RepairResult(body, "no_body")
        blocker = httpio.integrity_blocker(request)
        if blocker:
            operation = None
            try:
                env = soap.parse_envelope(body)
                operation = env.operation[1] if env.operation else None
            except soap.UnsafeXML:
                pass
            return soap.RepairResult(body, blocker, operation)
        to_url = "http://" + self._host(request) + request.target.decode("ascii")
        return soap.repair_request(
            body,
            to_url=to_url,
            wanted=self.camera.wsa_repair,
            must_understand=self.camera.wsa_must_understand,
        )

    async def _forward(self, request, result: soap.RepairResult, writer):
        is_pull = result.operation == PULL
        ip, port = self.camera.upstream
        limit = max(self.limits.max_header_bytes, httpio.MAX_CHUNK_LINE) + 1024
        try:
            async with asyncio.timeout(self.limits.connect_timeout):
                up_reader, up_writer = await asyncio.open_connection(ip, port, limit=limit)
        except (OSError, TimeoutError) as exc:
            category = "connect_timeout" if isinstance(exc, TimeoutError) else "connect_failed"
            self._upstream_failed(category, connect=True, pull=is_pull)
            writer.transport.abort()  # like an unreachable camera: no synthesized HTTP
            return
        local = up_writer.get_extra_info("sockname")
        local = (local[0], local[1]) if local else None
        if local:
            self._upstream_locals.add(local)
        sent_to_client = False
        try:
            async with asyncio.timeout(self.limits.response_timeout):
                up_writer.write(httpio.upstream_request(request, result.body))
                await up_writer.drain()
                while True:
                    raw = await httpio.read_head(
                        up_reader, self.limits.max_header_bytes, client=False
                    )
                    response = httpio.parse_response(raw)
                    if response.status == 101:
                        raise httpio.UpstreamProtocolError("upgrade_refused")
                    if response.status >= 200:
                        break
                kind, length = httpio.response_framing(request.method, response)
                translate = is_pull and self.translator is not None and response.status == 200
                capture = is_pull and response.status == 200
                if translate:
                    payload = await self._read_payload(up_reader, kind, length)
                    payload = self.translator.translate(request.target.decode("ascii"), payload)
                    for transition in self.translator.transitions:
                        name, _, reason = transition.partition(":")
                        self.log("info", "ai_" + name, reason=reason, force=True)
                    self.translator.transitions.clear()
                    head = httpio.client_response_head(response, content_length=len(payload))
                    writer.write(head + payload)
                    sent_to_client = True
                    await writer.drain()
                else:
                    writer.write(httpio.client_response_head(response))
                    sent_to_client = True
                    payload = await self._relay(up_reader, writer, kind, length, capture)
        except TimeoutError:
            self._upstream_failed("response_timeout", pull=is_pull)
            await self._abort_or_close(writer, sent_to_client)
            return
        except httpio.UpstreamProtocolError as exc:
            self._upstream_failed(exc.category, pull=is_pull)
            await self._abort_or_close(writer, sent_to_client)
            return
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            category = "relay_interrupted" if sent_to_client else "upstream_reset"
            self._upstream_failed(category, pull=is_pull)
            await self._abort_or_close(writer, sent_to_client)
            return
        finally:
            if local:
                self._upstream_locals.discard(local)
            up_writer.transport.abort()
        self._upstream_succeeded(response.status, is_pull, payload)
        await self._finish(writer)

    async def _abort_or_close(self, writer, sent: bool) -> None:
        # Before any byte was sent, mirror the camera (it closed or failed); after
        # a partial relay, abort so the client cannot mistake it for a full response.
        if sent:
            writer.transport.abort()
        else:
            await self._finish(writer)

    async def _read_payload(self, reader, kind: str, length: int) -> bytes:
        cap = self.limits.max_response_bytes
        if kind == "none":
            return b""
        if kind == "length":
            if length > cap:
                self.counters.response_too_large += 1
                raise httpio.UpstreamProtocolError("response_too_large")
            return await reader.readexactly(length)
        if kind == "chunked":
            return await self._chunked(reader, cap)
        data = bytearray()
        while chunk := await reader.read(65536):
            data += chunk
            if len(data) > cap:
                self.counters.response_too_large += 1
                raise httpio.UpstreamProtocolError("response_too_large")
        return bytes(data)

    async def _chunked(self, reader, cap: int, writer=None) -> bytes:
        try:
            return await httpio.read_chunked(
                reader, cap, writer=writer, error=httpio.UpstreamProtocolError
            )
        except httpio.UpstreamProtocolError as exc:
            if exc.category == "too_large":
                self.counters.response_too_large += 1
                raise httpio.UpstreamProtocolError("response_too_large") from None
            raise

    async def _relay(self, reader, writer, kind: str, length: int, capture: bool) -> bytes | None:
        """Copy the camera body to Protect unchanged; keep a bounded copy if observing."""
        cap = self.limits.max_response_bytes
        if kind == "none":
            await writer.drain()
            return b"" if capture else None
        if kind == "chunked":
            payload = await self._chunked(reader, cap, writer)
            return payload if capture else None
        if kind == "length" and length > cap:
            self.counters.response_too_large += 1
            raise httpio.UpstreamProtocolError("response_too_large")
        kept = bytearray() if capture else None
        total = 0
        remaining = length if kind == "length" else None
        while remaining is None or remaining > 0:
            size = 65536 if remaining is None else min(65536, remaining)
            chunk = await reader.read(size)
            if not chunk:
                if remaining:
                    raise httpio.UpstreamProtocolError("truncated_body")
                break
            total += len(chunk)
            if total > cap:
                self.counters.response_too_large += 1
                raise httpio.UpstreamProtocolError("response_too_large")
            if remaining is not None:
                remaining -= len(chunk)
            writer.write(chunk)
            await writer.drain()
            if kept is not None:
                kept += chunk
        return bytes(kept) if kept is not None else None

    # --- health accounting -----------------------------------------------------

    def _upstream_failed(self, category: str, *, connect: bool = False, pull: bool = False):
        c, u, now = self.counters, self.upstream, self.wall()
        c.failed += 1
        u.last_error = category
        u.last_error_at = now
        u.consecutive_failures += 1
        if connect:
            u.consecutive_connect_failures += 1
            if u.consecutive_connect_failures >= 3 and u.outage_since is None:
                u.outage_since = now
                u.outages += 1
                self.log("error", "camera_outage", reason=category, force=True)
        if pull:
            p = self.pulls
            p.failed += 1
            p.consecutive_failures += 1
            p.last_failure = category
        self.log("warn", "upstream_failed", reason=category, pull=int(pull))

    def _upstream_succeeded(self, status: int, pull: bool, payload: bytes | None):
        c, u, now = self.counters, self.upstream, self.wall()
        c.completed += 1
        u.last_status = status
        u.last_success_at = now
        u.consecutive_connect_failures = 0
        if u.outage_since is not None:
            u.outage_since = None
            u.recoveries += 1
            self.log("info", "camera_recovered", force=True)
        if status >= 400:
            u.consecutive_failures += 1
            u.last_error = f"http_{status}"
            u.last_error_at = now
        else:
            u.consecutive_failures = 0
        if not pull:
            return
        p = self.pulls
        observation = events.observe(payload) if payload is not None and status == 200 else None
        if observation is not None and observation.unparsed:
            p.unparsed += 1
        if status == 200 and observation is not None and observation.pull_ok:
            p.ok += 1
            p.consecutive_failures = 0
            p.last_ok_at = now
            p.notifications += observation.notifications
            if observation.motion_true:
                p.motion_true += observation.motion_true
                p.last_motion_true_at = now
                self.log("info", "motion_notification", value="true")
            if observation.motion_false:
                p.motion_false += observation.motion_false
                p.last_motion_false_at = now
                self.log("info", "motion_notification", value="false")
        else:
            p.failed += 1
            p.consecutive_failures += 1
            if observation is not None and observation.fault or status >= 400:
                p.faults += 1
                p.last_failure = f"http_{status}"
            else:
                p.last_failure = "unexpected_response"

    def transport_state(self) -> str:
        p, u = self.pulls, self.upstream
        now = self.wall()
        if u.outage_since is not None:
            return "outage"
        if p.ok == 0 and p.failed == 0:
            return "unobserved"
        fresh = p.last_ok_at is not None and now - p.last_ok_at <= 2 * self.limits.response_timeout
        if fresh and p.consecutive_failures < 3:
            return "healthy"
        if p.consecutive_failures >= 3 and not fresh:
            return "failing"
        return "degraded"

    def snapshot(self) -> dict:
        c = self.counters
        state = self.transport_state()
        return {
            "camera": self.camera.id,
            "version": __version__,
            "pid": os.getpid(),
            "mode": self.camera.mode,
            "listen_port": self.camera.listen_port,
            "started_at": round(self.started_at, 3),
            "heartbeat_at": round(self.wall(), 3),
            "process": {
                "listening": self.listening,
                "stopping": self.stopping,
                "serviceable": self.listening and not self.stopping and self.unsafe_reason is None,
                "unsafe_reason": self.unsafe_reason,
            },
            "requests": {k: v for k, v in c.__dict__.items() if not isinstance(v, dict)},
            "repairs": dict(c.repairs),
            "wsa_added": dict(c.added),
            "operations": dict(c.operations),
            "upstream": dict(self.upstream.__dict__),
            "event_transport": state,
            "pulls": dict(self.pulls.__dict__),
            "ai_motion": self.translator.snapshot() if self.translator else None,
            "detection_verified": False,
            "recording": "not_assessed",
            "log_suppressed": self.log.suppressed,
        }

    def write_status(self) -> None:
        if not self.status_dir:
            return
        path = os.path.join(self.status_dir, STATUS_FILE)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as out:
                json.dump(self.snapshot(), out, sort_keys=True)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except OSError as exc:
            self.log("warn", "status_write_failed", error=type(exc).__name__)

    async def heartbeat(self) -> None:
        interval = self.config.status.heartbeat_seconds
        summary_every = self.config.status.summary_log_seconds
        last_summary = self.clock()
        while True:
            self.write_status()
            sd_notify("WATCHDOG=1")
            state = self.transport_state()
            if state != self._last_transport:
                self.log("info", "transport_state", state=state, force=True)
                self._last_transport = state
            if self.clock() - last_summary >= summary_every:
                last_summary = self.clock()
                c, p = self.counters, self.pulls
                self.log(
                    "info",
                    "summary",
                    force=True,
                    transport=state,
                    requests=c.accepted,
                    pulls_ok=p.ok,
                    pulls_failed=p.failed,
                    repaired=c.repairs.get("repaired", 0),
                    motion_true=p.motion_true,
                    suppressed=self.log.suppressed,
                )
            await asyncio.sleep(interval)


def _refuse(message: str) -> int:
    print(f"error {message}", file=sys.stderr, flush=True)
    return EX_CONFIG


async def run(shim: CameraShim) -> int:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await shim.start()
    sd_notify(f"READY=1\nSTATUS=listening on 127.0.0.1:{shim.camera.listen_port}")
    beat = asyncio.create_task(shim.heartbeat())
    fatal = asyncio.create_task(shim._fatal.wait())
    stopper = asyncio.create_task(stop.wait())
    await asyncio.wait({fatal, stopper}, return_when=asyncio.FIRST_COMPLETED)
    sd_notify("STOPPING=1")
    await shim.close()
    beat.cancel()
    fatal.cancel()
    stopper.cancel()
    await asyncio.gather(beat, fatal, stopper, return_exceptions=True)
    if shim.unsafe_reason:
        return _refuse(
            f"cam={shim.camera.id} unsafe={shim.unsafe_reason}; interception must stay off"
        )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NVR-local ONVIF shim (one camera)")
    parser.add_argument("--config", required=True)
    parser.add_argument("--camera", required=True)
    parser.add_argument("--status-dir")
    parser.add_argument("--allow-root", action="store_true", help="testing only")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        camera = config.camera(args.camera)
    except (ConfigError, OSError) as exc:
        return _refuse(f"invalid configuration: {exc}")
    if not camera.enabled:
        return _refuse(f"cam={camera.id} is disabled in the inventory")
    try:
        client_uid = pwd.getpwnam(config.client_user).pw_uid
    except KeyError:
        client_uid = None
    if client_uid is not None and os.geteuid() == client_uid:
        return _refuse("running as the intercepted client uid would loop; use another user")
    if os.geteuid() == 0 and not args.allow_root:
        return _refuse("refusing to run as root; the unit uses DynamicUser")
    if args.status_dir:
        os.makedirs(args.status_dir, mode=0o755, exist_ok=True)
    shim = CameraShim(camera, config, args.status_dir)
    try:
        return asyncio.run(run(shim))
    except OSError as exc:
        return _refuse(f"cam={camera.id} cannot listen: {type(exc).__name__} errno={exc.errno}")


if __name__ == "__main__":
    sys.exit(main())
