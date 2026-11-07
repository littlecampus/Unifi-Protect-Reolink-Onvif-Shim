"""Protect stand-in: one request to camera:port, run under a chosen uid via setpriv."""

import json
import socket
import sys
import time

sys.path.insert(0, "/src")
from tests.support import build_request, pull_body  # noqa: E402

host, port, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3]
hold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
result = {"uid": __import__("os").getuid(), "target": f"{host}:{port}", "kind": kind}
started = time.monotonic()
try:
    sock = socket.create_connection((host, port), timeout=15)
    result["peer_seen_by_client"] = "%s:%d" % sock.getpeername()
    if kind == "pull":
        sock.sendall(build_request(pull_body(timeout=f"PT{hold}S"), host=f"{host}:{port}"))
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    result["status_line"] = data.split(b"\r\n", 1)[0].decode() if data else None
    result["bytes"] = len(data)
except OSError as exc:
    result["error"] = type(exc).__name__
result["elapsed"] = round(time.monotonic() - started, 2)
print(json.dumps(result))
