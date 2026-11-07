"""Mock Reolink camera for the kernel test (runs inside the camera network namespace).

ONVIF on 8000 behaves like Parking East (PullMessages without wsa:To -> connection
closed). 554 stands in for RTSP and 80 for the camera web/snapshot port; both only
record that a connection arrived, proving whether the shim was (not) in the path.
"""

import asyncio
import json
import sys

sys.path.insert(0, "/src")
from tests.support import MockCamera  # noqa: E402

LOG = "/tmp/camera.jsonl"


def record(**fields):
    with open(LOG, "a") as out:
        out.write(json.dumps(fields) + "\n")


class LoggingCamera(MockCamera):
    async def _serve(self, reader, writer):
        peer = writer.get_extra_info("peername")
        before = len(self.received)
        try:
            await super()._serve(reader, writer)
        finally:
            got = self.received[before:]
            record(
                port=8000,
                peer=peer[0],
                has_to=bool(got and b"<wsa:To" in got[-1].body),
                had_request=bool(got),
            )


async def banner(port, text):
    async def handle(reader, writer):
        record(port=port, peer=writer.get_extra_info("peername")[0])
        writer.write(text)
        await writer.drain()
        writer.close()

    await asyncio.start_server(handle, "10.99.0.13", port)


async def main():
    camera = LoggingCamera(host="10.99.0.13", port=8000, initial=[])
    await camera.start()
    await banner(554, b"RTSP/1.0 200 OK\r\nServer: mock-rtsp\r\n\r\n")
    await banner(80, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nweb!")
    print("camera ready", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
