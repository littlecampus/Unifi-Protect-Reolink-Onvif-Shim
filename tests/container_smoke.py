"""Linux Docker smoke: real container -> LOCAL MOCK ONVIF, never real cameras."""

import asyncio
import json
import os
import subprocess
import tempfile
import time
import uuid

import aiohttp
from aiohttp import web

from tests.test_external_proxy import elements, envelope, free_ports


async def docker(*args):
    def call():
        return subprocess.run(
            ["docker", *args], check=True, text=True, capture_output=True
        ).stdout.strip()

    return await asyncio.to_thread(call)


async def main():
    ports = free_ports(3)
    upstream = f"http://127.0.0.1:{ports[0]}"
    public = f"http://127.0.0.1:{ports[1]}"

    async def camera(request):
        body = await request.read()
        assert elements(body, "To")[0].text == upstream + request.raw_path
        assert elements(body, "Action")
        assert request.headers["Authorization"] == "Basic YWRtaW46"
        return web.Response(
            body=envelope(
                f"<e:CreatePullPointSubscriptionResponse><e:SubscriptionReference>"
                f"<w:Address>{upstream}/sub?sid=42</w:Address></e:SubscriptionReference>"
                "</e:CreatePullPointSubscriptionResponse>"
            ),
            content_type="application/soap+xml",
        )

    app = web.Application()
    app.router.add_post("/{tail:.*}", camera)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", ports[0]).start()
    name = "onvif-smoke-" + uuid.uuid4().hex[:12]
    # mkstemp uses the configured TMPDIR (CI sets it to the runner temp dir).
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as source:
            json.dump(
                {
                    "health_port": ports[2],
                    "cameras": [
                        {
                            "id": "mock",
                            "listen_host": "127.0.0.1",
                            "listen_port": ports[1],
                            "upstream": upstream,
                            "public": public,
                        }
                    ],
                },
                source,
            )
        os.chmod(path, 0o644)
        await docker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "host",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,source={path},target=/config/config.json,readonly",
            "external-onvif-proxy:test",
        )
        async with aiohttp.ClientSession() as client:
            deadline = time.monotonic() + 20
            while True:
                try:
                    async with client.get(f"http://127.0.0.1:{ports[2]}/health") as response:
                        assert response.status == 200
                        assert (await response.json())["cameras"]["mock"][
                            "transport"
                        ] == "unobserved"
                        break
                except aiohttp.ClientError:
                    if time.monotonic() > deadline:
                        raise
                    await asyncio.sleep(0.2)
            assert await docker("exec", name, "id", "-u") == "65532"
            await docker("exec", name, "/app/.venv/bin/python", "/app/container_health.py")
            async with client.post(
                public + "/sub?sid=42", data=envelope(), headers={"Authorization": "Basic YWRtaW46"}
            ) as response:
                assert response.status == 200
                assert (public + "/sub?sid=42").encode() in await response.read()
        await docker("stop", "--time", "120", name)
        assert await docker("inspect", "--format", "{{.State.ExitCode}}", name) == "0"
        print(
            "PASS: non-root/read-only/cap-drop container; "
            "header repair, URL rewrite, health, SIGTERM"
        )
    finally:
        try:
            await docker("rm", "-f", name)
        finally:
            os.unlink(path)
            await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
