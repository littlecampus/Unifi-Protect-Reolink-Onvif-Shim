"""Container liveness only; per-camera health and detections need separate monitoring."""

import json
import os
import urllib.request

config_path = os.environ.get("HEALTH_CONFIG", "/config/config.json")
with open(config_path) as source:
    config = json.load(source)
host = config.get("health_host", "127.0.0.1")
if host == "0.0.0.0":
    host = "127.0.0.1"
elif host == "::":
    host = "::1"
if ":" in host:
    host = f"[{host}]"
url = f"http://{host}:{config.get('health_port', 19000)}/health"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(url, timeout=3) as response:
    assert json.load(response)["service"] == "running"
