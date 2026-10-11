# External multi-camera ONVIF proxy (development mode)

This mode runs on a separate Linux Docker VM, not on the UNVR. It reuses Casey
Clifton's MIT-licensed event operation mappings from `onvif_shim.py`; the original
single-camera/NVR mode and its attribution remain unchanged. Do not run
`install.sh` or `rule.sh` for external mode.

**Not production-approved or hardware-accepted.** The local integration cameras
are mocks. Same-IP/different-port Protect acceptance, changing an existing camera's
ONVIF endpoint, parallel adoption, camera subscription survival, and uninterrupted
recording during proxy outages are all live-test gates. No deployment or adoption
change is authorized by this development PR.

## Architecture and dependencies

Protect -> VM:18001 -> camera A:8000
Protect -> VM:18002 -> camera B:8000 (through 18050 in the example)
Protect -> real camera:554 for RTSP, and real camera HTTP port for snapshots

One service creates an independent listener and HTTP connection pool for each
mapping. The listener, never the Host header, selects a fixed upstream literal IP
and port. No hostname DNS rebinding, redirects, environment HTTP proxies or
cookie storage. No privileges, SO_MARK, iptables, Docker socket, AI synthesis,
thumbnail fetching/caching, camera identity substitution or ONVIF discovery server.
Manual ONVIF endpoint entry is required; UDP WS-Discovery is not proxied.

Python >=3.12 and aiohttp provide maintained HTTP framing, duplicate headers,
async long polls and connection pooling without one thread per camera. yarl and
multidict (aiohttp dependencies) preserve encoded request targets and repeated
headers. `uv.lock` pins the resolved dependency graph; Docker and CI use frozen
installs. Expat from Python parses namespaces with DTD/external entities forbidden.
Four bounded XML worker threads keep parsing off the shared event loop. XML edits
are byte-range splices, not tree serialization: unchanged WS-Security tokens,
reference parameters and QName namespace declarations remain byte-for-byte intact.

Only the upstream's four mappings (PullMessages, SetSynchronizationPoint, Renew,
Unsubscribe) receive missing To/Action headers. Declaring a namespace or including
ReplyTo does not prove To/Action exist. Existing Action is preserved; existing To
is translated to the actual upstream HTTP request target for all SOAP operations.
Both common WS-Addressing namespaces and SOAP 1.1/1.2 are supported. No new
MessageID/ReplyTo is invented; existing ones pass through.

Returned GetServices service XAddr, GetCapabilities recognized service XAddr, and
ONVIF/WS-Notification SubscriptionReference/Address values are rewritten to the
mapping's public origin. Paths, encoded query and subscription IDs remain intact.
Direct RTSP and snapshot Uri values, identities, event data and reference parameters
are not rewritten. Returned control URLs must match the configured upstream origin;
foreign hosts, other ports, credentials, fragments and unsupported schemes fail
closed with 502. A camera advertising a different ONVIF service port needs an
evidenced design extension, not a relaxed arbitrary URL router.

Routing is stateless: an old proxy subscription path/query still reaches its camera
after proxy restart. This does **not** recreate an expired camera subscription.
Renew/Unsubscribe and new CreatePullPointSubscription requests are forwarded.
Clients must handle camera expiry/reboot and re-subscribe. No automatic retries of
SOAP POST (which could duplicate subscription creation or other mutations).

## Config and safe startup (only after separate deployment authorization)

1. Choose an isolated camera-facing VM IP and firewall policy first. Copy
   `config.example.json` to ignored `config.json`. The example has **50 RFC 5737
   documentation-only camera mappings**, not a real TLC inventory. Replace each
   upstream/public IP with the approved camera/VM address, remove unused mappings,
   and retain unique IDs and endpoints. Do not put credentials in the config.
2. `upstream` and `public` are HTTP origins with literal IPs, explicit ports and no
   trailing slash/path. `public` is the endpoint visible to Protect; it need not
   equal the container bind address. `listen_host` is a container-local IP.
   Bridged Docker example binds `0.0.0.0`; all ports are unprivileged (>1023).
3. Validate without connecting to any camera:
   `uv sync --frozen`
   `uv run python external_proxy.py --config config.json --validate`
4. Build: `docker build -t external-onvif-proxy:local .`
   Container validation:
   `docker run --rm -v "$PWD/config.json:/config/config.json:ro" external-onvif-proxy:local --config /config/config.json --validate`
5. Set `PROXY_BIND_IP` to the camera-facing VM IP. Review the resolved configuration:
   `PROXY_BIND_IP=VM_IP docker compose -f compose.example.yaml config`
   Then, **only with approval**:
   `PROXY_BIND_IP=VM_IP docker compose -f compose.example.yaml up -d --build`
   The container runs as UID/GID 65532, read-only, all capabilities dropped, no-new-
   privileges, bounded memory/CPU/PIDs/log rotation. Config must be readable by that UID.
   No host networking or Docker socket is required for this deployment.
6. Health: `curl -fsS http://127.0.0.1:19000/health` on the VM. In bridged mode the
   config health bind must be `0.0.0.0` so Docker's loopback-only published port works.
   If overriding the image config path, set `HEALTH_CONFIG` to the same path.

Firewall only the UNVR to VM ONVIF listener ports; VM to approved cameras:8000;
UNVR to real cameras for RTSP/snapshots. Keep management health local. Account for
Docker published-port firewall behavior (published ports may bypass uncomplicated
host firewall rules); verify policy from an unauthorized VLAN. ONVIF carries
credentials/tokens over HTTP. The proxy is not an authentication service, and
passwordless cameras make strict source restrictions essential. Never expose it to
the internet or broad LAN. An allowed client can send native camera operations;
this is not a read-only ONVIF filter.

### Multi-IP alternative if Protect deduplicates by IP

Same-IP/different-port acceptance is **UNVERIFIED**. If a one-camera canary proves
Protect cannot distinguish ports, provision 50 VM IP aliases (outside Docker,
with network-owner approval) and publish each VM alias's port 8000 to its unique
container port, e.g. `VM_ALIAS_A:8000:18001/tcp`. Set that mapping's public origin
`http://VM_ALIAS_A:8000`; retain the container listener 18001 and real upstream.
No container privilege is needed. Distinct public IPs preserve per-camera routing;
this alternative also requires physical Protect testing. Do not use arbitrary Host
headers or an external reverse proxy to select cameras.

## Resource limits, auth and failure behavior

Defaults: 1 MiB request/response, 8 active requests per camera, 512 global requests,
100 s total upstream exchange, 5 s connect, 10 s client body read/XML work,
110 s graceful shutdown. Set long-poll Timeout below the upstream exchange limit
with margin; timeout produces 504, transport failure 502, busy admission 503 with
Retry-After, invalid request XML 400, oversized request 413. No unbounded request
queue. XML also limits depth to 64 and element count to 20,000. Capacity is bounded
but large limit increases require memory/load testing on the actual VM; the mock
suite is not a production sizing benchmark. Separate pools isolate slow/broken
camera I/O; XML threads and CPU remain shared finite resources.

HTTP Basic/Digest auth (qop=auth), SOAPAction/content type, multiple authentication
challenges and WS-Security UsernameToken digests pass through; no credentials are
stored or independently authenticated. HTTP body-integrity digests/auth-int and
XML signatures cannot survive arbitrary edits: modified signed XML or modified
integrity-protected bodies are rejected rather than silently invalidated. HTTP
message-signed requests and responses are unsupported because Host/framing changes. Signed
no-edit XML can pass. UTF-8 XML only; no compressed SOAP, MTOM, web-UI proxy or
firmware-upload proxy. Response buffering is bounded; no RTSP passes through it.

SIGTERM stops listeners and drains pending requests before session/worker cleanup;
Compose allows 120 s. Pending requests may be canceled at the configured drain
limit. This does not guarantee recording continuity in Protect.

## Operations and honest health

`docker compose -f compose.example.yaml logs --tail=100 onvif-proxy`
`curl -fsS http://127.0.0.1:19000/health`

Logs contain only configured camera IDs, numerical status/elapsed time and coarse
error codes. No bodies, URLs, query tokens, Authorization, camera credentials or
exception strings. Do not enable aiohttp/debug/access logs or packet capture without
a separate secure evidence-handling plan.

Health shows per-camera active/requests/responses/failures/repaired counts, last
accepted HTTP status, response age and transport error. `unobserved` means no
response yet; `responding` means recent HTTP transport; `degraded` means a last
error or stale response. A 401/500 or SOAP fault remains native, not synthesized.
HTTP 200 may still contain a SOAP fault, an empty poll or a non-motion event.
**detection_verified is always false**: a health endpoint cannot certify a physical
motion detection. Docker's healthcheck is process/HTTP liveness only; it does not
restart the container for a single disconnected camera. Counters reset on process
restart. Monitor per-camera ages/errors externally.

On transport errors, inspect camera reachability/allowlisted origins and client
long-poll settings without logging secrets. Preserve continuous recording; never
switch to detection-only recording merely because this proxy starts responding.

## Rollback

Before any adoption/endpoint change, record/export existing camera endpoint,
identity, recording/retention settings and playback baseline through approved UI.
Do not delete/re-adopt an existing production camera just to test this proxy.

If separately authorized endpoint migration fails, restore the documented original
real camera ONVIF endpoint in Protect using the proven UI procedure; verify RTSP
live view, recording timeline and historical playback. Then stop the external
service: `docker compose -f compose.example.yaml down`. No NVR uninstall,
iptables cleanup, camera reset or credential change is needed. **Stopping the
proxy does not automatically restore Protect's ONVIF endpoint**, unlike upstream
NVR DNAT failover. If endpoint editing is unsupported, stop and obtain an approved
migration/rollback plan before adoption experiments. VM/proxy failure recording
behavior is unknown until measured.

## Live-test acceptance checklist (separate approval required)

- [ ] Secure approved VM/firewall; prove UNVR reachability and unauthorized-source denial.
- [ ] Packet-confirm actual Protect To/Action behavior with sanitized evidence; current
      TLC header-missing diagnosis is not packet-confirmed.
- [ ] One non-destructive canary: verify same VM IP plus distinct ports accepted and
      camera identity/serial/MAC unaffected. If not, validate multi-IP alternative.
- [ ] Prove supported existing-camera endpoint edit or explicitly approved parallel
      adoption, and prove restoration without deleting production camera/history.
- [ ] GetServices/GetCapabilities and CreatePullPointSubscription point at correct
      proxy; To reaches real camera; Renew, Unsubscribe, reconnect and expiry work.
- [ ] Controlled walk produces real motion start/stop ONVIF notifications **and**
      corresponding Protect events, not merely empty HTTP 200 polls.
- [ ] RTSP/snapshot URLs still point directly to camera; continuous live recording
      and old playback remain intact before/during/after proxy restart and outage.
- [ ] Confirm camera reboot/re-subscription, slow/disconnected-camera isolation,
      auth failure behavior and per-camera transport monitoring on actual VM.
- [ ] Soak/load with 50 real cameras and measured CPU/memory/latency; stage rollout
      only after explicit approval. No claim of production readiness before this.

## Development verification

`uv sync --frozen --python 3.12`
`uv run pytest -q`
`uv run ruff check external_proxy.py container_health.py tests`
`uv run ruff format --check external_proxy.py container_health.py tests`
`uv run python external_proxy.py --config config.example.json --validate`

Local tests start actual proxy listeners and 50 local mock camera HTTP servers.
Linux Docker runtime test: build `external-onvif-proxy:test`, then
`uv run python -m tests.container_smoke`. The latter uses Linux host networking
**only for loopback mock integration**, not the deployment recipe. CI runs Python
3.12/3.13, Docker build/non-root runtime/health/SIGTERM, and Compose validation.
These tests certify software behavior with mocks, not camera/Protect compatibility.
