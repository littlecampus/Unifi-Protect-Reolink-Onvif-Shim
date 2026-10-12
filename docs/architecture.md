# Architecture, security and test evidence

Companion to the [README](../README.md). Site-specific findings and the TLC pilot plan
are in [tlc-pilot.md](tlc-pilot.md).

Contents: [Architecture](#architecture) · [WS-Addressing repair](#ws-addressing-repair) ·
[Security](#security-and-privileges) · [Failure behavior](#failure-behavior-and-fail-open) ·
[AI mode](#ai-motion-mode-opt-in) · [Capacity](#capacity-estimates-vs-measurements) ·
[Tests](#tests-and-results) · [Risks](#unverified-behavior-and-remaining-risks)

## Changes from the single-camera v1

| Area | v1 (`onvif_shim.py` single camera) | v2 (this version) | Why |
| --- | --- | --- | --- |
| Cameras | one `SHIM_CAM_HOST` in `shim.conf` | any number, validated `cameras.json` | multi-camera; reject ambiguous mappings |
| Process model | one root process, unbounded threads | one systemd instance per camera, bounded asyncio | isolation: one stalled/crashed camera cannot affect others |
| Loop prevention | `SO_MARK` on upstream sockets | redirect only Protect's uid (`-m owner`) | no `CAP_NET_ADMIN` in the request path; narrower scope |
| Firewall | DNAT rules appended to `OUTPUT`, `rule.sh` timer | one tagged `ONVIF_SHIM` chain, atomic restore, conntrack anchor, health gate | scoped install/uninstall; verified fail-open |
| Header repair | regex; skipped when the WS-A namespace appears anywhere | namespace-aware, per element, byte splice, fail-transparent | correctness; WS-Security preserved |
| Defaults | AI motion on, snapshots on (port 80 + stored password) | header-only; AI opt-in; snapshots removed | preserve genuine motion; non-AI cameras; no credentials |
| Lifecycle | `install.sh` / `install.sh uninstall` | `install.sh`, `uninstall.sh` + `shimctl.py`: dry-run, preflight, status, enable/disable, bypass, release rollback | operability at fleet scale |

The v1 header fix and `Action` URIs, the loopback-DNAT approach and the AI-motion
idea come from Casey Clifton's original design.

## Repository layout

| Path | Purpose |
| --- | --- |
| `onvif_shim.py` | one camera's service (systemd `onvif-shim@<id>`) |
| `shimctl.py`, `install.sh`, `uninstall.sh` | control CLI (root) and its non-interactive install and uninstall wrappers |
| `shimlib/protect.py`, `shimlib/cameras.py` | read-only Protect camera list; `cameras`, `add`, `remove`, `setup` |
| `shimlib/oui.py`, `tools/gen_oui.py` | camera-brand MAC prefixes (188 IEEE assignments, 22 brands, exact organization names, TP-Link excluded) and their generator (development only) |
| `shimlib/` | config, SOAP repair, HTTP framing, events/AI, shim, firewall, units, control, release builder |
| `cameras.example.json`, `examples/` | inventories |
| `tests/` | mocks and fakes (pytest); `tests/kernel/` real netfilter; `tests/systemd/` real systemd |
| `docs/evidence/` | recorded output of the kernel, systemd and scale runs |

## Architecture

Example for one camera (Parking East):

```
Protect (uid 996) ──TCP──► 10.48.20.13:8000
        │  nat OUTPUT: -m owner --uid-owner 996 -> ONVIF_SHIM
        │  ONVIF_SHIM: -d 10.48.20.13/32 --dport 8000 -> DNAT 127.0.0.1:18113
        ▼
127.0.0.1:18113  onvif-shim@parking_east  (DynamicUser, no capabilities)
        │  adds missing wsa:To / wsa:Action, forwards everything else byte-for-byte
        ▼
camera 10.48.20.13:8000   (shim's own connection: uid != 996, so not redirected)

RTSP (ms, uid 982 -> :554), snapshots (:80), RTMP/HLS repeater: never touched.
```

* **One process per camera** (`onvif-shim@<id>.service`, systemd template).
  A crash, hang, stalled camera or bug is confined to one camera. Inside each
  process, asyncio serves concurrent long polls without a thread per request.
* **One inventory** (`/data/onvif-shim/cameras.json`), validated strictly.
* **One scoped firewall chain** `ONVIF_SHIM` in the nat table plus one tagged
  jump from `nat OUTPUT`. Nothing else is flushed or rewritten. All changes are a
  single atomic `iptables-restore --noflush` transaction, read back and verified.
* **Loop prevention by uid, not marks.** The jump matches only Protect's uid
  (resolved by name from `client_user`, default `unifi-protect`). The shim runs
  as a systemd DynamicUser, so its upstream connections never match. The shim
  also refuses to start as uid 996 or root, and detects a loop at runtime (a
  connection from one of its own upstream sockets) and exits 78 (fail-open,
  no restart). Chosen over v1's `SO_MARK` because marking needs
  `CAP_NET_ADMIN`, which would also let the request-processing process rewrite
  the firewall. No existing marks exist on the NVR, so neither approach collides.
* **Conntrack anchor.** The chain always starts with a no-op
  `-m conntrack --ctstate INVALID -j RETURN` rule while any camera is enabled.
  On a real kernel, deleting the *last* DNAT rule deactivates connection tracking
  and an in-flight redirected long poll then hangs (its replies are no longer
  un-NAT'd); with the anchor it completes. The anchor is removed only by
  uninstall or when no camera is enabled, after instances have drained.
* **Header-only passthrough is the default.** Responses (event notifications)
  are relayed unchanged; the shim only reads a bounded copy to count PullMessages
  outcomes and motion notifications for health.
* **Original destination check.** Each accepted connection's pre-DNAT
  destination (`SO_ORIGINAL_DST`) is compared with the configured camera:
  `redirected`, `direct` (local test connections, small separate budget) or
  `misrouted` (refused).
* **Privileged helper split.** The privileged part is `shimctl.py`, run
  only as `ExecStartPost=+`/`ExecStopPost=+` hooks, by the reconcile timer and
  by the operator. It never handles camera traffic.

### WS-Addressing repair

* Applies only to `PullMessages`, `SetSynchronizationPoint` (events WSDL) and
  `Renew`, `Unsubscribe` (WS-Notification b-2), identified by namespace-qualified
  Body child, not by string matching.
* Each element is checked individually in the Header's WS-Addressing children
  (2005/08 and 2004/08 namespaces). A declared namespace, a `ReplyTo`, or a
  `MessageID` does not count as `To`/`Action`.
* Adds only what is missing from the camera's `wsa_repair` list (default
  `To`, `Action`; optional `MessageID`, `ReplyTo`). Existing elements are kept
  byte-for-byte, never rewritten. `To` is `http://<Host header if it names the
  camera, else camera_ip:port><original request target>`, so path, query string
  and subscription index are preserved (XML-escaped).
* Edits are byte insertions located by an expat parse; nothing is re-serialized,
  so WS-Security UsernameToken bytes, reference parameters, prefixes and
  QName-valued text keep their exact bytes and meaning. Inserted elements carry
  their own namespace declarations.
* `mustUnderstand="1"` on `To`/`Action` by default (as in v1); `wsa_must_understand: false` per camera if a camera faults on it.

**Fail-transparent handling.** When an edit is not provably safe the request is
forwarded **unchanged** and the reason counted, so the camera sees exactly what
it would see without the shim:

| Input | Outcome |
| --- | --- |
| DTD / entity declarations (incl. billion laughs) | `skipped_dtd`, never expanded |
| depth > 64 or > 20 000 elements | `skipped_limits` |
| malformed XML, not SOAP | `skipped_malformed`, `skipped_not_soap` |
| UTF-16/BOM, non-UTF-8 bytes or declared encoding, non-UTF-8 charset, `Content-Encoding` | `skipped_encoding` |
| XML Signature present | `skipped_signed` (never invalidated) |
| `Content-MD5`, `Digest`, `Content-Digest`, `Repr-Digest`, `Signature*`, Digest `qop=auth-int` | `skipped_integrity` |
| duplicate or mixed-version addressing, Header after Body | `skipped_ambiguous` |

HTTP framing errors are rejected before reaching the camera: >256 KiB body
(413), >32 KiB head (431), conflicting `Content-Length`, `Content-Length` with
`Transfer-Encoding`, obsolete folding, absolute-form targets, missing Host (400),
methods other than GET/POST/HEAD (405), non-chunked transfer codings (501).

## Security and privileges

| Component | Runs as | Privileges |
| --- | --- | --- |
| `onvif-shim@<id>` (request processing) | DynamicUser (e.g. uid 64365 in tests) | none: `CapEff=0`, empty bounding set, `NoNewPrivileges`, seccomp `@system-service`, `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, `RestrictAddressFamilies=AF_INET AF_UNIX`, `MemoryDenyWriteExecute`, `MemoryMax=96M`, `TasksMax=16`, `CPUWeight=50`, `OOMScoreAdjust=500` |
| `shimctl.py` (firewall + systemd) | root | needed for iptables-restore and systemctl; runs only as unit hooks, the timer, or by the operator |

Verified in a systemd container: `Uid 64365`, `CapEff 0`, `CapBnd 0`,
`NoNewPrivs 1`, `Seccomp 2`. Fully unprivileged operation is **not** claimed:
the firewall management is root.

* No credentials anywhere: the inventory rejects unknown fields, units take
  only `%i`, the shim forwards Protect's own Authorization/WS-Security. Header-only
  mode stores nothing.
* Logs: only camera id, event name, numeric counters and fixed category words.
  Never Authorization, cookies, WS-Security, bodies, URLs, paths or queries
  (tested). Per-instance token bucket (default 30 lines/min) plus systemd
  `LogRateLimit*`, because the whole NVR journal is capped at 80 MB.
* Health is a JSON file in `/run/onvif-shim/<id>/status.json`, written
  atomically every heartbeat; no extra listening port. Listeners bind
  127.0.0.1 only. Any local process can reach a loopback listener, which only
  gives what it could already do (talk to the camera); direct connections get a
  separate, smaller concurrency budget so they cannot starve Protect.
* Releases are pinned: a tarball with `MANIFEST.sha256`; install verifies every
  hash, rejects unlisted `.py` files and requires root-owned, non-group/other
  writable code (it runs as root in the hooks). Nothing is downloaded on the NVR.
* Snapshot/thumbnail interception is **not implemented** (`snapshots.enabled:
  true` is rejected): it would require intercepting camera HTTP. If ever added,
  credentials must come from a root-only file passed with systemd
  `LoadCredential=`, never the inventory or unit files.

## AI motion mode (opt-in)

**AI mode** (not for Parking East, which is non-AI) drops the camera's raw
pixel-motion messages and emits one synthetic `CellMotionDetector/Motion`
notification whenever the OR of Reolink `MyRuleDetector/*Detect` states
changes. State is per camera *and* per subscription (request target), bounded to
16 subscriptions and expired after 30 min idle. `Initialized` messages reset
state and produce a synthetic `Initialized` value; "off" is held
`off_hold_seconds` and delivered in a later poll; after a shim restart (unknown
state) an AI "false" still produces an "off"; a stuck "on" is forced off after
`max_motion_seconds` and re-armed. Synthetic messages are built from the
camera's own message, made namespace-self-contained. Unverified on hardware.

## Failure behavior and fail-open

A redirect exists only while the instance is verifiably serving: unit
`active`, status file written by the unit's current `MainPID`, heartbeat newer
than 15 s, listening on its port, not self-declared unsafe, and no conflicting
foreign DNAT (e.g. leftover v1 rules) for that camera. Otherwise the redirect
is removed and Protect connects to the camera directly, which is exactly
today's behavior (events fail; video unaffected).

| Event | What happens (verified in tests unless noted) |
| --- | --- |
| Planned stop/restart | `ExecStop` removes the redirect *before* SIGTERM, so new connections go direct while in-flight long polls drain (≤ `drain_timeout`); the anchor keeps their NAT mapping. |
| Shim crash (SIGKILL) | `ExecStopPost` removes the redirect in ~0.2 s; restart after 5 s re-adds it (~5.4 s). In-flight request sees EOF; new connections refused until removal. |
| Event loop hang (SIGSTOP) | Reconcile timer sees stale heartbeat and removes the redirect (~30 s); systemd watchdog (30 s) kills and restarts it. |
| Crash loop | `StartLimitBurst=5` per 600 s: unit ends `failed`, redirect off, reconcile raises `unit_failed` alert and does **not** restart it. `shimctl reset <id>` after fixing. |
| Safety refusal (port taken, disabled camera, would run as Protect uid/root, loop detected, invalid config) | exit 78, `RestartPreventExitStatus=78`, no restart loop, alert. |
| Camera offline | Shim aborts the client connection like an unreachable camera (no synthesized HTTP), marks `outage` after 3 connect failures, `recovered` on the next success. Redirect stays (direct would fail equally). Other cameras unaffected (separate processes). |
| Inventory invalid / Protect user missing | all redirects and the anchor removed, alert. |
| Firewall apply error | atomic restore = no partial state; then fail-open removal of everything, alert. |
| Rule removed while a redirected long poll is in flight | the established connection keeps its conntrack NAT mapping and completes through the shim (anchor keeps conntrack active); new connections go direct. |
| Shim restarted | Stateless routing: Protect's existing subscription path keeps working; counters reset. |
| UniFi OS update removes units | No units → no rules after the next boot: fail-safe (direct path). Reinstall needed. |
| Reboot | Kernel rules vanish; enabled instances start at boot and their `ExecStartPost` re-adds redirects (immediate in the container test). |

Protect and the NVR are never restarted by this integration.

## Capacity estimates vs measurements

**Estimates (not measured on the UNVR):** per camera one process; Protect uses
about one long poll at a time per camera; 4 active requests allowed;
~15 MB PSS each; 50 cameras ≈ 0.75 GB of the ~10.5 GB observed available; CPU
negligible (a few small XML parses per poll); journal ≈ 4 summary lines per
camera per hour plus state changes.

**Measured, simulated** ([evidence/scale-test.txt](evidence/scale-test.txt); OrbStack aarch64,
kernel 7.0, Python 3.13, 50 real shim processes, 50 DNAT rules, 50 mock cameras,
one made unreachable, three rounds of 50 concurrent 2 s long polls from uid 996):

| Metric | Result |
| --- | --- |
| Processes alive | 50/50 |
| RSS per instance / total | 25.6 MB / 1.30 GB (shared pages double-counted) |
| PSS per instance / total | 15.0 MB / 0.73 GB |
| Healthy cameras per round | 49/49 succeeded, max 2.02 s for a 2 s poll |
| Unreachable camera | failed alone at the 5 s connect timeout; its shim reported `degraded`, `connect_timeout` |

This is not production acceptance for 50 real cameras.

## Tests and results

| Suite | Command | Result (2026-10-11) |
| --- | --- | --- |
| Unit/integration (mocks): config, SOAP repair, events/AI, HTTP framing, 50-camera concurrency, overload, stall isolation, outage/recovery, loop, drain, sanitized logs, lifecycle with fake systemd/iptables | `uv run pytest -q -W error` | 187 passed on Python 3.12 and 3.13 (+1 registry-freshness check run with `IEEE_OUI_DIR`) |
| Real netfilter (privileged container, iptables-legacy, separate camera netns) | `tests/kernel/run.sh` | 15/15 scenarios ([evidence/kernel-test.txt](evidence/kernel-test.txt)) |
| Real systemd 257 as PID 1 | `uv run python tests/systemd/systemd_test.py` | 16/16 scenarios ([evidence/systemd-test.txt](evidence/systemd-test.txt)) |
| Simulated 50 cameras on real kernel | `docker run --rm --privileged -v "$PWD:/src:ro" onvif-shim-kernel-test python3 /src/tests/kernel/scale_test.py` | see Capacity |
| Lint / format / inventory | `uv run ruff check shimlib tests tools onvif_shim.py shimctl.py`, `uv run ruff format --check shimlib tests tools onvif_shim.py shimctl.py`, `python3 -I shimctl.py validate --config cameras.example.json` | clean / valid |

Kernel scenarios: shim has zero capabilities; uid-996 PullMessages traverses
the shim and is repaired; conntrack shows the reply tuple
`src=127.0.0.1 sport=18113` and an un-NAT'd shim upstream flow; uid 0 and uid 982
are not redirected; ports 554 and 80 are not intercepted; local direct
connections are classified via `SO_ORIGINAL_DST`; rule removal keeps an
established poll and bypasses new ones; crash then fail-open; loop with a rule
deliberately matching the shim's uid exits 78 without reaching the camera;
negative control without the anchor strands an in-flight poll (15 s timeout);
uninstall restores the pristine nat table; conntrack count 0 before the first
rule.

Systemd scenarios: dry-run changes nothing; install starts the instance and
redirects; DynamicUser sandbox; Protect pull via the real unit; idempotent
re-install; planned stop drains an in-flight poll while new connections go
direct; crash fail-open/recovery; hang bypass + watchdog restart; safety
refusal not restarted; reset; crash loop bounded (failed after 6 kills);
per-camera disable/enable; `shimctl add` by IP applies at once and `remove` reverts
it (with Protect's database unavailable); bypass-all/resume; redirect restored after reboot;
uninstall clean and idempotent (configuration kept).

## Unverified behavior and remaining risks

1. **Parking East with the shim's exact headers.** TLC's A/B showed `To` fixes
   it; the shim sends `To` + `Action` with `mustUnderstand="1"`. Not yet observed
   against the RLC-410-5MP firmware.
2. **Protect 7.2.105's client behavior**: long-poll `Timeout`, HTTP timeout,
   connection reuse (the shim answers every request with `Connection: close`),
   and how it treats an aborted connection or 503. Upstream was proven on
   Protect 7.3.56 and an RLC-1240A, not this pair.
3. **Real motion end-to-end**: that this camera emits `CellMotionDetector/Motion`
   notifications Protect turns into timeline events with correct times.
4. **UNVR kernel 5.15 vs test kernel 7.0**: owner match, DNAT to loopback,
   `SO_ORIGINAL_DST`, and the conntrack activation/anchor behavior were verified
   on 7.0 only. The NVR's empty-nat `nf_conntrack_count = 0` is consistent.
5. **Conntrack activation on the NVR**: the first rule turns on tracking for all
   NVR traffic (RTSP from ~50 cameras, UI, etc.). Expected small; measure count
   and CPU in the pilot.
6. **systemd sandbox options on the UniFi kernel** (seccomp filter,
   `MemoryDenyWriteExecute`, `ProtectProc`, DynamicUser): tested on Debian 13
   systemd 257 in a container. If any fails on the NVR the unit fails to start,
   which is fail-safe (no redirect); the fix would be removing that option.
7. **UniFi OS update behavior**: whether `/etc` units are removed, whether
   `python3`, iptables-legacy and uid 996 remain. Use the post-update checklist.
8. **Unknown firewall managers**: none seen on this UNVR; a future UniFi
   component flushing nat would remove redirects (fail-safe); reconcile re-adds
   them every 30 s.
9. **Protect identity of the redirected uid**: if Protect moves ONVIF calls to
   another process/uid, interception silently stops (fail-safe; status shows
   `unobserved`).
10. **AI mode**: implemented and unit-tested only; not validated on any camera.
11. **Capacity**: 50-camera numbers are simulated; Protect's real polling mix and
    the UNVR's memory pressure are not represented.
12. **Shared loopback**: any local process can connect to 127.0.0.1 listeners
    (bounded separately, no privilege gain).
13. **Timer is on the NVR**: no off-box supervision.
14. **Protect's database is internal**: `shimctl cameras/add/setup` read Protect's
    Postgres (`unifi-protect`, port 5433, as the `postgres` user) in a `READ ONLY`
    transaction that is rolled back, selecting only name, IP, MAC, type, adoption,
    ONVIF port and motion status. The schema is undocumented and may change with a
    Protect update; the commands then report it and `add IP --onvif-port` still works.
    Nothing in the shim's runtime path depends on it.
