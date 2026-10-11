# UniFi Protect ONVIF Shim for Reolink cameras (multi-camera)

**Get motion events working for Reolink (and similar gSOAP) cameras adopted in UniFi
Protect as third-party ONVIF cameras.** The shim runs on the UniFi console itself,
serves any number of cameras, and changes nothing in Protect: cameras keep their
adoption, IP, MAC, history and direct video streams.

> ⚠️ **Unofficial and unsupported.** It adds one small service per camera and a few
> scoped firewall (NAT) rules to your console. Everything is removable with one
> command. Not affiliated with Ubiquiti or Reolink.

Based on [cclifton7/Unifi-Protect-Reolink-Onvif-Shim](https://github.com/cclifton7/Unifi-Protect-Reolink-Onvif-Shim)
(MIT). Version 2 is a multi-camera rework with **no backward compatibility** with the
single-camera `shim.conf` install; uninstall that first (see [Installation](#installation)).

**Status:** tested with mock cameras, a real Linux kernel firewall and real systemd
([test evidence](docs/architecture.md#tests-and-results)). Not yet accepted on real
hardware; see [Limitations](#limitations).

---

## Contents
- [Symptoms](#symptoms) · [Confirm you have this problem](#confirm-you-have-this-problem) · [Root cause](#root-cause)
- [What the shim does](#what-the-shim-does) · [Requirements](#requirements)
- [Installation](#installation) · [Verify it's working](#verify-its-working)
- [Configuration](#configuration) · [Day-to-day operation](#day-to-day-operation)
- [Rollback](#rollback) · [After a UniFi OS update](#after-a-unifi-os-update)
- [Troubleshooting](#troubleshooting) · [How it works](#how-it-works)
- [Security](#security) · [Limitations](#limitations) · [Development](#development)

## Symptoms

- The camera is adopted in Protect (third-party / ONVIF); live view and recording work.
- **No motion events ever appear** for it, even with motion detection enabled.
- Re-adopting, camera firmware updates and Protect settings change nothing.
- The camera itself *is* detecting motion (its app, spotlight or siren show it).

## Confirm you have this problem

On the console (SSH as `root`):

```bash
grep -iE "consecutive errors|circuit-breaker" /srv/unifi-protect/logs/onvif.events.log | tail -5
```

Lines like these, repeating every 5 minutes for your camera, confirm it:

```
warn: Deactivated ONVIF event subscription for XXXXXXXXXXXX after 3 consecutive errors
warn: REOLINK ... ONVIF event subscription circuit-breaker fired: subscription kept failing after 3 deactivations
info: REOLINK ... motionDetection available -> misconfigured [...]
```

`motionDetection available` alone proves nothing: Protect reports the capability
before any poll succeeds.

## Root cause

Protect subscribes to the camera's ONVIF events correctly, then polls them with
`PullMessages` (and `Renew`, `Unsubscribe`, `SetSynchronizationPoint`) **without
WS-Addressing headers** (`wsa:To`, `wsa:Action`). Reolink's embedded gSOAP server
requires them: depending on model and firmware it answers HTTP 400 or simply closes
the connection. After three failures Protect deactivates the subscription, trips a
circuit breaker and marks motion detection "misconfigured", retrying every 5 minutes.
Neither side can be configured to fix it.

## What the shim does

| Feature | Effect | Default |
|---|---|---|
| **Header repair** | Adds only the missing `wsa:To` / `wsa:Action` to those four requests. Everything else, including the camera's real motion events, passes through byte-for-byte. | **On** (the only thing a default install does) |
| **AI-driven motion** | Protect motion follows the camera's Reolink AI detections (person/vehicle/animal) instead of pixel motion. Only for AI cameras whose pixel motion proves unreliable. **On a non-AI camera it would suppress all motion.** | Off; opt-in per camera |

Video never passes through the shim; it does not open extra streams to cameras.
Thumbnail/snapshot interception from the single-camera version has been removed
(it required intercepting camera HTTP and storing camera passwords).

## Requirements

- UniFi console running Protect with `python3` ≥ 3.11, `systemd`, `iptables` with
  the `owner` match. Developed against a UNVR Gen 2 Pro, UniFi OS 6.0.11, Protect
  7.2.105 (Debian 13, Python 3.13, iptables-legacy).
- Cameras adopted in Protect as third-party ONVIF with **fixed IPs** (DHCP reservations).
- Protect's ONVIF client runs as the `unifi-protect` user (checked by preflight).

## Installation

Build a pinned release on your computer (from a clean checkout of a reviewed commit):

```bash
uv run python -m shimlib.release --out dist
# prints the version (2.0.0-g<commit>), the tarball path and its sha256
scp dist/onvif-shim-2.0.0-g<commit>.tar.gz root@CONSOLE_IP:/root/
```

On the console:

```bash
V=2.0.0-g<commit>
sha256sum /root/onvif-shim-$V.tar.gz            # compare with the value printed above
# Single-camera v1 installed? Remove it first: sh /data/onvif-shim/install.sh uninstall
mkdir -p /data/onvif-shim/releases
tar -xzf /root/onvif-shim-$V.tar.gz -C /data/onvif-shim/releases
cp /data/onvif-shim/releases/$V/cameras.example.json /data/onvif-shim/cameras.json
vi /data/onvif-shim/cameras.json                # your cameras; start with one enabled
python3 -I /data/onvif-shim/releases/$V/shimctl.py validate --preflight
sh /data/onvif-shim/releases/$V/install.sh --dry-run    # shows every change, changes nothing
sh /data/onvif-shim/releases/$V/install.sh
```

From then on use `/data/onvif-shim/current/` (a symlink to the active release):

```bash
alias shimctl='python3 -I /data/onvif-shim/current/shimctl.py'
```

`install` is idempotent: re-running it reports `no changes`. It writes three
systemd unit files, starts one `onvif-shim@<id>` instance per enabled camera, enables
a 30-second reconcile timer, and adds a camera's firewall redirect only after its
instance is verifiably serving.

Do not switch cameras to "Detections" recording because events start working; keep
your recording mode as it is.

## Verify it's working

```bash
shimctl status
```

Wanted: `UNIT active`, `REDIR on`, `PROCESS healthy`, `TRANSPORT healthy`, and
`PULLS ok` increasing over a few minutes. Then:

```bash
grep -iE "Started ONVIF|Deactivated|circuit-breaker" /srv/unifi-protect/logs/onvif.events.log | tail
journalctl -u onvif-shim@CAMERA_ID -f -o cat      # walk through the scene
```

A healthy camera logs one `Started ONVIF event subscription` and no new
`Deactivated`/`circuit-breaker` lines. During a walk test the shim logs
`motion_notification value=true` then `value=false`, and **a motion event appears on
the Protect timeline**. That last step is the real acceptance: the shim cannot see
inside Protect, so `status` never claims detection or recording health.

## Configuration

`/data/onvif-shim/cameras.json`; full example: [cameras.example.json](cameras.example.json),
one camera: [examples/parking-east.json](examples/parking-east.json).

```json
{
  "schema_version": 1,
  "client_user": "unifi-protect",
  "cameras": [
    {"id": "front_door", "camera_ip": "192.168.1.50", "onvif_port": 8000,
     "listen_port": 18101, "enabled": true}
  ]
}
```

| Field | Rules / default |
|---|---|
| `client_user` | user whose connections are redirected; default `unifi-protect` |
| `id` | `[a-z][a-z0-9_]{0,31}`, unique; also the systemd instance name |
| `camera_ip` | literal IPv4, one entry per camera, not an address of the console |
| `onvif_port` | camera ONVIF port (Reolink: 8000). Video ports (554, 322, 1935, 7441, 7447, 8554) and TLS ports are refused; 80/8080 only with `"onvif_port_shared_with_http": true` |
| `listen_port` | unique local port 1024–65535 (loopback only), must be free |
| `enabled` | required `true`/`false` |
| `mode` | `passthrough` (default) or `ai_motion` |
| `ai_motion` | with `ai_motion` only: `off_hold_seconds` (10), `max_motion_seconds` (900, 0 = off) |
| `wsa_repair` | headers to add when missing: subset of `To`, `Action`, `MessageID`, `ReplyTo`; must include `To`; default `["To", "Action"]` |
| `wsa_must_understand` | default `true` |
| `limits` | `max_active_requests` (4), `max_request_bytes` (256 KiB), `max_response_bytes` (4 MiB), `max_header_bytes` (32 KiB), `connect_timeout` (5 s), `client_timeout` (10 s), `response_timeout` (120 s), `drain_timeout` (20 s) |

`defaults.limits`, `defaults.wsa_repair`, `defaults.wsa_must_understand` and
`status.{heartbeat_seconds, summary_log_seconds, log_lines_per_minute}` set
inventory-wide values. Unknown fields, duplicate keys, duplicate ids, listeners or
camera addresses are rejected. The file contains no credentials: the shim forwards
Protect's own authentication.

After editing: `shimctl validate`, `shimctl install --dry-run`, `shimctl install`.

## Day-to-day operation

| Task | Command |
|---|---|
| Health | `shimctl status` · `shimctl status CAMERA_ID` · `shimctl status --json` |
| Live log | `journalctl -u onvif-shim@CAMERA_ID -f -o cat` |
| Reconcile log / alerts | `journalctl -u onvif-shim-reconcile -n 50 -o cat` |
| Firewall rules and counters | `iptables -t nat -L ONVIF_SHIM -n -v` |
| Add a camera | add it with `"enabled": false`, `shimctl validate --preflight`, then `shimctl enable CAMERA_ID` |
| Disable one camera | `shimctl disable CAMERA_ID` |
| Restart one camera's shim | `systemctl restart onvif-shim@CAMERA_ID` |
| Clear a failed instance (after fixing the cause) | `shimctl reset CAMERA_ID` |
| Upgrade | extract a new release, `sh /data/onvif-shim/releases/NEW/install.sh --dry-run`, then without `--dry-run` |

`shimctl status` keeps separate questions separate:

| Column | Meaning |
|---|---|
| `UNIT`, `PROCESS` | is the camera's shim process running and serving (heartbeat, listening, not unsafe) |
| `REDIR` | are Protect's connections to this camera currently redirected through it |
| `TRANSPORT` | event transport: `healthy` (recent successful polls), `degraded`, `failing`, `outage` (camera unreachable), `unobserved` |
| `PULLS ok/fail`, `REPAIRED` | counters since the process started |
| `LAST MOTION NOTIF` | last camera motion=true event relayed to Protect |

`ALERT` lines need action: `unit_failed`, `unhealthy cam=… reason=…`,
`conflicting_dnat`, `config_invalid`, `client_user_missing`, `firewall_apply_failed`,
`bypass_all_active`.

## Rollback

| Scope | Command | Effect |
|---|---|---|
| One camera | `shimctl disable CAMERA_ID` | backs up the inventory, removes that camera's redirect **first**, then stops its instance. Protect talks to the camera directly again. `shimctl enable CAMERA_ID` to undo. |
| Every camera, now | `shimctl bypass-all` | removes all redirects and keeps them off (persists across reboots) until `shimctl resume` |
| Code version | `shimctl rollback-release [--to VERSION]` | switches back to the previous verified release and restarts instances |
| Everything | `sh /data/onvif-shim/current/install.sh uninstall` | removes redirects, stops and removes all units, removes the firewall chain; keeps `/data/onvif-shim` |
| If Python is broken | `iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner $(id -u unifi-protect) -m comment --comment onvif-shim:jump -j ONVIF_SHIM; iptables -t nat -F ONVIF_SHIM; iptables -t nat -X ONVIF_SHIM; systemctl disable --now onvif-shim-reconcile.timer 'onvif-shim@*'` | manual fail-open |

To prove a rollback worked, confirm the camera's rule is gone
(`iptables -t nat -S | grep onvif-shim:cam:CAMERA_ID` prints nothing) and that
Protect's original behavior returns in `onvif.events.log`.

## After a UniFi OS update

`/data` survives updates; unit files in `/etc/systemd/system` and firewall rules may
not. If they are gone, nothing is redirected (Protect is back to its original,
failing behavior; video is unaffected). The reconcile timer lives on the console too,
so it cannot repair an update that removed it. After every update:

```bash
ubnt-device-info firmware; dpkg-query -W unifi-protect
python3 -VV; iptables -V; id unifi-protect
shimctl validate --preflight
sh /data/onvif-shim/current/install.sh --dry-run
sh /data/onvif-shim/current/install.sh
shimctl status
```

If `status` shows requests as `complete` rather than `repaired`, Protect now sends the
headers itself and the shim is no longer needed for that camera.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `REDIR off`, `PROCESS no_status`/`unit_inactive` | instance not running: `systemctl status onvif-shim@ID`, `journalctl -u onvif-shim@ID` |
| `unit_failed` alert | restart limit hit or safety refusal (port in use, disabled camera, loop). Fix the cause, then `shimctl reset ID` |
| `TRANSPORT unobserved` with `REDIR on` | Protect hasn't polled yet (it retries every 5 minutes), or Protect connects as another user: check `ss -tnep 'dst CAMERA_IP and dport = :8000'` |
| `TRANSPORT failing`, `PULLS fail` rising | camera still rejects: try `"wsa_repair": ["To", "Action", "MessageID"]` or `"wsa_must_understand": false` for that camera |
| `TRANSPORT outage` | camera unreachable (power, PoE, network) |
| `repairs` shows `skipped_*` | request not safely editable (signed, malformed, unusual encoding); forwarded unchanged |
| `conflicting_dnat` alert | the single-camera v1 shim's rules are still present; uninstall it |
| Events reach the shim log but not Protect | check motion detection is enabled for the camera in Protect and `/srv/unifi-protect/logs/events.cameras.log` |

## How it works

```
Protect (unifi-protect) ──► CAMERA_IP:8000
   nat OUTPUT: only connections owned by unifi-protect jump to ONVIF_SHIM
   ONVIF_SHIM: CAMERA_IP:8000 -> DNAT 127.0.0.1:LISTEN_PORT
      ▼
onvif-shim@ID (unprivileged, one per camera) adds missing wsa:To/Action
      ▼
CAMERA_IP:8000   (the shim's own connection is not Protect's user: not redirected)
```

Only Protect's own connections to configured camera ONVIF ports are redirected;
RTSP, snapshots and every other process's traffic are untouched. Details, security
model, failure behavior and test evidence: [docs/architecture.md](docs/architecture.md).

## Security

- Each camera's shim runs as a systemd dynamic user with **no capabilities**,
  `NoNewPrivileges`, a seccomp filter and a read-only view of the system. Only the
  control tool (`shimctl.py`, run by unit hooks, the timer or you) runs as root, to
  manage the firewall and services.
- No credentials are stored. Logs contain camera ids, counters and fixed reason
  words only: never authorization headers, cookies, WS-Security tokens, bodies or URLs.
- Listeners bind to 127.0.0.1. The status files live in `/run/onvif-shim/`.
- Releases are pinned and checksummed; nothing is downloaded on the console.
- ONVIF and RTSP are unencrypted protocols: a dedicated camera VLAN where only the
  console can reach the cameras remains the strongest protection.

## Limitations

- Not yet accepted on real hardware: no camera/Protect pair has been verified
  end-to-end with this version. See the risk list in
  [docs/architecture.md](docs/architecture.md#unverified-behavior-and-remaining-risks).
- Requires the `owner` iptables match and Protect running as its own user.
- IPv4 cameras only; plain HTTP ONVIF only (no TLS).
- Protect shows plain "Motion"; AI mode decides *when*, not the label.
- About 15 MB of memory per camera (measured in a simulation; see architecture doc).

## Development

```bash
uv sync
uv run pytest -q -W error                                   # 158 tests, mocks
uv run ruff check shimlib tests onvif_shim.py shimctl.py
tests/kernel/run.sh                                         # real netfilter, privileged container
uv run python tests/systemd/systemd_test.py                 # real systemd as PID 1
```

## License

[MIT](LICENSE)
