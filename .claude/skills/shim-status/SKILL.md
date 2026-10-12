---
name: shim-status
description: Read-only health check and diagnosis of the ONVIF shim on a remote UniFi console. Use when asked whether the shim or a camera's motion events work, to investigate alerts, failing pulls or circuit breakers, and before and after any change on a console.
---

# Shim status

Read-only on any target. It diagnoses and proposes fixes; applying a fix belongs to
`shim-cameras`, `shim-deploy` or `shim-rollback`.

## Steps

1. **Snapshot.** `python3 tools/nvr.py snapshot TARGET`. Done when the bundle printed
   every section (an SSH failure is the finding: report it and stop).
2. **Classify the install.** From `install` and `units`: not installed, installed with
   no cameras, or installed with N cameras. Flag a `LEGACY v1` line, `BYPASS-ALL ACTIVE`,
   missing unit files while `current` exists (UniFi OS update removed them), and
   `foreign_dnat` entries.
3. **Account for every camera and every alert.** For each inventory camera in
   `status --json`, record `unit`, `redirect`, `process_healthy`/`process_reason`,
   `event_transport`, `pulls_ok`/`pulls_failed`, `repairs`, and
   `last_motion_notification_at`. Match each `ALERT` and each non-healthy camera to a
   cause using README.md § Troubleshooting, then confirm with read-only probes:
   - `nvr.py run TARGET -- journalctl -u onvif-shim@ID -n 100 -o short-iso --no-pager`
   - `nvr.py run TARGET -- systemctl status onvif-shim@ID --no-pager`
   - `nvr.py run TARGET -- "ss -tnep 'dst CAMERA_IP and dport = :PORT'"`
   Done when every camera has a verdict and every alert has a cause with an evidence line.
4. **Check Protect's side.** In `protect onvif.events.log`, count only lines newer than
   the camera's redirect coming on: a new `Deactivated`/`circuit-breaker` line for a
   shimmed camera means it is still failing. In `cameras --json`, list cameras whose
   `advice` is `NEEDS SHIM`.
5. **Report**: overall verdict (healthy, degraded, broken, not installed); a per-camera
   table; each finding with its evidence and the proposed fix, naming the skill that
   applies it.

## Reading the numbers

- Counters reset when an instance restarts. "Rising" needs two samples at least 5
  minutes apart (Protect polls, and retries failed subscriptions, every 5 minutes);
  one snapshot shows a level, not a trend.
- `TRANSPORT unobserved` right after an add or restart is normal until Protect's next
  poll.
- `repairs.complete` growing while `repaired` stays flat means Protect now sends the
  headers itself; the camera may no longer need the shim.
- `requests.redirected` counts connections that arrived through the firewall redirect;
  it proves traversal.
- `detection_verified` is always false: motion works only when a motion event appears
  on the Protect timeline, which the user confirms.
