---
name: shim-acceptance
description: Hardware acceptance test of one shimmed camera on a remote console, with an evidence file.
disable-model-invocation: true
argument-hint: TARGET CAMERA_ID
---

# Shim acceptance

Proves one camera end to end on real hardware. Precondition: the camera was added
(`shim-cameras`) and `shimctl TARGET status ID` shows `REDIR on` and `PROCESS healthy`.
Site specifics for the TLC pilot are in `docs/tlc-pilot.md`.

Write `docs/evidence/acceptance-TARGET-ID-YYYY-MM-DD.md` as you go: per step, the UTC
time, commands, trimmed output, and PASS/FAIL against its criterion. The user is the only
source for what Protect's UI shows; record their answers as theirs. Steps 5–7 are changes:
apply the change protocol in CLAUDE.md to each.

`nvr` below is `python3 tools/nvr.py`; `IP`/`PORT` are the camera's address and ONVIF port.

## Steps

0. **Baseline.** `nvr snapshot TARGET`; `nvr shimctl TARGET status ID --json`;
   RTSP readers `nvr run TARGET -- "ss -tnp 'dst IP and dport = :554'"`. Ask the user
   for the camera's Protect recording mode and its latest recording time.
1. **Traversal.** Two samples 5 minutes apart. PASS when all hold: `redirect` true; the
   camera's DNAT packet counter in `nvr run TARGET -- iptables -t nat -L ONVIF_SHIM -n -v`
   rises; `requests.redirected` rises; `nvr run TARGET -- "ss -tnp 'dst IP and dport = :PORT'"`
   shows the shim's python3 connection.
2. **Soak, at least 30 minutes.** Sample `nvr shimctl TARGET status ID --json` every 5
   minutes (7 or more samples), as a background loop writing to a temp file. PASS when
   `pulls_ok` rises every sample, `pulls_failed` stays flat, `event_transport` stays
   healthy, `repairs.repaired` rises, and `onvif.events.log` since step 0 shows one
   `Started ONVIF event subscription` and no `Deactivated`/`circuit-breaker` line for the
   camera (match its name and its MAC without colons).
3. **Walk test.** Ask the user to walk through the scene and tell you when they start and
   stop; note both UTC times. Then
   `nvr run TARGET -- "journalctl -u onvif-shim@ID --since 'START' -o short-iso --no-pager | grep motion_notification"`.
   PASS when `value=true` follows the start within seconds, `value=false` follows the
   stop, and the user confirms a motion event on the Protect timeline at those times.
   Empty successful polls or `motionDetection available` are not a pass.
4. **Recording continues.** PASS when the user confirms the Protect timeline advanced
   through the test and the `:554` readers match step 0.
5. **Restart.** `nvr run TARGET -- systemctl restart onvif-shim@ID`. PASS when status is
   healthy with `REDIR on` again and, over the next 10 minutes, Protect resubscribes at
   most once with no circuit breaker.
6. **Camera outage**, only if the user approves a physical outage (for example PoE off for
   about 2 minutes). PASS when the journal shows `camera_outage` then `camera_recovered`,
   Protect resubscribes, a short walk test passes again and recording resumes.
7. **Rollback.** Per-camera `disable` via `shim-rollback`. PASS when the camera's rule is
   gone and Protect's prior behavior returns within about 5 minutes (circuit breaker for
   a camera that had it). Then `enable ID` and confirm healthy again.
8. **Measure.** `nf_conntrack_count`, `free -m`, and the instance's Pss:
   `nvr run TARGET -- 'grep Pss /proc/$(systemctl show -p MainPID --value onvif-shim@ID)/smaps_rollup'`.
9. **Verdict** at the top of the evidence file: ACCEPTED when steps 1–5 and 7 pass (and 6
   if run); otherwise NOT ACCEPTED, naming the failing step and its evidence. Report the
   verdict and the file path.
