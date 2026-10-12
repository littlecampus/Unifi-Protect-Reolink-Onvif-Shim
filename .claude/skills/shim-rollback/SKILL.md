---
name: shim-rollback
description: Roll back the ONVIF shim on a remote UniFi console (one camera, all redirects, a release, or a full uninstall) and prove Protect talks to the cameras directly again. Use when asked to disable, bypass, roll back or uninstall the shim, or when a shim change made things worse.
---

# Shim rollback

Every rollback moves toward fail-open: Protect connects to the camera directly, which is
its behavior before the shim (events fail again; video is unaffected).

## Scopes

| Scope | Command (`python3 tools/nvr.py …`) | Undo |
|---|---|---|
| One camera | `shimctl TARGET disable ID` | `shimctl TARGET enable ID` |
| All redirects, persists across reboots | `shimctl TARGET bypass-all` | `shimctl TARGET resume` |
| Code version | `shimctl TARGET rollback-release [--to VERSION]` | `rollback-release --to NEWER` |
| Everything | `run TARGET -- sh /data/onvif-shim/current/uninstall.sh` | `shim-deploy` reapply |
| Python broken on the console | README.md § Rollback, last row ("manual fail-open") | `shim-deploy` reapply |

## Steps

1. **Pick the scope.** Use the one the user named; otherwise the narrowest one that
   removes the problem (one camera before all, redirects before uninstall).
2. **Apply** under the change protocol in CLAUDE.md. The user's rollback request is the
   approval for that scope. When they call it urgent, run `disable` or `bypass-all`
   directly; every other scope gets its `--dry-run` shown first. For the manual
   fail-open, copy the commands from the README at run time and pass them in single
   quotes so `$(id -u unifi-protect)` expands on the console.
3. **Prove the redirect is gone.**
   - One camera: `nvr.py run TARGET -- 'iptables -t nat -S | grep onvif-shim:cam:ID'`
     prints nothing; `shimctl TARGET status ID` shows `REDIR off` and the unit inactive.
   - Bypass: `status` shows `bypass_all=True` and every camera `REDIR off`.
   - Release: `status` shows the target `release=`, and each enabled camera is healthy
     with `REDIR on`.
   - Uninstall: `snapshot` shows no unit files and `no shim or DNAT nat rules`.
4. **Prove Protect is direct.** Within about 5 minutes, `onvif.events.log` shows Protect
   working against the camera again. For a camera that had the circuit-breaker
   pattern, its return is the expected proof, not a new failure. Ask the user to
   confirm recordings still advance in Protect.
5. **Report** the scope, the evidence from steps 3–4, and the undo command.

`uninstall.sh` keeps `/data/onvif-shim` (inventory, releases, backups) so a reinstall
restores the same setup. Deleting that directory is a separate, explicit user request.
