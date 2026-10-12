---
name: shim-deploy
description: Build a pinned ONVIF shim release on this workstation and install, upgrade or reapply it on a remote UniFi console. Use when asked to deploy, install or upgrade the shim, or to restore it after a UniFi OS update.
---

# Shim deploy

Branches:
- **First install** and **upgrade** ship a new release: all steps.
- **Reapply** (UniFi OS update removed units or rules; same release): steps 1, 5–8, with
  `/data/onvif-shim/current/install.sh` in place of `releases/VERSION/install.sh`.

## Steps

1. **Baseline.** `python3 tools/nvr.py snapshot TARGET`; keep firmware and Protect
   versions, the current release and any alerts for the report. Stop and report if it
   shows `LEGACY v1` (its own uninstall comes first, by user decision), no
   `unifi-protect` user, or no `iptables` owner match.
2. **Build.** `git status --porcelain` is empty and HEAD is the commit the user wants
   deployed. Run the CI checks (CLAUDE.md § Development) and stop on any failure. Then
   `uv run python -m shimlib.release --out dist` and record the printed version, tarball
   and sha256. The tarball is deterministic: if `dist/onvif-shim-VERSION.tar.gz` already
   exists for this commit, reuse it.
3. **Upload** (a change). On production, ask approval for "upload VERSION to TARGET (writes
   `/root/` and `/data/onvif-shim/releases/VERSION` only)". Then
   `nvr.py upload TARGET dist/onvif-shim-VERSION.tar.gz`. Done when it prints matching
   local and remote sha256 and `extracted`.
4. **Back up the firewall** before the first install on a console, inside the install
   approval:
   `nvr.py run TARGET -- 'mkdir -p /data/onvif-shim/backups && iptables-save > /data/onvif-shim/backups/iptables-pre-$(date -u +%Y%m%dT%H%M%SZ).txt'`
5. **Dry-run.** `nvr.py run TARGET -- sh /data/onvif-shim/releases/VERSION/install.sh --dry-run`.
   Any `PREFLIGHT` or `ERROR` line stops the deploy: report it.
6. **Apply** under the change protocol in CLAUDE.md: show the dry-run plan, get approval
   on production, run the same command without `--dry-run`.
7. **Restart instances after an upgrade.** `install.sh` restarts instances only when unit
   files change, so after a release switch the running instances still execute the old
   code. Restart them one at a time (each restart is a change):
   `nvr.py run TARGET -- systemctl restart onvif-shim@ID`, then `shimctl TARGET status ID`
   until it shows `UNIT active`, `REDIR on`, `PROCESS healthy` before the next one.
8. **Verify.** `nvr.py shimctl TARGET status`: `release=VERSION`, `timer=active`, no
   `ALERT` lines; with enabled cameras also `chain=yes jump=yes` and every camera
   `UNIT active`, `REDIR on`, `PROCESS healthy`. Re-check after 5 minutes for
   `TRANSPORT healthy` and rising `PULLS ok` (see `shim-status` for interpreting them).
9. **Report**: branch, version and sha256, before/after versions, what changed, status.
   After a first install the inventory is empty; cameras come next (`shim-cameras`).

If verification fails, report what failed; rolling back is `shim-rollback`
(`rollback-release` for an upgrade).
