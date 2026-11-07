---
name: shim-deploy
description: Build a pinned ONVIF shim release on this workstation and install, update or reapply it on a remote UniFi console. Use when asked to deploy, install, update or upgrade the shim, whether a console runs the latest version, or to restore it after a UniFi OS update.
---

# Shim deploy

Branches:
- **First install** and **update** ship a new release: all steps.
- **Reapply** (UniFi OS update removed units or rules; same release): steps 1, 6–8, with
  `/data/onvif-shim/current/install.sh` in place of `releases/VERSION/install.sh`.
- **"Is it up to date?"** alone: steps 1–2, then report.

REF is the git ref to ship: `origin/main` by default, `origin/BRANCH` when the user names
a branch, `HEAD` for unpushed local work they ask to deploy.

## Steps

1. **Baseline.** `python3 tools/nvr.py snapshot TARGET`; keep firmware and Protect
   versions, the current release and any alerts for the report. Stop and report if it
   shows `LEGACY v1` (its own uninstall comes first, by user decision), no
   `unifi-protect` user, or no `iptables` owner match.
2. **Compare.** `python3 tools/nvr.py version TARGET --ref REF` (fetches origin first).
   - `up-to-date`: report it; an update stops here.
   - `behind`: the listed commits are the update; put them in the approval request.
   - `diverged`, `unknown-commit` or a `-dirty` warning: the console runs a build that is
     not on REF. Report the listed commits and ask with `AskUserQuestion` whether to
     replace it.
   - A ref that is "not a multi-camera release" (e.g. a `main` that still holds the v1
     shim): ask with `AskUserQuestion` which branch to ship, candidate branches as
     options.
3. **Build.** CI passed for REF's commit: every run in
   `gh run list --commit $(git rev-parse REF) --json name,conclusion` is `success`. For
   `HEAD` with no CI run, the working tree is clean and the CI checks (CLAUDE.md §
   Development) pass locally. Then `uv run python -m shimlib.release --ref REF --out dist`
   (builds the commit from git; the checkout is untouched) and record the printed
   version, tarball and sha256. The tarball is deterministic: reuse an existing
   `dist/onvif-shim-VERSION.tar.gz`.
4. **Upload** (a change). On production, ask with `AskUserQuestion` to approve "upload
   VERSION to TARGET (writes `/root/` and `/data/onvif-shim/releases/VERSION` only)".
   Then `nvr.py upload TARGET dist/onvif-shim-VERSION.tar.gz`. Done when it prints matching
   local and remote sha256 and `extracted`.
5. **Back up the firewall** before the first install on a console, inside the install
   approval:
   `nvr.py run TARGET -- 'mkdir -p /data/onvif-shim/backups && iptables-save > /data/onvif-shim/backups/iptables-pre-$(date -u +%Y%m%dT%H%M%SZ).txt'`
6. **Dry-run.** `nvr.py run TARGET -- sh /data/onvif-shim/releases/VERSION/install.sh --dry-run`.
   Any `PREFLIGHT` or `ERROR` line stops the deploy: report it. On an update the plan
   restarts every running camera (`restart onvif-shim@ID (release changed)`); each
   restart briefly sends that camera's connections direct.
7. **Apply** under the change protocol in CLAUDE.md: show the dry-run plan, get approval
   on production, run the same command without `--dry-run`.
8. **Verify.** `nvr.py shimctl TARGET status`: `release=VERSION`, `timer=active`, no
   `ALERT` lines; with enabled cameras also `chain=yes jump=yes` and every camera
   `UNIT active`, `REDIR on`, `PROCESS healthy`. Re-check after 5 minutes for
   `TRANSPORT healthy` and rising `PULLS ok` (see `shim-status` for interpreting them).
9. **Report**: REF, version and sha256, before/after versions, the commits shipped, status.
   After a first install the inventory is empty; cameras come next (`shim-cameras`).

If verification fails, report what failed; rolling back is `shim-rollback`
(`rollback-release` for an update).
