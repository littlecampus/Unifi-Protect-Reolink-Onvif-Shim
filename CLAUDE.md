# ONVIF shim for UniFi Protect

The shim runs on a UniFi console (NVR). Claude Code runs only on this workstation and
reaches consoles over SSH through `tools/nvr.py`; nothing agent-related is ever installed
or run on a console.

## Consoles

- Targets live in `.claude/nvr-targets.json` (gitignored; format:
  `.claude/nvr-targets.example.json`). Each has an `ssh` destination (key auth as root)
  and `production: true|false`.
- Every console command names its target. If the user did not name one and more than
  one is configured, ask which.
- For a console that is not configured, ask the user for its SSH destination and whether
  it is production (their answer only; it decides whether changes need approval), then
  `nvr.py targets add NAME --ssh DEST --production true|false [--description TEXT]`.
  It tests SSH as root on a UniFi console before saving. Changing a target is
  `targets remove NAME` then `add`, with the user's answers again.
- `python3 tools/nvr.py --help`: `snapshot` (read-only bundle), `shimctl TARGET ...`,
  `run TARGET -- CMD`, `upload`. Quote remote shell syntax (`$(...)`, pipes) in single
  quotes so it expands on the console.

## Change protocol

Read-only work is free on any target: `snapshot`; `shimctl status|cameras|validate|units`;
anything with `--dry-run`; journals, logs, `iptables -L/-S`, `ss`, `systemctl status|show`.

Everything else is a change, including `upload`, `systemctl restart onvif-shim@…` and
writing backups. For each change:

1. Dry-run it (`shimctl … --dry-run`, `install.sh --dry-run`, `uninstall.sh --dry-run`).
2. Show the user the dry-run output and the target name.
3. Production target: wait for the user's explicit approval of that plan on that target;
   approval covers that plan only. Test target: continue.
4. Apply exactly the plan that was dry-run.
5. Verify with `shimctl status` (plus the skill's own checks) and report what you observed.

A user's request to roll back a named scope is approval for that scope (see the
`shim-rollback` skill).

## Hard rules on consoles

- Protect stays untouched: unifi-protect, unifi-core and the console keep running (no
  restarts, reboots, firmware or package changes); adoption and recording modes stay as
  they are. Protect's database is read only through `shimctl cameras`, which never
  selects credential columns.
- Shim state changes only through `shimctl`, `install.sh` and `uninstall.sh` (they lock,
  back up, validate and fail open). The one hand edit of firewall or units is the
  README's manual fail-open, for when Python on the console is broken.
- Releases are built here from a clean commit and copied with `nvr.py upload`; the
  console downloads nothing.
- Logs, notes and evidence carry no secrets: no auth headers, cookies, passwords or
  stream URLs.

## Development

- Console runtime is the Python ≥ 3.11 standard library: `shimlib/`, `onvif_shim.py` and
  `shimctl.py` import nothing third-party.
- Checks are the steps in `.github/workflows/ci.yaml` (pytest, ruff check and format,
  kernel and systemd suites).
