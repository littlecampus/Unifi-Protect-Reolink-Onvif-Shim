---
name: shim-cameras
description: Add, remove, re-enable, reset or tune cameras in the ONVIF shim inventory on a remote UniFi console. Use when asked which cameras need the shim, to shim a camera, or to change a camera's WS-Addressing repair settings.
---

# Shim cameras

Disabling a camera is a rollback: `shim-rollback`. Installing the shim itself:
`shim-deploy`.

## Steps

1. **Inventory.** `python3 tools/nvr.py shimctl TARGET cameras --json` (`--needs-shim` for
   cameras Protect reports `misconfigured`; `--all` adds unadopted ones) and
   `shimctl TARGET status --json`. Before the first install, list cameras from an
   uploaded release with `shimctl TARGET --release VERSION cameras`.
2. **Plan one camera at a time** on production: the next starts only after the previous
   one passes step 5. Dry-run the action:

   | Action | Command (`nvr.py shimctl TARGET …`) |
   |---|---|
   | Add | `add SELECTOR --dry-run` (IP preferred; a Protect name or MAC also works; options in README.md § Choosing and adding cameras) |
   | Stage (write it disabled) | `add SELECTOR --stage --dry-run` |
   | Re-enable | `enable ID --dry-run` |
   | Remove | `remove ID --dry-run` |
   | Clear a failed unit | `reset ID --dry-run`, once the journal shows the cause is fixed |
   | Tune | see below |

   Surface every `WARN` line to the user. A non-Reolink camera, or one whose ONVIF port
   is its web port 80 (the Dahua door stations), gets a single-camera trial before any
   batch.
3. **Apply** under the change protocol in CLAUDE.md.
4. **Check right away.** `add` and `enable` print the camera's status: `UNIT active`,
   `REDIR on`, `PROCESS healthy`. `TRANSPORT unobserved` is expected until Protect's
   next poll.
5. **Check after at least 5 minutes** (`shimctl TARGET status ID --json`, then the Protect
   log via `snapshot` or `run`): `event_transport` healthy, `pulls_ok` and
   `repairs.repaired` higher than at step 4, `Started ONVIF event subscription` for the
   camera, and no new `Deactivated`/`circuit-breaker` line for it since the add. Anything
   else: diagnose with `shim-status`.
6. **Report** the inventory change, the step 4–5 evidence, and the remaining
   acceptance step: a motion event on the Protect timeline (`/shim-acceptance`).

## Tuning a camera

There is no `shimctl` command to edit a camera in place. Re-create it with the same id and
port: `remove ID`, then
`add CAMERA_IP --id ID --listen-port PORT [--onvif-port P] [--mode M] --wsa To,Action,MessageID`
(add `--no-must-understand` as the next step if the camera still rejects). Show both
commands for approval together. `add` cannot dry-run while the old entry exists; in
between, the camera is on Protect's direct path, which is safe. Carry over every
non-default option from the old entry, as read from
`nvr.py run TARGET -- cat /data/onvif-shim/cameras.json`.
