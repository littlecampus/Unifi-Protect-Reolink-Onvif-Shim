# TLC deployment: inventory and Parking East pilot

Site-specific companion to the [README](../README.md) and
[architecture](architecture.md). **Nothing has been installed on the TLC UNVR.** The
pilot below requires explicit approval of the exact changes.

## Recorder inventory (read-only, 2026-10-11, no changes made)

| Fact | Observed |
| --- | --- |
| Platform | UNVR Gen 2 Pro, `UNVRAI.qcs8550.v6.0.11`, Debian 13, kernel 5.15.167 aarch64 |
| Protect / UniFi Core | `unifi-protect 7.2.105`, `unifi-core 6.0.123` |
| Python | 3.13.5 (standard library only) |
| Firewall | `iptables v1.8.11 (legacy)`; nat/mangle/raw/filter all empty, ACCEPT policies; no `ip rule` fwmark routing; no firewall manager service |
| Marks | none in use (no MARK/CONNMARK rules, no fwmark policy routing) |
| Conntrack | `nf_conntrack_count = 0` (inactive: no rule references it) |
| Matches available | `owner`, `conntrack`, `comment`, `mark`, ... (`/proc/net/ip_tables_matches`) |
| Protect process | `unifi-protect` **uid 996**; RTSP readers are `ms` (uid 982) |
| ONVIF connections to Parking East :8000 | sampled at 0.2 s for a full 5-minute cycle: **all uid 996** |
| Persistence | `/` is overlayfs, upper `/mnt/.rwfs/data` (ext4 partition `overlay`); `/data -> /ssd1/.data` (NVMe) |
| journald | `SystemMaxUse=80M` for the whole NVR |
| Protect failure | every 5 min for Parking East, Parking North, Prog Room Int, Prog Room Ext: 3 deactivations within ~45 s, then `circuit-breaker fired`, `motionDetection available -> misconfigured` |

Protect's own camera list (read-only query of its database, 2026-10-11; no
credential fields read):

| Group | Count | Protect motion | Notes |
| --- | --- | --- | --- |
| Adopted Reolink (`IPC-BO`, MAC `EC71DB…`): Parking East, Parking North, Prog Room - Ext, Prog Room - Int | 4 | `misconfigured` | the four cameras tripping the circuit breaker; ONVIF 8000 |
| Adopted Dahua door stations (MAC `BC325F…`): Front Door, Ramp, Staff Room, Stair B VTO | 4 | `misconfigured` | ONVIF on port **80** (shared with their web/snapshot port); untested with the shim |
| Discovered, **not adopted** Reolink | 32 | n/a | no name in Protect; the shim has no effect on cameras Protect does not adopt |

Open question for the rollout: "about 50 cameras recorded by Protect" does not match 8
adopted third-party cameras on this UNVR; confirm where the other cameras are recorded.

Established earlier by TLC A/B testing: authenticated PullMessages without
`wsa:To` makes Parking East close the connection; adding `To` yields HTTP 200;
adding `Action` alone does not.

## Parking East pilot (requires approval)

Parking East only; continuous recording must stay on; no re-adoption, database
edits, recording-mode changes, firmware or Protect upgrades.

1. **Inventory and backup** (read-only plus copies into `/data/onvif-shim/backups`):
   versions (`ubnt-device-info firmware`, `dpkg-query -W unifi-protect unifi-core`),
   `iptables-save > backups/iptables-pre.txt`, `ls /etc/systemd/system`,
   `ss -tnp 'dst 10.48.20.13'` (RTSP readers), `cat /proc/sys/net/netfilter/nf_conntrack_count`,
   `free -m`, last 50 Parking East lines of `onvif.events.log`. In Protect:
   confirm Parking East recording mode (Always) and note the latest recording time.
2. **Approve the exact change**: one inventory entry (`parking_east`, 10.48.20.13:8000 →
   127.0.0.1:18113), three unit files, one chain + anchor + one DNAT + one jump.
3. **Install** per the README (`install.sh --dry-run`, `install.sh`; the first
   install creates an empty inventory), then `shimctl cameras --needs-shim`,
   `shimctl add "Parking East" --dry-run` (expect id `parking_east`, 10.48.20.13:8000 →
   127.0.0.1:18113, as in [`examples/parking-east.json`](../examples/parking-east.json)),
   then `shimctl add "Parking East"`. No legacy v1 shim is installed on this UNVR
   (`/data/onvif-shim` did not exist at inventory time).
4. **Prove traversal**: `shimctl status parking_east` shows `REDIR on`;
   `iptables -t nat -L ONVIF_SHIM -n -v` DNAT packet counter increases;
   `status --json` `requests.redirected` (from `SO_ORIGINAL_DST`) increases;
   `ss -tnp 'dst 10.48.20.13 and dport = :8000'` shows the shim's python3
   connection (non-996 uid) while Protect's own sockets show peer 10.48.20.13:8000.
5. **Prove continuous long polls** for ≥ 30 minutes: `pulls_ok` keeps rising,
   `consecutive_failures` stays 0, `repairs.repaired` rises, and `onvif.events.log`
   shows one `Started ONVIF event subscription` for Parking East and **no** new
   `Deactivated` / `circuit-breaker` lines.
6. **Physical motion**: walk through the scene; record wall-clock start/end;
   expect `motion_notification value=true` then `value=false` in the shim
   journal, and a Protect motion event on the Parking East timeline with matching
   start/end times. Empty 200 polls or `motionDetection available` are not
   acceptance.
7. **Recording continues**: in Protect, the timeline keeps advancing during and
   after the pilot; `ss` shows the same `ms` RTSP connections to :554 (no extra
   reader added by the shim).
8. **Restart test**: `systemctl restart onvif-shim@parking_east`; Protect
   recovers without a circuit breaker, or resubscribes once.
9. **Camera outage test** (separately approved, e.g. PoE port off ~2 min): status
   `outage` then `recovered`; Protect resubscribes; motion works again; recording
   resumes when video returns.
10. **Rollback test**: `shimctl disable parking_east`; verify no DNAT rule and that
    Protect's prior behavior returns (circuit breaker within ~5 min). Re-enable if
    the pilot continues.
11. Measure `nf_conntrack_count`, `free -m`, the instance's Pss
    (`grep Pss /proc/$(systemctl show -p MainPID --value onvif-shim@parking_east)/smaps_rollup`).

Only after pilot acceptance: add a small batch (`shimctl add` or `shimctl setup` for
Parking North, Prog Room - Int/Ext, which show the same breaker pattern), then scale
gradually. The Dahua VTOs need their own single-camera trial first (different vendor,
ONVIF on port 80).
