#!/bin/sh
# Remove the multi-camera ONVIF shim: redirects first (Protect goes direct to the
# cameras), then instances, timer, unit files and the firewall chain.
# Non-interactive and idempotent. Keeps /data/onvif-shim (inventory, releases,
# backups); delete that directory afterwards to remove everything.
#   sh /data/onvif-shim/current/uninstall.sh [--dry-run]
set -eu
DIR=$(cd "$(dirname "$0")" && pwd -P)
for arg in "$@"; do
  case "$arg" in
    --dry-run) ;;
    *) echo "usage: sh $0 [--dry-run]" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || {
  echo "python3 not found; manual removal steps are in README.md (Rollback)" >&2; exit 1; }
exec python3 -I "$DIR/shimctl.py" uninstall "$@"
