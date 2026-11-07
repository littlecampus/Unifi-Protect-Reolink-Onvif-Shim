#!/bin/sh
# Install or update the multi-camera ONVIF shim from this extracted release.
# Non-interactive and idempotent: safe to re-run, e.g. after a UniFi OS update.
#   sh /data/onvif-shim/releases/VERSION/install.sh [--dry-run]   install this release
#   sh /data/onvif-shim/current/install.sh [--dry-run]            reapply the active release
# Reads /data/onvif-shim/cameras.json. Remove with uninstall.sh; manage with shimctl.py.
set -eu
DIR=$(cd "$(dirname "$0")" && pwd -P)
for arg in "$@"; do
  case "$arg" in
    --dry-run) ;;
    *) echo "usage: sh $0 [--dry-run]   (to remove: sh $DIR/uninstall.sh)" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || { echo "python3 not found on this console" >&2; exit 1; }
exec python3 -I "$DIR/shimctl.py" install --release "$(basename "$DIR")" "$@"
