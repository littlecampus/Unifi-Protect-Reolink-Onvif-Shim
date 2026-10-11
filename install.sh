#!/bin/sh
# Install, update or manage the multi-camera ONVIF shim from an extracted release.
# Safe to re-run (idempotent), e.g. after a UniFi OS update.
#   sh /data/onvif-shim/releases/VERSION/install.sh [--dry-run]   install/update this release
#   sh /data/onvif-shim/current/install.sh uninstall [--dry-run]  remove units + rules (keeps /data/onvif-shim)
#   sh /data/onvif-shim/current/install.sh status|enable ID|...   any shimctl.py command
set -eu
DIR=$(cd "$(dirname "$0")" && pwd -P)
command -v python3 >/dev/null 2>&1 || { echo "python3 not found on this console"; exit 1; }
case "${1:-install}" in
  install) [ $# -gt 0 ] && shift
           exec python3 -I "$DIR/shimctl.py" install --release "$(basename "$DIR")" "$@" ;;
  --*)     exec python3 -I "$DIR/shimctl.py" install --release "$(basename "$DIR")" "$@" ;;
  *)       exec python3 -I "$DIR/shimctl.py" "$@" ;;
esac
