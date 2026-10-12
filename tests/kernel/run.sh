#!/bin/sh
# Real-kernel netfilter test for the NVR-local shim. Needs Docker on Linux (or a
# Linux VM such as OrbStack/Docker Desktop) and runs a *privileged* throwaway
# container; it never touches the host's firewall or any NVR/camera.
set -eu
cd "$(dirname "$0")/../.."
docker build -q -t onvif-shim-kernel-test tests/kernel >/dev/null
exec docker run --rm --privileged -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/src:ro" onvif-shim-kernel-test python3 /src/tests/kernel/kernel_test.py
