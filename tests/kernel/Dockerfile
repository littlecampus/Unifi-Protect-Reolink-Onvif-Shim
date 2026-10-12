# Kernel-level test bed approximating the UNVR: Debian 13, Python 3.13, iptables-legacy.
# Test-only image: it is never deployed. Run via tests/kernel/run.sh (privileged).
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 iptables iproute2 conntrack procps util-linux \
 && update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
