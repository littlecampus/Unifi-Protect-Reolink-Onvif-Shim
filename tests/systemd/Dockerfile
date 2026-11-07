# systemd-as-PID-1 test bed approximating the UNVR (Debian 13, systemd 257,
# Python 3.13, iptables-legacy, /data -> /ssd1/.data). Test-only, never deployed.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 iptables iproute2 \
      conntrack procps util-linux \
 && update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /ssd1/.data && ln -s /ssd1/.data /data \
 && groupadd -g 981 unifi-streaming && useradd -u 996 -g 981 -M unifi-protect
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
