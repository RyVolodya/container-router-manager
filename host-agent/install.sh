#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root'; exit 1; }
install -d -m 0755 /usr/local/lib/drm /run/drm-network-agent /var/lib/drm-network-agent
install -m 0755 "$(dirname "$0")/drm_network_agent.py" /usr/local/lib/drm/drm_network_agent.py
install -m 0644 "$(dirname "$0")/drm-network-agent.service" /etc/systemd/system/drm-network-agent.service
systemctl daemon-reload
systemctl enable --now drm-network-agent.service
systemctl status drm-network-agent.service --no-pager
