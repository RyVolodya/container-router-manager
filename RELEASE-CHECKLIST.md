# v0.18.0 release checklist

1. Run `docker compose build --no-cache` and record successful frontend/backend builds.
2. Run `docker compose up -d` and `docker compose ps`; check backend/frontend logs.
3. Verify host network agent is installed and active.
4. Test IPv4 DHCP/static, IPv6 static/SLAAC/DHCPv6/RA route, DNS and rollback using noncritical interfaces.
5. Test dual-stack Docker network create/edit and container connectivity.
6. Test NAT44/NAT66, firewall, routing and WireGuard, including reboot persistence.
7. Confirm the release archive matches the tested source and tag `v0.18.0`.
