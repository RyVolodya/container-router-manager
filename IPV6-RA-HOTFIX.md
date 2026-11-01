# IPv6 Static + RA test hotfix

Static and Automatic are exclusive. In Static, Add default route (RA) enables router advertisements without SLAAC or DHCPv6 and disables the manual gateway field. Leave it unchecked to enter a manual gateway.

The host agent snapshots IPv6 addresses and default routes for 60s rollback. The Linux runtime uses IPv6-only operations to avoid networkctl reconfigure resetting IPv4. A saved networkd drop-in persists the desired setting on restart.

Known test constraint: transitions from an active networkd-managed DHCPv6 session may require link reconfiguration on some Ubuntu/systemd versions; watch for DHCPv6 renewal after confirming. Test from Proxmox console with a VM snapshot, not production.

Installation: sudo sh host-agent/install.sh && sudo systemctl restart drm-network-agent.service && docker compose up -d --build backend frontend
