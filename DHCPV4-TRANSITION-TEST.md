# v0.17.5 DHCPv4 transition test

Test only on a Proxmox VM with console access and snapshot. IPv4 network changes temporarily interrupt SSH.

- Install host-agent/install.sh and restart drm-network-agent.service.
- Rebuild backend and frontend with docker compose up -d --build backend frontend.
- Select IPv4 DHCP in Host Interfaces and Apply.
- Check networkctl status ens18, ip -4 addr show dev ens18, ip -4 route show dev ens18, and /run/systemd/netif/leases.
- Confirm only after DHCP lease is acquired and desired network connectivity works. Otherwise choose Rollback or use Proxmox console.
- Recheck IPv6 Static/RA/DNS and DNS after reboot.

Note: Full Docker build and DHCP lease integration have not been executed in this environment.
