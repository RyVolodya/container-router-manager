# DNS test hotfix (based on v0.17.5 RA Exclusive Hotfix)

Adds distinct comma-separated IPv4/IPv6 DNS fields to the Static interface editor, and a DNS column to Host Interfaces populated from systemd-resolved's per-interface DNS data.

- Backend validates family and supports at most eight entries per family.
- Confirming Static IPv4 persists IPv4 DNS in the per-interface Netplan overlay.
- IPv6 DNS is stored in the networkd drop-in and set on the live link using resolvectl, retaining current IPv4 DNS.
- Safe Apply rollback restores the previous runtime DNS values.
- Verify runtime with `resolvectl dns ens18`, reboot persistence and confirm/rollback using Proxmox console.

NOTE: Full frontend/backend npm build was not possible in the isolated authoring environment because dependencies were not cached. Run `docker compose build backend frontend` before applying to a host. Test only in a VM with snapshot and console access.
