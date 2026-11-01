# v0.17.5 test hotfix — Static IPv6 + RA

## Issue
Static IPv6 with `Add default route (via RA)` caused a new SLAAC IPv6 address and duplicate default routes (metrics 10 and 1024) despite a correct static address. IPv4 persistence from the previous build must remain intact.

## Changes
- The host agent no longer sets `accept_ra=2` in static + RA mode.
- `systemd-networkd` is configured as the sole RA consumer (`IPv6AcceptRA=yes`, `UseAutonomousPrefix=no`, `DHCPv6Client=no`, `UseGateway=yes`).
- Kernel RA handling remains off (`accept_ra=0`, `autoconf=0`, `accept_ra_defrtr=0`) to avoid creating an additional route with kernel metric 1024.
- A guarded networkd reconfigure is used only for static + RA; it refuses to operate if a live static IPv4 would be replaced by DHCP or is absent from generated Netplan. Other static IPv6 modes retain the non-reconfigure fast path.
- Previously created dynamic IPv6 addresses and stale kernel RA default routes are cleaned up.
- Safe Apply rollback restores previous networkd configuration as well.

## Important
Changes to systemd-networkd may briefly interrupt connectivity. Test using Proxmox VM console and snapshot. A successful Python syntax check does not guarantee runtime correctness. No Docker/frontend modifications are included.

## Check
```
cat /etc/netplan/99-drm-ens18.yaml
ip -4 addr show dev ens18
ip -6 addr show dev ens18
ip -6 route show default
sysctl net.ipv6.conf.ens18.accept_ra net.ipv6.conf.ens18.autoconf
```
