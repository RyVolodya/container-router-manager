# CRM 0.17.5 – persistent IPv4 and static IPv6 RA test hotfix

Changes from previous IPv6 RA test build:

- On confirming an IPv4 change, write a late `/etc/netplan/99-drm-<interface>.yaml` overlay and validate it using `netplan generate` (no `netplan apply`). This ensures Netplan regenerates the confirmed IPv4 configuration after reboot/reconfiguration rather than reverting to DHCP. Base Netplan YAML is not overwritten.
- Before an IPv6-only operation, repair missing persistent IPv4 Netplan configuration if CRM already stores a static IPv4 address.
- For **static IPv6 + RA gateway**, prevent systemd-networkd and the kernel from both accepting RA: the networkd drop-in has `IPv6AcceptRA=no`, while the agent enables kernel RA with `autoconf=0`. This is deliberately a runtime no-reconfigure path for static IPv6, to avoid disturbing IPv4.
- Show **DHCP IPv4** or **STATIC IPv4** according to the live address instead of stored desired mode.

## Important limitations of this test build

- The Netplan overlay is generated without applying it. If the current live IPv4 has already reverted to DHCP, the overlay will protect the stored static address on the next Netplan/networkd reconfiguration but does **not** change the live IPv4 immediately. Restore IPv4 using CRM's IPv4 Safe Apply/Confirm, preferably from a Proxmox console.
- An existing networkd RA listener may continue running until networkd reconfigures. Thus the old `metric 10` RA default may temporarily return. Verify after reconf/restart.
- Only test on an Ubuntu host using Netplan and systemd-networkd. Do not use this experiment on a production machine.
- A snapshot and out-of-band Proxmox console are strongly recommended.

## Read-only checks

```sh
cat /etc/netplan/99-drm-ens18.yaml
cat /etc/systemd/network/10-netplan-ens18.network.d/90-drm-ipv6.conf
ip -4 addr show dev ens18
ip -6 addr show dev ens18
ip -6 route show default
```

## Deploy

```sh
sudo sh host-agent/install.sh
sudo systemctl restart drm-network-agent
sudo docker compose up -d --build backend frontend
```
