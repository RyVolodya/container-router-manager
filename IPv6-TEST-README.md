# Container Router Manager v0.17.5 — IPv6 static + automatic networkd test

**TEST-ONLY:** This is a source patch assembled from the user's uploaded ZIP. It has not been validated against a running Proxmox VM or a full Docker build. Keep Proxmox console available. Make a VM snapshot first. Do not use on a production host.

## Changes

- Automatic IPv6 addressing on Netplan + systemd-networkd interfaces is configured via a host-side helper instead of flushing IPv6 addresses and routes using `ip`.
- SLAAC, DHCPv6 client and RA default route are controlled separately in a generated `systemd-networkd` drop-in.
- No use of unavailable `dhclient` in automatic networkd mode.
- Safe Apply backup and 60-second timer live on the Ubuntu host, so backend restart does not cancel rollback.
- IPv6 host changes require the helper and **fail closed** if it is absent.
- Static IPv6 with prefix and optional gateway is now supported via the same host-side Safe Apply helper. Static and automatic addressing are mutually exclusive. Existing IPv4 runtime paths are unchanged.

## Installation (Ubuntu 24.04 / systemd-networkd host only)

1. Create a Proxmox VM snapshot and verify console access.
2. Inspect `/etc/netplan` and back up `/etc/systemd/network`.
3. From the extracted project directory run on the HOST:

   ```sh
   sudo sh host-agent/install.sh
   sudo systemctl status drm-network-agent --no-pager
   ```

4. Rebuild the backend:

   ```sh
   docker compose up -d --build backend
   docker compose logs --tail=50 backend
   ```

5. Use Host Interfaces -> ens18 -> IPv6. Choose either Static (address/prefix and optional gateway) or Automatic (SLAAC, DHCPv6, or both; independent RA default route).
6. Apply only while watching the local Proxmox console, and **do not Confirm until** verifying `ip -6 addr`, `ip -6 route`, and `networkctl status ens18`.
7. If the result is wrong, choose Rollback or let 60 seconds elapse. Check `journalctl -u drm-network-agent -n 80` and the actual address/route state. Do not assume rollback succeeded without checking.

The host helper creates a single file like `/etc/systemd/network/10-netplan-ens18.network.d/90-drm-ipv6.conf` and uses `networkctl reload` + `networkctl reconfigure`. It doesn't overwrite `/etc/netplan/50-cloud-init.yaml`.

**Limitations:** networkd may retain previously acquired SLAAC or DHCPv6 addresses during a reconfigure until renewal/expiration. Validation of exact address removal, duplicate route cleanup, DHCPv6 renewal and rollback is still required on the test VM. No automatic claim of production readiness.

## Checks

```sh
ip -d -6 addr show dev ens18
ip -6 route show default
networkctl status ens18 --no-pager
sysctl net.ipv6.conf.ens18.accept_ra
sudo journalctl -u drm-network-agent -n 80 --no-pager
docker compose logs --tail=80 backend
```

## Removing the helper (after restoring the host's original network state)

```sh
sudo systemctl disable --now drm-network-agent
sudo rm -f /etc/systemd/system/drm-network-agent.service /usr/local/lib/drm/drm_network_agent.py
sudo systemctl daemon-reload
```

Don't remove a managed `.network.d/90-drm-ipv6.conf` while a Safe Apply is pending. To revert a confirmed config, restore the previous networkd config and reload/reconfigure from the Proxmox console.

## Additional tests for this patch

- Static: `fd00:1::2/64` without gateway -> address only, no default route.
- Static: `fd00:1::2/64` with gateway `fe80::1` -> one configured default route. Gateway must be reachable on this link.
- Automatic: SLAAC only; DHCPv6 only; SLAAC+DHCPv6; each with RA default route on/off.
- Verify automatic-to-static and static-to-automatic transitions. networkd may retain old dynamic addresses until they expire: verify `ip -6 addr`, and do not assume every old address disappears immediately.
- Check 60-second rollback before confirming a trial. A confirmed change persists in a networkd drop-in.
- If an interface already has additional manual `[Address]` entries in Netplan, this patch does not remove them.

Reinstall the updated host agent (required; rebuilding Docker alone will not replace it):

```sh
sudo sh host-agent/install.sh
sudo systemctl restart drm-network-agent.service
docker compose up -d --build backend frontend
```

**Important:** host-agent/install.sh uses `systemctl enable --now`; if the service is already running, the explicit `restart` above is necessary to load the new Python code.
