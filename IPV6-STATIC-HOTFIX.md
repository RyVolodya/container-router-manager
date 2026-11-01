# IPv6 static / IPv4 continuity hotfix (v0.17.5 test)

Scope: Static IPv6 Apply and backend/host-agent pending synchronization.

- Static IPv6 preview applies IPv6 address, optional IPv6 default route, and IPv6 RA sysctls directly, **without** `networkctl reconfigure`, which may alter existing IPv4 DHCP connectivity.
- The new `.network.d` configuration is written for networkd persistence (including at boot).
- The agent restores the pre-change override, removes the preview IPv6 address/route, and restores RA sysctls on rollback or timeout.
- Backend reconciles its pending token with the agent on every status request. A finished agent rollback no longer leaves a stale confirmation banner.
- Automatic IPv6 still uses `networkctl reconfigure` and was NOT made IPv4-safe in this hotfix: avoid applying automatic IPv6 on remote management interfaces until tested on local console.

**Before testing**: make a Proxmox snapshot, verify IPv4 via `ip -4 addr show dev ens18`, run `sudo sh host-agent/install.sh`, restart host agent, rebuild backend and frontend. Test from Proxmox console.

**Known limitations**: Static IPv6 preview does not purge previously configured automatic IPv6 addresses at runtime, and refuses an address that already exists. Full static/automatic transitions need additional validation. This is a targeted test hotfix, not a production release.
