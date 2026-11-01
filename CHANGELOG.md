# Changelog

## v0.18.1 — GHCR distribution and version check
- Added GitHub Actions to publish backend and frontend images to GHCR on version tags.
- Added pinned Docker Compose image references for `docker compose pull`.
- Updated the built-in GitHub release checker and displayed version to 0.18.1.
- Added deployment and update instructions in `UPDATE-GHCR.md`.
- No intentional changes to network control logic from v0.18.0.

# Changelog

## v0.18.0 — Stable release (user approved)

- Consolidates the user-tested v0.17.5 DHCP/DNS/IPv6 combined baseline.
- Updates application package versions and release metadata.
- No intentional changes to network control logic relative to the supplied baseline.
- Includes dual-stack host interface configuration, Docker networks, NAT, routing, firewall and WireGuard features from the supplied source.

### Verification

The user reports successful testing of the source baseline on their test host. The user approved publication as stable based on successful testing of the source baseline. A clean build and full regression suite have not been independently verified in this environment.
