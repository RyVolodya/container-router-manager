# Container Router Manager v0.18.0

Stable release based on the latest v0.17.5 DHCP/DNS/IPv6 combined build tested and approved by the project maintainer.

## Highlights

- Dual-stack host interfaces: IPv4 and IPv6 static configuration, SLAAC, DHCPv6, RA default route options, DNS settings and safe apply workflows.
- IPv4/IPv6 Docker network management, including IPv6 allocation and network editing.
- NAT44/NAT66 and port forwarding configuration.
- Routing, firewall, WireGuard and container networking interface.
- Fixes accumulated through the v0.17.5 DHCP/DNS/IPv6 testing cycle.

## Installation

See README.md and docker-compose.yml. Back up existing application state and host network configuration before upgrading.

## Validation

The source baseline was tested by the project maintainer. Clean Docker builds and a complete independent integration test suite are not claimed; see TESTING-STATUS.md.
