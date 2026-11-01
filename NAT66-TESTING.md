# NAT44/NAT66 test build v0.17.4

This build is intended for an isolated Linux test server. Frontend TypeScript type-check passed. Backend compilation and live ip6tables validation have NOT been completed in this environment.

- NAT rules accept `family: 4 | 6` in POST/PUT `/api/nat/rules`; absent family defaults to 4.
- IPv6 rules use ip6tables nat PREROUTING/POSTROUTING and IPv6-specific source/destination resolution.
- IPv6 DNAT to a container does NOT automatically create an IPv6 FORWARD ACCEPT rule. Configure IPv6 forwarding and firewall policy independently.
- For IPv6 outbound policy routing, a suitable IPv6 default route must exist through the selected interface.
- Back up the persistent Docker volume containing `/data/nat.json` and keep out-of-band console access before testing.
- IPv6 NAT requires kernel ip6tables NAT support. NAT66 is usually unnecessary when native IPv6 routing is possible.
