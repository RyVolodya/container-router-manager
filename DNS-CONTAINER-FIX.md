# DNS container ENOENT fix (test build)

- Backend now reads and writes host link DNS through the existing Unix-socket DRM network agent instead of launching `resolvectl` inside Alpine.
- Host agent adds `get_dns` and `set_dns` operations. Both validate the managed interface; `set_dns` validates numeric IPv4/IPv6 addresses.
- Existing IPv6 host-agent DNS application and rollback remain unchanged.
- Reinstall host-agent **before** rebuilding/restarting backend, otherwise the new operations will return `Unknown operation`.
- Test with Proxmox console and snapshot. This is not production validated.
