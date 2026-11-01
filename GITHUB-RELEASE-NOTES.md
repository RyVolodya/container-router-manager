# Container Router Manager v0.18.1

## What's new
- Added GitHub Releases version checking.
- Added GitHub Actions publishing backend and frontend Docker images to GHCR with versioned and `latest` tags for stable releases.
- Updated Docker Compose to pull published images using `DRM_VERSION` (defaults to `latest`).
- Added deployment and update documentation.
- Retained the networking functionality from v0.18.0.

## Update
```bash
docker compose pull
docker compose up -d --no-build
```

**Note:** Docker Compose image updates do not update the Compose file or the host network agent. Deploy host-agent changes separately.
