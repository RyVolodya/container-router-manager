
<img src="docs/images/drm-logo.png" alt="Docker Router Manager logo" width="120">

# Docker Router Manager

### Turn your Docker host into a manageable router, firewall and WireGuard gateway.

**Visualize Docker networks · Control published ports · Route traffic ·
Manage WireGuard**

[![Release](https://img.shields.io/github/v/release/RyVolodya/docker-router-manager?display_name=tag&sort=semver)](https://github.com/RyVolodya/docker-router-manager/releases)
![Docker](https://img.shields.io/badge/Docker-supported-2496ED?logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-host-FCC624?logo=linux&logoColor=black)
![IPv4%20%2B%20IPv6](https://img.shields.io/badge/IPv4%20%2B%20IPv6-dual--stack-2f80ff)
![WireGuard](https://img.shields.io/badge/WireGuard-supported-88171A?logo=wireguard&logoColor=white)

**Current release: v0.16.9**

[Quick Start](#-quick-start) · [Features](#-what-can-drm-do) ·
[Screenshots](#-screenshots) · [Security](#-security-considerations) ·
[Roadmap](#-roadmap)
:::

------------------------------------------------------------------------

## What is Docker Router Manager?

**Docker Router Manager (DRM)** is an open-source web interface for
managing the network layer around Docker.

Docker makes containers and published ports easy to create, but once a
host also needs **source-based firewall rules, routing between networks,
VPN access, IPv4/IPv6 forwarding or network visibility**, administration
quickly moves to `iptables`, `ip route`, `conntrack`, WireGuard
configuration and Docker CLI.

DRM brings those tasks into one interface.

``` text
                         Internet
                            │
                            ▼
                     ┌─────────────┐
                     │ Docker Host │
                     └──────┬──────┘
                            │
                 ┌──────────┼──────────┐
                 │          │          │
                 ▼          ▼          ▼
              Firewall    Routing   WireGuard
                 │          │          │
                 └──────────┼──────────┘
                            ▼
                    Docker Networks
                            │
                       Containers
```

DRM is designed for environments where the Docker host is more than an
application runtime and also acts as a gateway between **containers,
Docker networks, LANs, VPN clients and external networks**.

> **DRM is not a replacement for Portainer or other container-management
> platforms.**\
> It focuses on the network path around your containers: **visibility,
> firewall, routing and VPN access**.

------------------------------------------------------------------------

## 📸 Screenshots

### Dashboard

Get an immediate overview of Docker networks, containers, endpoints,
published ports and traffic.

<img src="docs/images/dashboard.png" alt="Docker Router Manager dashboard">

### Interactive Network Topology

See Docker networks, containers, published ports and external paths in
one live diagram.

<img src="docs/images/topology.png" alt="Docker Router Manager topology">

### Docker-aware Firewall

Control access to published Docker services and policies between Docker
networks.

<img src="docs/images/firewall.png" alt="Docker Router Manager firewall">

### IPv4 / IPv6 Routing

Inspect the Linux routing table, forwarding state and DRM-managed static
routes.

<img src="docs/images/routing.png" alt="Docker Router Manager routing">

### WireGuard

Create interfaces and peers, define access policies and generate client
configurations or QR codes.

<img src="docs/images/wireguard.png" alt="Docker Router Manager WireGuard">

------------------------------------------------------------------------

## 🚀 What can DRM do?

  -----------------------------------------------------------------------
  Area                                Capabilities
  ----------------------------------- -----------------------------------
  **Docker visibility**               Networks, containers, endpoints,
                                      IPv4/IPv6 addresses, published
                                      ports

  **Traffic monitoring**              Real-time RX/TX rates and
                                      cumulative counters

  **Topology**                        Interactive Docker network and
                                      external-path visualization

  **Published-port firewall**         Source CIDR filtering for exposed
                                      Docker services

  **Network policies**                Rules between Docker networks with
                                      protocol/port matching

  **Firewall workflow**               Apply / Rollback, engine
                                      enable/disable, conntrack session
                                      termination

  **Routing**                         IPv4/IPv6 forwarding, route tables
                                      and persistent static routes

  **WireGuard**                       Interfaces, peers, IPv4/IPv6, DNS,
                                      routes, QR codes and client configs

  **VPN access policy**               Docker networks, LAN/custom CIDRs
                                      and Internet access

  **Authentication**                  Administrator, Operator and Viewer
                                      roles

  **UI**                              Dark/light themes and responsive
                                      layout

  **Deployment**                      Docker Compose on a Linux Docker
                                      host
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 🔥 Firewall Engine

Docker Router Manager manages traffic at the Docker host level and
integrates with Docker's forwarding path.

### Published-port filtering

A Docker service can be published on the host while access is restricted
to selected source networks.

For example:

``` text
Internet / LAN
      │
      │ TCP/9443
      ▼
 Docker Host
      │
      │ Source: 192.168.100.0/24
      │ Action: DROP
      ▼
   Portainer
```

Example policy:

``` text
Published service:
0.0.0.0:9443/tcp → portainer:9443

Source:
192.168.100.0/24

Action:
DROP
```

DRM can also terminate matching existing `conntrack` sessions when a
published-port block is applied, so a new policy can affect existing
connections instead of only future ones.

### Docker network policies

Policies can be created between Docker networks with protocol and
destination-port matching.

``` text
Docker Network A
       │
       │ TCP/5432
       ▼
Docker Network B
```

Firewall changes use an **Apply / Rollback** workflow, and the Firewall
Engine can be enabled or disabled from the GUI.

> **Important:** Firewall and routing changes affect the Docker host.
> Always keep an alternative management path available while testing
> remote firewall rules.

------------------------------------------------------------------------

## 🗺 Interactive Network Topology

DRM builds its topology from live Docker networking information.

It can represent:

-   Docker networks
-   containers and endpoints
-   IPv4 and IPv6 addresses
-   published host ports
-   External / Internet paths
-   firewall state
-   relationships between containers and Docker networks

The path **External / Internet → published host port → container** can
be visualized directly. Firewall state can also be reflected in the
path, making access policies easier to understand than by reading
firewall tables alone.

------------------------------------------------------------------------

## 🌐 Routing Engine

DRM exposes the Linux host routing table and provides controls for
forwarding and DRM-managed static routes.

Features include:

-   IPv4 forwarding ON/OFF
-   IPv6 forwarding ON/OFF
-   current IPv4 and IPv6 Linux routing tables
-   connected Docker routes
-   WireGuard routes
-   IPv4 and IPv6 static destination routes
-   create, edit and delete DRM-managed static routes
-   gateway selection
-   outgoing interface selection
-   route metrics
-   persistence of DRM-managed routes

Example:

``` text
Family:      IPv6
Destination: 2001:db8:100::/64
Gateway:     fd42:8::2
Interface:   wg0
Metric:      100
```

This allows the Docker host to act as a router between:

``` text
Docker ↔ Docker
Docker ↔ LAN
Docker ↔ WireGuard
WireGuard ↔ LAN
WireGuard ↔ Internet
```

------------------------------------------------------------------------

## 🔐 WireGuard

WireGuard is managed as a native Linux interface in the host network
namespace.

DRM can:

-   create WireGuard interfaces
-   generate private/public keys
-   configure IPv4/IPv6 interface addresses
-   configure listen ports
-   enable IPv6 with suggested gateway/client addresses
-   add and remove peers
-   configure IPv4 and IPv6 peer tunnel addresses
-   separate endpoint address and endpoint port
-   configure server-side `AllowedIPs`
-   configure client routes
-   add DNS servers to generated client configurations
-   configure Persistent Keepalive
-   generate client `.conf` configurations
-   download WireGuard client configurations
-   generate QR codes for mobile clients

### Routing & Access Policy

WireGuard peers can be granted access only to selected resources.

``` text
WireGuard Client
       │
       ▼
      wg0
       │
       ├── Docker Network A    ✓
       ├── Docker Network B    ✗
       ├── LAN                 ✓
       └── Internet            ✓
```

Access policies can include:

-   selected IPv4/IPv6 Docker networks
-   LAN/custom CIDRs
-   IPv4 Internet access
-   IPv6 Internet access
-   full-tunnel operation

IPv4 Internet access can use MASQUERADE. IPv6 Internet access supports
normal routed IPv6 or optional NAT66 when required.

### Example generated client configuration

``` ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.8.0.2/32, fd42:8::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 172.20.0.0/16, fd20:20::/64, 192.168.1.0/24
PersistentKeepalive = 25
```

> Private keys and generated client configurations must be treated as
> sensitive data.

------------------------------------------------------------------------

## 🌍 Dual-stack IPv4 + IPv6

DRM supports dual-stack Docker and WireGuard environments.

-   Container views can display IPv4 and IPv6 addresses.
-   Docker network subnets and gateways are discovered for both address
    families.
-   WireGuard interfaces can operate IPv4-only or dual-stack.
-   WireGuard → Docker access policies can be generated for IPv4 and
    IPv6 Docker subnets.
-   IPv6 forwarding state is exposed in Routing.
-   DRM manages dedicated IPv6 WireGuard firewall paths.
-   Optional NAT66 can be used when a ULA WireGuard prefix has no
    upstream route.

A dual-stack full-tunnel client can use:

``` ini
AllowedIPs = 0.0.0.0/0, ::/0
```

For direct access between a WireGuard IPv6 prefix and a Docker IPv6
prefix, normal routed IPv6 can be used without NAT when the prefixes are
properly routed.

------------------------------------------------------------------------

## 👥 Authentication & Management

DRM includes built-in authentication and role-based access control.

  Role                Access
  ------------------- -----------------------------------------------------
  **Administrator**   Full system and user management
  **Operator**        Network, Firewall, Routing and WireGuard management
  **Viewer**          Read-only access

The Management section supports:

-   adding users
-   changing roles
-   resetting passwords
-   changing your own password
-   deleting users
-   protection of the built-in `admin` account

Authentication uses server-side sessions, HttpOnly cookies, CSRF
protection and login rate limiting. Passwords are stored as Argon2id
hashes.

------------------------------------------------------------------------

## ⚡ Quick Start

### Requirements

-   Linux Docker host
-   Docker Engine
-   Docker Compose plugin
-   permission to mount the Docker socket
-   `NET_ADMIN` capability for host networking operations

### 1. Clone DRM

``` bash
git clone https://github.com/RyVolodya/docker-router-manager.git /opt/drm
cd /opt/drm
```

### 2. Build and start

``` bash
docker compose up -d --build
```

### 3. Check status

``` bash
docker compose ps
```

### 4. Open the Web UI

``` text
http://DOCKER-HOST:8080
```

### 5. First login

``` text
Username: admin
Password: admin
```

**The default password must be changed after the first login.** New
passwords must contain at least 8 characters.

> 🔐 Change the bootstrap password immediately. For remote
> administration, use a trusted management network/VPN and HTTPS.

------------------------------------------------------------------------

## 🔄 Updating

Pull the latest source and rebuild:

``` bash
cd /opt/drm
git pull
docker compose down
docker compose up -d --build
```

Before upgrading a production installation, back up DRM persistent data
and review the release notes.

------------------------------------------------------------------------

## ⏪ Rollback

Releases are tagged, so you can return to an earlier DRM version.

Example:

``` bash
cd /opt/drm
docker compose down
git checkout v0.9.9
docker compose build --no-cache
docker compose up -d
```

Before rolling back across versions that change persistent configuration
formats, back up important DRM data.

------------------------------------------------------------------------

## 🏗 Architecture

DRM uses a containerized frontend/backend architecture while allowing
the backend to manage the host networking environment.

``` text
                       Browser
                          │
                          ▼
                 ┌────────────────┐
                 │  DRM Frontend  │
                 └───────┬────────┘
                         │
                         ▼
                 ┌────────────────┐
                 │  DRM Backend   │
                 └───────┬────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
     Docker Engine    Firewall       Routing
          │              │              │
          ▼              ▼              ▼
      Containers      iptables      Linux routes
      Networks        conntrack     WireGuard
```

The frontend and backend run as Docker containers.

The backend interacts with:

-   Docker Engine / Docker socket
-   Linux host network namespace
-   Linux routing table
-   `iptables` / `ip6tables`
-   `conntrack`
-   `ip`
-   `wg`

------------------------------------------------------------------------

## 🔒 Security Considerations

DRM is a **privileged network-management application**. The backend can
modify host firewall rules, routes and WireGuard interfaces.

The backend may require access to:

``` text
/var/run/docker.sock
NET_ADMIN
host network namespace
iptables
ip6tables
ip
wg
conntrack
```

This gives DRM significant control over the Docker host.

### Recommended deployment

``` text
Public Internet
      │
      X  Do not expose DRM directly
      │
Management LAN / VPN
      │
      ▼
Docker Router Manager
```

Recommended practices:

1.  Never expose the backend management API directly to the public
    Internet.
2.  Restrict GUI access to a trusted management LAN or VPN.
3.  Use HTTPS for remote administration.
4.  Set secure session cookies when DRM is deployed behind HTTPS.
5.  Never commit `.env`, private keys, WireGuard client configurations
    or DRM runtime data to Git.
6.  Protect access to the Docker socket.
7.  Keep an out-of-band or alternative SSH management path while testing
    firewall/routing policies.

------------------------------------------------------------------------

## 🎯 Use Cases

### Homelab

Manage the network path between Docker services, your LAN, WireGuard
clients and the Internet from one interface.

### Self-hosted servers

Control access to services such as Portainer, Pi-hole, monitoring
systems, web applications and databases without managing every rule
manually from the shell.

### Secure published ports

Instead of treating every published service as equally reachable, apply
source-based access policies to exposed ports.

### Docker router

Use the Linux Docker host as a gateway between Docker networks, LAN
networks and VPN clients.

### Remote access

Use WireGuard to reach selected Docker or LAN resources without directly
exposing those services to the Internet.

------------------------------------------------------------------------

## 📁 Project Structure

``` text
docker-router-manager/
├── backend/              # Management API and host network engine
├── frontend/             # React web interface
├── docker-compose.yml
├── README.md
└── docs/
    └── images/
        ├── drm-logo.svg
        ├── dashboard.png
        ├── topology.png
        ├── firewall.png
        ├── routing.png
        └── wireguard.png
```

------------------------------------------------------------------------

## 🛣 Roadmap

Potential future development areas:

-   [ ] VLAN interface management
-   [ ] Docker `macvlan` / `ipvlan` management
-   [ ] policy-based routing (`ip rule` / multiple routing tables)
-   [ ] nftables backend
-   [ ] OpenVPN integration
-   [ ] enhanced WireGuard site-to-site workflows
-   [ ] firewall logging and traffic counters
-   [ ] richer topology interaction
-   [ ] configuration backup / restore
-   [ ] audit log
-   [ ] HTTPS deployment workflow
-   [ ] monitoring and historical traffic graphs
-   [ ] network diagnostics

Have an idea? Open a **Feature Request** in GitHub Issues.

------------------------------------------------------------------------

## 🤝 Contributing

Issues, bug reports, feature requests and pull requests are welcome.

When reporting a networking issue, please include:

``` text
DRM version:
Linux distribution:
Docker version:
Docker Compose version:
IPv4/IPv6:
Steps to reproduce:
Relevant logs:
```

Useful diagnostic commands may include:

``` bash
docker compose ps
docker compose logs
docker version
docker compose version
ip addr
ip route
ip -6 route
sudo iptables -L -n -v
sudo ip6tables -L -n -v
```

> Remove passwords, private keys, public IP addresses and other
> sensitive information before posting logs or screenshots.

------------------------------------------------------------------------

## ⭐ Support Docker Router Manager

If DRM is useful to you, **give the repository a star**. It helps other
Docker, self-hosted and homelab users discover the project.

You can also help by:

-   reporting bugs
-   suggesting features
-   testing IPv4 and IPv6 environments
-   improving documentation
-   submitting pull requests
-   sharing the project with Docker and self-hosted communities

------------------------------------------------------------------------

## 📦 Release

Current release: **Docker Router Manager v0.10.0**

See [GitHub
Releases](https://github.com/RyVolodya/docker-router-manager/releases)
for release notes and previous versions.

------------------------------------------------------------------------

## 📄 License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

Copyright © 2026 Volodymyr Rybak.

------------------------------------------------------------------------

### Docker Router Manager

**Docker networking, routing, firewall and WireGuard management from one
web interface.**

[GitHub](https://github.com/RyVolodya/docker-router-manager) ·
[Releases](https://github.com/RyVolodya/docker-router-manager/releases)
· [Issues](https://github.com/RyVolodya/docker-router-manager/issues)

**If DRM helps you manage your Docker network, consider giving it a
⭐.**
