import { dockerGet } from "./dockerClient.js";
import type { DockerContainerSummary, DockerNetwork, DockerContainerInspect } from "./types.js";

export async function getDockerInfo() {
  return dockerGet<Record<string, unknown>>("/info");
}

export async function listContainers() {
  return dockerGet<DockerContainerSummary[]>("/containers/json?all=1");
}

export async function listNetworks() {
  const networks = await dockerGet<DockerNetwork[]>("/networks");
  const inspected = await Promise.all(
    networks.map((n) => dockerGet<DockerNetwork>(`/networks/${encodeURIComponent(n.Id)}`))
  );

  return inspected.map((network) => ({
    id: network.Id,
    name: network.Name,
    driver: network.Driver,
    scope: network.Scope,
    internal: network.Internal,
    attachable: network.Attachable,
    ingress: network.Ingress,
    ipv4Enabled: network.EnableIPv4 ?? true,
    ipv6Enabled: network.EnableIPv6 ?? false,
    subnets: (network.IPAM?.Config ?? []).map((config) => ({
      subnet: config.Subnet ?? null,
      gateway: config.Gateway ?? null,
      ipRange: config.IPRange ?? null
    })),
    containers: Object.entries(network.Containers ?? {}).map(([id, endpoint]) => ({
      id,
      name: endpoint.Name,
      endpointId: endpoint.EndpointID,
      macAddress: endpoint.MacAddress,
      ipv4Address: endpoint.IPv4Address,
      ipv6Address: endpoint.IPv6Address
    })),
    labels: network.Labels ?? {},
    options: network.Options ?? {},
    parent: network.Options?.parent ?? null,
    vlanId: network.Labels?.["com.drm.vlan-id"] ? Number(network.Labels["com.drm.vlan-id"]) : null,
    managedVlanInterface: network.Labels?.["com.drm.vlan-interface"] ?? null
  }));
}

export async function getTopology() {
  const [networks, containers] = await Promise.all([listNetworks(), listContainers()]);

  const inspectedContainers = await Promise.all(
    containers.map((container) =>
      dockerGet<DockerContainerInspect>(
        `/containers/${encodeURIComponent(container.Id)}/json`
      )
    )
  );

  const inspectById = new Map(
    inspectedContainers.map((container) => [container.Id, container])
  );

  return {
    generatedAt: new Date().toISOString(),
    networkCount: networks.length,
    containerCount: containers.length,
    runningContainerCount: containers.filter((c) => c.State === "running").length,
    networks,
    containers: containers.map((container) => {
      const inspected = inspectById.get(container.Id);
      const portMap = inspected?.NetworkSettings?.Ports ?? {};
      const exposedPorts = Object.keys(inspected?.Config?.ExposedPorts ?? {});

      const ports = Object.entries(portMap).map(([containerPort, bindings]) => ({
        containerPort,
        protocol: containerPort.split("/")[1] ?? "tcp",
        port: Number(containerPort.split("/")[0]),
        published: (bindings ?? []).map((binding) => ({
          hostIp: binding.HostIp,
          hostPort: Number(binding.HostPort)
        }))
      }));

      // Docker may expose a port without publishing it. Ensure those ports
      // still appear in the API and GUI.
      for (const exposed of exposedPorts) {
        if (!ports.some((port) => port.containerPort === exposed)) {
          ports.push({
            containerPort: exposed,
            protocol: exposed.split("/")[1] ?? "tcp",
            port: Number(exposed.split("/")[0]),
            published: []
          });
        }
      }

      ports.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));

      const labels = inspected?.Config?.Labels ?? container.Labels ?? {};
      const composeProject = labels["com.docker.compose.project"] ?? null;
      const composeService = labels["com.docker.compose.service"] ?? null;
      const composeContainerNumber = labels["com.docker.compose.container-number"] ?? null;

      return {
        id: container.Id,
        name: container.Names?.[0]?.replace(/^\//, "") ?? container.Id.slice(0, 12),
        image: container.Image,
        labels,
        compose: composeProject && composeService ? { project: composeProject, service: composeService, containerNumber: composeContainerNumber } : null,
        state: container.State,
        status: container.Status,
        ports,
        networks: Object.entries(container.NetworkSettings?.Networks ?? {}).map(
          ([networkName, attachment]) => ({
            networkName,
            networkId: attachment.NetworkID ?? null,
            ipv4Address: attachment.IPAddress ?? null,
            ipv4PrefixLen: attachment.IPPrefixLen ?? null,
            gateway: attachment.Gateway ?? null,
            ipv6Address: attachment.GlobalIPv6Address ?? null,
            macAddress: attachment.MacAddress ?? null
          })
        )
      };
    })
  };
}


type DockerStats = {
  read?: string;
  networks?: Record<string, { rx_bytes?: number; tx_bytes?: number; rx_packets?: number; tx_packets?: number; }>;
};

export async function getContainerNetworkStats() {
  const containers = await listContainers();
  const running = containers.filter((container) => container.State === "running");
  const stats = await Promise.all(running.map(async (container) => {
    const sample = await dockerGet<DockerStats>(`/containers/${encodeURIComponent(container.Id)}/stats?stream=false`);
    const networks = Object.entries(sample.networks ?? {}).map(([name, counters]) => ({
      name, rxBytes: counters.rx_bytes ?? 0, txBytes: counters.tx_bytes ?? 0, rxPackets: counters.rx_packets ?? 0, txPackets: counters.tx_packets ?? 0
    }));
    return {
      id: container.Id,
      name: container.Names?.[0]?.replace(/^\//, "") ?? container.Id.slice(0, 12),
      readAt: sample.read ?? new Date().toISOString(),
      rxBytes: networks.reduce((sum, n) => sum + n.rxBytes, 0),
      txBytes: networks.reduce((sum, n) => sum + n.txBytes, 0),
      rxPackets: networks.reduce((sum, n) => sum + n.rxPackets, 0),
      txPackets: networks.reduce((sum, n) => sum + n.txPackets, 0),
      networks
    };
  }));
  return { generatedAt: new Date().toISOString(), containers: stats.sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)) };
}
