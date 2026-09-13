import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dockerPost } from "./dockerClient.js";
import { listContainers, listNetworks } from "./dockerService.js";
import { refreshDynamicFirewallRules } from "./firewallService.js";
import { refreshNatRules } from "./natService.js";
import type { DockerContainerSummary } from "./types.js";

type ContainerIdentity = {
  kind: "compose" | "name";
  key: string;
  project?: string;
  service?: string;
  containerNumber?: string;
  name?: string;
};

type DesiredNetwork = {
  networkName: string;
  ipv4Address: string | null;
};

export type ContainerNetworkPolicy = {
  id: string;
  enabled: boolean;
  identity: ContainerIdentity;
  displayName: string;
  desiredNetworks: DesiredNetwork[];
  createdAt: string;
  updatedAt: string;
};

type PolicyRuntime = {
  state: "idle" | "waiting" | "applied" | "error";
  lastCheckedAt: string | null;
  lastAppliedAt: string | null;
  lastSeenContainerId: string | null;
  message: string | null;
};

const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const path = `${dataDir}/container-network-policies.json`;
const runtimes = new Map<string, PolicyRuntime>();
let writeLock: Promise<void> = Promise.resolve();
let reconcileRunning = false;
let timer: NodeJS.Timeout | null = null;

async function loadPolicies(): Promise<ContainerNetworkPolicy[]> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function savePolicies(value: ContainerNetworkPolicy[]) {
  await mkdir(dataDir, { recursive: true });
  const current = writeLock.catch(() => undefined).then(async () => {
    const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
    await rename(temp, path);
  });
  writeLock = current;
  await current;
}

function containerName(c: DockerContainerSummary) {
  return c.Names?.[0]?.replace(/^\//, "") ?? c.Id.slice(0, 12);
}

function identityFor(c: DockerContainerSummary): ContainerIdentity {
  const labels = c.Labels ?? {};
  const project = labels["com.docker.compose.project"]?.trim();
  const service = labels["com.docker.compose.service"]?.trim();
  const number = labels["com.docker.compose.container-number"]?.trim() || "1";
  if (project && service) {
    return {
      kind: "compose",
      key: `compose:${project}:${service}:${number}`,
      project,
      service,
      containerNumber: number
    };
  }
  const name = containerName(c);
  return { kind: "name", key: `name:${name}`, name };
}

function identityMatches(identity: ContainerIdentity, c: DockerContainerSummary) {
  return identityFor(c).key === identity.key;
}

function plainIp(value: string | null | undefined) {
  const v = String(value ?? "").split("/")[0]?.trim() ?? "";
  return v || null;
}

function policyRuntime(policyId: string): PolicyRuntime {
  return runtimes.get(policyId) ?? {
    state: "idle",
    lastCheckedAt: null,
    lastAppliedAt: null,
    lastSeenContainerId: null,
    message: null
  };
}

function withRuntime(policy: ContainerNetworkPolicy) {
  return { ...policy, runtime: policyRuntime(policy.id) };
}

export async function getContainerNetworkPolicy(containerId: string) {
  const containers = await listContainers();
  const container = containers.find(c => c.Id === containerId || containerName(c) === containerId);
  if (!container) throw new Error("Container not found");
  const identity = identityFor(container);
  const policy = (await loadPolicies()).find(p => p.identity.key === identity.key);
  return {
    supportedIdentity: identity,
    policy: policy ? withRuntime(policy) : null
  };
}

export async function saveCurrentContainerNetworkPolicy(containerId: string) {
  const [containers, networks] = await Promise.all([listContainers(), listNetworks()]);
  const container = containers.find(c => c.Id === containerId || containerName(c) === containerId);
  if (!container) throw new Error("Container not found");
  const identity = identityFor(container);
  const currentAttachments = container.NetworkSettings?.Networks ?? {};
  const desiredNetworks: DesiredNetwork[] = Object.entries(currentAttachments)
    .filter(([name]) => {
      const network = networks.find(n => n.name === name);
      return Boolean(network && !["host", "none"].includes(network.name) && !["host", "null"].includes(network.driver));
    })
    .map(([networkName, attachment]) => ({
      networkName,
      ipv4Address: plainIp(attachment.IPAddress)
    }))
    .sort((a,b) => a.networkName.localeCompare(b.networkName));

  const policies = await loadPolicies();
  const now = new Date().toISOString();
  const existing = policies.find(p => p.identity.key === identity.key);
  if (existing) {
    existing.enabled = true;
    existing.displayName = containerName(container);
    existing.desiredNetworks = desiredNetworks;
    existing.updatedAt = now;
    await savePolicies(policies);
    return withRuntime(existing);
  }

  const policy: ContainerNetworkPolicy = {
    id: randomUUID(), enabled: true, identity, displayName: containerName(container),
    desiredNetworks, createdAt: now, updatedAt: now
  };
  policies.push(policy);
  await savePolicies(policies);
  runtimes.set(policy.id, {
    state: "idle", lastCheckedAt: null, lastAppliedAt: null,
    lastSeenContainerId: container.Id, message: "Persistent network policy saved"
  });
  return withRuntime(policy);
}

export async function deleteContainerNetworkPolicy(containerId: string) {
  const containers = await listContainers();
  const container = containers.find(c => c.Id === containerId || containerName(c) === containerId);
  if (!container) throw new Error("Container not found");
  const key = identityFor(container).key;
  const policies = await loadPolicies();
  const removed = policies.find(p => p.identity.key === key);
  const next = policies.filter(p => p.identity.key !== key);
  if (removed) runtimes.delete(removed.id);
  await savePolicies(next);
}

async function reconnectWithIp(network: any, containerId: string, desiredIp: string, currentIp: string | null) {
  await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/disconnect`, { Container: containerId, Force: false });
  try {
    await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`, {
      Container: containerId,
      EndpointConfig: { IPAMConfig: { IPv4Address: desiredIp } }
    });
  } catch (error) {
    try {
      const rollback = currentIp ? { IPAMConfig: { IPv4Address: currentIp } } : {};
      await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`, {
        Container: containerId, EndpointConfig: rollback
      });
    } catch {}
    throw error;
  }
}

async function reconcilePolicy(policy: ContainerNetworkPolicy, containers: DockerContainerSummary[], networks: any[]):Promise<boolean> {
  const now = new Date().toISOString();
  const runtime = policyRuntime(policy.id);
  runtime.lastCheckedAt = now;
  const container = containers.find(c => identityMatches(policy.identity, c));
  if (!container) {
    runtime.state = "waiting";
    runtime.lastSeenContainerId = null;
    runtime.message = "Waiting for container recreation";
    runtimes.set(policy.id, runtime);
    return false;
  }

  runtime.lastSeenContainerId = container.Id;
  let changed = false;
  const desiredNames = new Set(policy.desiredNetworks.map(n => n.networkName));

  try {
    // Safety rule: ensure every desired network exists before removing Compose-provided networks.
    const missing = policy.desiredNetworks.filter(d => !networks.some(n => n.name === d.networkName));
    if (missing.length) {
      runtime.state = "waiting";
      runtime.message = `Waiting for Docker network: ${missing.map(x=>x.networkName).join(", ")}`;
      runtimes.set(policy.id, runtime);
      return false;
    }

    // First connect/fix every desired network.
    for (const desired of policy.desiredNetworks) {
      const network = networks.find(n => n.name === desired.networkName);
      if (!network) continue;
      const endpoint = network.containers.find((e:any) => e.id === container.Id);
      if (!endpoint) {
        const endpointConfig = desired.ipv4Address
          ? { IPAMConfig: { IPv4Address: desired.ipv4Address } }
          : {};
        await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`, {
          Container: container.Id, EndpointConfig: endpointConfig
        });
        changed = true;
      } else if (desired.ipv4Address) {
        const currentIp = plainIp(endpoint.ipv4Address);
        if (currentIp !== desired.ipv4Address) {
          await reconnectWithIp(network, container.Id, desired.ipv4Address, currentIp);
          changed = true;
        }
      }
    }

    // Only after desired connectivity is ready, remove networks not present in the persistent snapshot.
    const currentNetworkNames = Object.keys(container.NetworkSettings?.Networks ?? {});
    for (const name of currentNetworkNames) {
      if (desiredNames.has(name)) continue;
      const network = networks.find(n => n.name === name);
      if (!network || ["host","none"].includes(network.name) || ["host","null"].includes(network.driver)) continue;
      await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/disconnect`, {
        Container: container.Id, Force: false
      });
      changed = true;
    }

    runtime.state = "applied";
    runtime.message = changed ? "Persistent network configuration reapplied" : "Persistent network configuration is in sync";
    if (changed) runtime.lastAppliedAt = now;
  } catch (error) {
    runtime.state = "error";
    runtime.message = error instanceof Error ? error.message : String(error);
  }
  runtimes.set(policy.id, runtime);
  return changed;
}

export async function reconcileContainerNetworkPolicies() {
  if (reconcileRunning) return;
  reconcileRunning = true;
  try {
    const policies = (await loadPolicies()).filter(p => p.enabled);
    if (!policies.length) return;
    const [containers, networks] = await Promise.all([listContainers(), listNetworks()]);
    let changed=false;
    for (const policy of policies) changed=(await reconcilePolicy(policy, containers, networks))||changed;
    if(changed){
      try{await refreshDynamicFirewallRules(true);}
      catch(error){console.warn("DRM firewall refresh after persistent network policy failed",error);}
      try{await refreshNatRules(true);}
      catch(error){console.warn("DRM NAT refresh after persistent network policy failed",error);}
    }
  } finally {
    reconcileRunning = false;
  }
}

export function startContainerNetworkPolicyReconciler() {
  if (timer) return;
  const intervalMs = Math.max(3000, Number(process.env.DRM_NETWORK_POLICY_INTERVAL_MS ?? 5000));
  void reconcileContainerNetworkPolicies().catch(e => console.warn("DRM persistent network reconcile warning", e));
  timer = setInterval(() => {
    void reconcileContainerNetworkPolicies().catch(e => console.warn("DRM persistent network reconcile warning", e));
  }, intervalMs);
  timer.unref?.();
}
