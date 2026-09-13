import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { getTopology, listNetworks } from "./dockerService.js";
import { addNatManagedFirewallRule, removeNatManagedFirewallRule } from "./firewallService.js";
import type { AccessSelector } from "./types.js";
import { findVrfByInterface } from "./vrfService.js";

const execFileAsync = promisify(execFile);
const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const configPath = `${dataDir}/nat.json`;
const preChain = "DRM-NAT-PREROUTING";
const postChain = "DRM-NAT-POSTROUTING";

type NatProtocol = "tcp" | "udp";
type NatSourceType = "custom" | "docker-network" | "container" | "wireguard";

type NatSourceSelector = {
  type: NatSourceType;
  refId?: string | null;
  refName?: string | null;
  value?: string | null;
  label?: string | null;
  composeProject?: string | null;
  composeService?: string | null;
  composeContainerNumber?: string | null;
};

type NatContainerDestination = {
  kind: "container";
  refId: string;
  refName?: string | null;
  label?: string | null;
  composeProject?: string | null;
  composeService?: string | null;
  composeContainerNumber?: string | null;
  networkName?: string | null;
};

type NatIpDestination = { kind: "ip"; ip: string };

type BaseRule = {
  id: string;
  enabled: boolean;
  description: string;
  createdAt: string;
  updatedAt: string;
};

export type NatOutboundRule = BaseRule & {
  type: "masquerade" | "snat";
  source: NatSourceSelector;
  outInterface: string;
  toSourceIp: string | null;
  policyRoute: boolean;
  routeTable: number;
};

export type NatDnatRule = BaseRule & {
  type: "dnat";
  inInterface: string;
  externalIp: string;
  protocol: NatProtocol;
  externalPort: number;
  sourceCidr: string;
  destination: NatContainerDestination | NatIpDestination;
  internalPort: number;
  createFirewallRule: boolean;
};

export type NatRule = NatOutboundRule | NatDnatRule;

type NatConfig = { rules: NatRule[]; updatedAt: string };

type ResolvedRule = {
  resolved: boolean;
  message: string;
  source: string[];
  destination: string[];
};

let reconcileTimer: NodeJS.Timeout | null = null;
let fingerprint = "";
let refreshing = false;
let lastRefreshAt: string | null = null;
let lastError: string | null = null;

async function iptablesNat(args: string[]) {
  return execFileAsync("iptables", ["-w", "5", "-t", "nat", ...args], { maxBuffer: 1024 * 1024 });
}
async function ip(args:string[]){
  return execFileAsync("ip", args, {maxBuffer:1024*1024});
}

type NatRuleOwner = "DRM" | "Docker" | "System-External";
type HostNatRule = {
  id:string;
  chain:string;
  position:number;
  packets:number;
  bytes:number;
  protocol:string;
  source:string;
  destination:string;
  inInterface:string|null;
  outInterface:string|null;
  target:string;
  sourcePort:string|null;
  destinationPort:string|null;
  toDestination:string|null;
  toSource:string|null;
  owner:NatRuleOwner;
  raw:string;
};

function shellTokens(line:string){
  const tokens:string[]=[];
  const re=/"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)/g;
  let match:RegExpExecArray|null;
  while((match=re.exec(line)))tokens.push((match[1]??match[2]??match[3]??"").replace(/\\"/g,'"'));
  return tokens;
}
function tokenValue(tokens:string[],...keys:string[]){
  for(const key of keys){
    const i=tokens.indexOf(key);
    if(i>=0&&i+1<tokens.length)return tokens[i+1];
  }
  return null;
}
function natOwner(chain:string,tokens:string[]):NatRuleOwner{
  const jump=tokenValue(tokens,"-j","--jump")??"";
  const comment=tokenValue(tokens,"--comment")??"";
  if(chain.startsWith("DRM-NAT-")||jump.startsWith("DRM-NAT-")||comment.startsWith("DRM:")||comment.includes("docker-router-manager"))return "DRM";
  if(chain==="DOCKER"||chain.startsWith("DOCKER-")||jump==="DOCKER"||jump.startsWith("DOCKER-")||comment.toLowerCase().includes("docker"))return "Docker";
  return "System-External";
}
function cleanIface(value:string|null){return value&&value!=="*" ? value : null;}

export async function listAllNatRules():Promise<HostNatRule[]>{
  const {stdout}=await execFileAsync("iptables-save",["-t","nat","-c"],{maxBuffer:4*1024*1024});
  const positions=new Map<string,number>();
  const rules:HostNatRule[]=[];
  for(const rawLine of stdout.split(/\r?\n/)){
    const line=rawLine.trim();
    if(!line.startsWith("["))continue;
    const counterMatch=line.match(/^\[(\d+):(\d+)\]\s+(.+)$/);
    if(!counterMatch)continue;
    const packets=Number(counterMatch[1]),bytes=Number(counterMatch[2]),spec=counterMatch[3];
    const tokens=shellTokens(spec);
    if(tokens[0]!=="-A"||!tokens[1])continue;
    const chain=tokens[1];
    const position=(positions.get(chain)??0)+1;
    positions.set(chain,position);
    const protocol=tokenValue(tokens,"-p","--protocol")??"all";
    const source=tokenValue(tokens,"-s","--source")??"0.0.0.0/0";
    const destination=tokenValue(tokens,"-d","--destination")??"0.0.0.0/0";
    const target=tokenValue(tokens,"-j","--jump")??"";
    const sourcePort=tokenValue(tokens,"--sport","--source-port","--sports");
    const destinationPort=tokenValue(tokens,"--dport","--destination-port","--dports");
    const toDestination=tokenValue(tokens,"--to-destination");
    const toSource=tokenValue(tokens,"--to-source");
    rules.push({
      id:`${chain}:${position}`,
      chain,position,packets,bytes,protocol,source,destination,
      inInterface:cleanIface(tokenValue(tokens,"-i","--in-interface")),
      outInterface:cleanIface(tokenValue(tokens,"-o","--out-interface")),
      target,sourcePort,destinationPort,toDestination,toSource,
      owner:natOwner(chain,tokens),raw:spec
    });
  }
  return rules;
}

async function readConfig(): Promise<NatConfig> {
  await mkdir(dataDir, { recursive: true });
  try {
    const parsed = JSON.parse(await readFile(configPath, "utf8")) as NatConfig;
    return { rules: Array.isArray(parsed.rules) ? parsed.rules : [], updatedAt: parsed.updatedAt ?? new Date(0).toISOString() };
  } catch {
    return { rules: [], updatedAt: new Date().toISOString() };
  }
}

async function saveConfig(config: NatConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(configPath, JSON.stringify(config, null, 2));
}

function validPort(value: unknown, label: string) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${label} must be 1..65535`);
  return port;
}

function validIpv4(value: string, label: string) {
  if (isIP(value) !== 4) throw new Error(`${label} must be an IPv4 address`);
  return value;
}

function validIpv4Cidr(value: string, label: string) {
  const raw = String(value || "").trim();
  const [ip, prefixRaw] = raw.split("/");
  const prefix = Number(prefixRaw);
  if (isIP(ip) !== 4 || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error(`${label} must be a valid IPv4 CIDR`);
  return raw;
}

function normalizeSource(input: any): NatSourceSelector {
  const type = String(input?.type ?? "custom") as NatSourceType;
  if (!(["custom", "docker-network", "container", "wireguard"] as string[]).includes(type)) throw new Error("Unsupported NAT source type");
  const selector: NatSourceSelector = {
    type,
    refId: input?.refId ? String(input.refId) : null,
    refName: input?.refName ? String(input.refName).trim() : null,
    value: input?.value ? String(input.value).trim() : null,
    label: input?.label ? String(input.label).trim() : null,
    composeProject: input?.composeProject ? String(input.composeProject).trim() : null,
    composeService: input?.composeService ? String(input.composeService).trim() : null,
    composeContainerNumber: input?.composeContainerNumber ? String(input.composeContainerNumber).trim() : null
  };
  if (selector.type === "custom") validIpv4Cidr(selector.value ?? "", "Source");
  if (selector.type === "wireguard") validIpv4Cidr(selector.value ?? "", "WireGuard source");
  if (["docker-network", "container"].includes(selector.type) && !selector.refId && !selector.refName) throw new Error("Selected NAT source no longer exists");
  return selector;
}

async function enrichSource(selector: NatSourceSelector): Promise<NatSourceSelector> {
  if (selector.type === "docker-network") {
    const networks = await listNetworks();
    const n = networks.find((x: any) => x.id === selector.refId || x.name === selector.refName || x.name === selector.label);
    if (!n) throw new Error("Selected Docker network no longer exists");
    return { ...selector, refId: n.id, refName: n.name, label: n.name };
  }
  if (selector.type === "container") {
    const topology = await getTopology();
    const c = topology.containers.find((x: any) => x.id === selector.refId || x.name === selector.refName || x.name === selector.label);
    if (!c) throw new Error("Selected container no longer exists");
    return {
      ...selector,
      refId: c.id,
      refName: c.name,
      label: c.name,
      composeProject: c.compose?.project ?? null,
      composeService: c.compose?.service ?? null,
      composeContainerNumber: c.compose?.containerNumber ?? null
    };
  }
  return selector;
}

async function normalizeDestination(input: any): Promise<NatContainerDestination | NatIpDestination> {
  const kind = String(input?.kind ?? "container");
  if (kind === "ip") return { kind: "ip", ip: validIpv4(String(input?.ip ?? "").trim(), "Destination IP") };
  if (kind !== "container") throw new Error("Unsupported DNAT destination type");
  const topology = await getTopology();
  const c = topology.containers.find((x: any) => x.id === input?.refId || x.name === input?.refName || x.name === input?.label);
  if (!c) throw new Error("Selected destination container no longer exists");
  return {
    kind: "container",
    refId: c.id,
    refName: c.name,
    label: c.name,
    composeProject: c.compose?.project ?? null,
    composeService: c.compose?.service ?? null,
    composeContainerNumber: c.compose?.containerNumber ?? null,
    networkName: input?.networkName ? String(input.networkName) : null
  };
}

async function hostInterfaces() {
  const { stdout } = await execFileAsync("ip", ["-j", "-4", "address", "show"], { maxBuffer: 1024 * 1024 });
  const interfaces = (JSON.parse(stdout) as any[])
    .filter(x => x.ifname && x.ifname !== "lo")
    .map(x => ({
      name: String(x.ifname),
      state: String(x.operstate ?? "UNKNOWN"),
      addresses: (x.addr_info ?? []).filter((a: any) => a.family === "inet").map((a: any) => `${a.local}/${a.prefixlen}`),
      ips: (x.addr_info ?? []).filter((a: any) => a.family === "inet").map((a: any) => String(a.local))
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  let defaultWanInterface: string | null = null;
  let defaultRoutes:any[]=[];
  try {
    const route = await execFileAsync("ip", ["-j", "-4", "route", "show", "default"], { maxBuffer: 1024 * 1024 });
    defaultRoutes=JSON.parse(route.stdout) as any[];
    defaultWanInterface = defaultRoutes[0]?.dev ?? null;
  } catch {}
  return { interfaces, defaultWanInterface, defaultRoutes };
}

function composeMatches(selector: { composeProject?: string | null; composeService?: string | null; composeContainerNumber?: string | null }, c: any) {
  return Boolean(selector.composeProject && selector.composeService &&
    c.compose?.project === selector.composeProject &&
    c.compose?.service === selector.composeService &&
    String(c.compose?.containerNumber ?? "1") === String(selector.composeContainerNumber ?? "1"));
}

async function resolveSource(selector: NatSourceSelector, networks: any[], topology: any): Promise<string[]> {
  if (selector.type === "custom" || selector.type === "wireguard") return selector.value ? [selector.value] : [];
  if (selector.type === "docker-network") {
    const n = networks.find((x: any) => x.id === selector.refId || (selector.refName && x.name === selector.refName));
    return n ? (n.subnets ?? []).map((x: any) => x.subnet).filter((x: any) => typeof x === "string" && x.includes(".")) : [];
  }
  const c = topology.containers.find((x: any) => x.id === selector.refId || composeMatches(selector, x) || (selector.refName && x.name === selector.refName));
  if (!c) return [];
  return [...new Set((c.networks ?? []).map((n: any) => n.ipv4Address).filter(Boolean).map((ip: string) => `${ip}/32`))] as string[];
}

async function resolveDestination(destination: NatContainerDestination | NatIpDestination, topology: any): Promise<string[]> {
  if (destination.kind === "ip") return [destination.ip];
  const c = topology.containers.find((x: any) => x.id === destination.refId || composeMatches(destination, x) || (destination.refName && x.name === destination.refName));
  if (!c) return [];
  const networks = destination.networkName ? (c.networks ?? []).filter((n: any) => n.networkName === destination.networkName) : (c.networks ?? []);
  return [...new Set(networks.map((n: any) => n.ipv4Address).filter(Boolean))] as string[];
}

async function resolveRule(rule: NatRule, networks: any[], topology: any): Promise<ResolvedRule> {
  if (rule.type === "dnat") {
    const destination = await resolveDestination(rule.destination, topology);
    return {
      resolved: destination.length > 0,
      message: destination.length ? "Resolved from current Docker/host state" : "Destination is currently unavailable",
      source: [rule.sourceCidr],
      destination
    };
  }
  const source = await resolveSource(rule.source, networks, topology);
  return {
    resolved: source.length > 0,
    message: source.length ? "Resolved from current Docker/host state" : "Source is currently unavailable",
    source,
    destination: rule.toSourceIp ? [rule.toSourceIp] : []
  };
}

async function chainExists(name: string) {
  try { await iptablesNat(["-n", "-L", name]); return true; } catch { return false; }
}

async function ensureChain(name: string, parent: "PREROUTING" | "POSTROUTING") {
  if (!(await chainExists(name))) await iptablesNat(["-N", name]);
  try { await iptablesNat(["-C", parent, "-j", name]); }
  catch { await iptablesNat(["-I", parent, "1", "-j", name]); }
}


function defaultRouteForInterface(defaultRoutes:any[],name:string){
  return defaultRoutes.find((r:any)=>r.dev===name)??null;
}

async function cleanupPolicyRoute(rule:NatOutboundRule){
  const priority=Number(rule.routeTable);
  if(!Number.isInteger(priority)||priority<1)return;
  // routeTable remains the DRM-owned policy-rule priority/id. Never flush a VRF table.
  try{
    const {stdout}=await ip(["-j","-4","rule","show"]);
    const rules=JSON.parse(stdout) as any[];
    for(const r of rules.filter((x:any)=>Number(x.priority)===priority)){
      try{await ip(["-4","rule","del","priority",String(priority)])}catch{}
    }
  }catch{}
  const vrf=await findVrfByInterface(rule.outInterface);
  if(!vrf){try{await ip(["-4","route","flush","table",String(rule.routeTable)])}catch{}}
}

async function installPolicyRoute(rule:NatOutboundRule,sources:string[],defaultRoutes:any[]){
  await cleanupPolicyRoute(rule);
  if(!rule.enabled||!rule.policyRoute||sources.length===0)return;
  const vrf=await findVrfByInterface(rule.outInterface);
  const table=String(vrf?.table??rule.routeTable);
  let route:any=null;
  if(vrf){
    try{
      const {stdout}=await execFileAsync("ip",["-j","-4","route","show","table",table,"default"],{maxBuffer:1024*1024});
      const rows=JSON.parse(stdout) as any[];
      route=rows.find((r:any)=>r.dev===rule.outInterface)??rows[0]??null;
    }catch{}
  } else route=defaultRouteForInterface(defaultRoutes,rule.outInterface);
  if(!route)throw new Error(`No IPv4 default route is available through ${rule.outInterface}${vrf?` in VRF ${vrf.name} table ${vrf.table}`:""}`);
  if(!vrf){
    const routeArgs=["-4","route","replace","table",table,"default"];
    if(route.gateway)routeArgs.push("via",String(route.gateway));
    routeArgs.push("dev",rule.outInterface);
    if(route.gateway)routeArgs.push("onlink");
    await ip(routeArgs);
  }
  for(const source of sources)await ip(["-4","rule","add","priority",String(rule.routeTable),"from",source,"lookup",table]);
}

async function render(config: NatConfig) {
  await ensureChain(preChain, "PREROUTING");
  await ensureChain(postChain, "POSTROUTING");
  await iptablesNat(["-F", preChain]);
  await iptablesNat(["-F", postChain]);
  const [networks, topology, hosts] = await Promise.all([listNetworks(), getTopology(), hostInterfaces()]);
  for(const rule of config.rules.filter((r):r is NatOutboundRule=>r.type!=="dnat"))await cleanupPolicyRoute(rule);

  for (const rule of config.rules.filter(r => r.enabled)) {
    const resolved = await resolveRule(rule, networks, topology);
    if (!resolved.resolved) continue;
    if (rule.type === "dnat") {
      for (const targetIp of resolved.destination) {
        const args = ["-A", preChain];
        if (rule.inInterface && rule.inInterface !== "*") args.push("-i", rule.inInterface);
        if (rule.externalIp && rule.externalIp !== "0.0.0.0") args.push("-d", rule.externalIp);
        if (rule.sourceCidr !== "0.0.0.0/0") args.push("-s", rule.sourceCidr);
        args.push("-p", rule.protocol, "--dport", String(rule.externalPort), "-m", "comment", "--comment", `DRM:nat:${rule.id}`, "-j", "DNAT", "--to-destination", `${targetIp}:${rule.internalPort}`);
        await iptablesNat(args);
        break; // one deterministic destination per DNAT rule
      }
      continue;
    }
    await installPolicyRoute(rule,resolved.source,hosts.defaultRoutes);
    for (const sourceCidr of resolved.source) {
      const args = ["-A", postChain, "-s", sourceCidr, "-o", rule.outInterface, "-m", "comment", "--comment", `DRM:nat:${rule.id}`];
      if (rule.type === "masquerade") args.push("-j", "MASQUERADE");
      else args.push("-j", "SNAT", "--to-source", rule.toSourceIp!);
      await iptablesNat(args);
    }
  }
}

async function validateInterface(name: string, ip?: string | null) {
  const refs = await hostInterfaces();
  const iface = refs.interfaces.find(x => x.name === name);
  if (!iface) throw new Error(`Host interface ${name} does not exist`);
  if (ip && ip !== "0.0.0.0" && !iface.ips.includes(ip)) throw new Error(`${ip} is not configured on ${name}`);
  return iface;
}

async function validateDnatConflict(rule: NatDnatRule, ignoreId?: string) {
  const config = await readConfig();
  const conflict = config.rules.find(r => r.id !== ignoreId && r.enabled && r.type === "dnat" && r.protocol === rule.protocol && r.externalPort === rule.externalPort && r.inInterface === rule.inInterface && (r.externalIp === rule.externalIp || r.externalIp === "0.0.0.0" || rule.externalIp === "0.0.0.0"));
  if (conflict) throw new Error(`DNAT conflict with existing rule ${conflict.description || conflict.id}`);

  const topology = await getTopology();
  const dockerConflict = topology.containers.flatMap((c: any) => (c.ports ?? []).flatMap((p: any) => (p.published ?? []).map((b: any) => ({ c, p, b })))).find((x: any) =>
    x.p.protocol === rule.protocol && Number(x.b.hostPort) === rule.externalPort && (x.b.hostIp === "0.0.0.0" || rule.externalIp === "0.0.0.0" || x.b.hostIp === rule.externalIp)
  );
  if (dockerConflict) throw new Error(`External ${rule.protocol.toUpperCase()} port ${rule.externalPort} is already published by Docker container ${dockerConflict.c.name}`);

  try{
    const {stdout}=await execFileAsync("ss",["-H","-lntu","-n"],{maxBuffer:1024*1024});
    for(const line of stdout.split("\n").filter(Boolean)){
      const fields=line.trim().split(/\s+/);
      const proto=fields[0]?.startsWith("tcp")?"tcp":fields[0]?.startsWith("udp")?"udp":null;
      if(proto!==rule.protocol)continue;
      const local=fields[4]??"";
      const match=local.match(/(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
      if(!match)continue;
      const listenIp=(match[1]??match[2]??"").replace(/^\*$/,rule.externalIp);
      const listenPort=Number(match[3]);
      if(listenPort!==rule.externalPort)continue;
      if(listenIp==="0.0.0.0"||listenIp==="*"||rule.externalIp==="0.0.0.0"||listenIp===rule.externalIp){
        throw new Error(`External ${rule.protocol.toUpperCase()} port ${rule.externalPort} is already used by a host service on ${listenIp||"*"}`);
      }
    }
  }catch(error){
    if(error instanceof Error&&error.message.startsWith("External "))throw error;
  }
}


function routeTableFromId(id:string){
  let hash=2166136261;
  for(const ch of id){hash^=ch.charCodeAt(0);hash=Math.imul(hash,16777619)>>>0;}
  return 28000+(hash%900);
}

async function normalizeRule(input: any, current?: NatRule): Promise<NatRule> {
  const now = new Date().toISOString();
  const type = String(input?.type ?? current?.type ?? "masquerade");
  const base = {
    id: current?.id ?? randomUUID(),
    enabled: input?.enabled === undefined ? (current?.enabled ?? true) : Boolean(input.enabled),
    description: input?.description === undefined ? (current?.description ?? "") : String(input.description).trim(),
    createdAt: current?.createdAt ?? now,
    updatedAt: now
  };

  if (type === "masquerade" || type === "snat") {
    const source = await enrichSource(normalizeSource(input?.source ?? (current && current.type !== "dnat" ? current.source : null)));
    const outInterface = String(input?.outInterface ?? (current && current.type !== "dnat" ? current.outInterface : "")).trim();
    if (!outInterface) throw new Error("WAN/output interface is required");
    const toSourceIp = type === "snat" ? validIpv4(String(input?.toSourceIp ?? (current && current.type === "snat" ? current.toSourceIp ?? "" : "")).trim(), "SNAT source IP") : null;
    await validateInterface(outInterface, toSourceIp);
    const previous=current&&current.type!=="dnat"?current:null;
    const routeTable=Number(input?.routeTable??previous?.routeTable??routeTableFromId(base.id));
    const policyRoute=input?.policyRoute===undefined?(previous?.policyRoute??true):Boolean(input.policyRoute);
    return { ...base, type, source, outInterface, toSourceIp, policyRoute, routeTable };
  }

  if (type !== "dnat") throw new Error("Unsupported NAT rule type");
  const existing = current?.type === "dnat" ? current : null;
  const inInterface = String(input?.inInterface ?? existing?.inInterface ?? "").trim();
  if (!inInterface) throw new Error("WAN/input interface is required");
  const externalIp = String(input?.externalIp ?? existing?.externalIp ?? "0.0.0.0").trim() || "0.0.0.0";
  if (externalIp !== "0.0.0.0") validIpv4(externalIp, "External IP");
  await validateInterface(inInterface, externalIp);
  const protocol = String(input?.protocol ?? existing?.protocol ?? "tcp") as NatProtocol;
  if (!(["tcp", "udp"] as string[]).includes(protocol)) throw new Error("Protocol must be TCP or UDP");
  const sourceCidr = validIpv4Cidr(String(input?.sourceCidr ?? existing?.sourceCidr ?? "0.0.0.0/0"), "Source CIDR");
  const rule: NatDnatRule = {
    ...base,
    type: "dnat",
    inInterface,
    externalIp,
    protocol,
    externalPort: validPort(input?.externalPort ?? existing?.externalPort, "External port"),
    sourceCidr,
    destination: await normalizeDestination(input?.destination ?? existing?.destination),
    internalPort: validPort(input?.internalPort ?? existing?.internalPort, "Internal port"),
    createFirewallRule: input?.createFirewallRule === undefined ? (existing?.createFirewallRule ?? false) : Boolean(input.createFirewallRule)
  };
  await validateDnatConflict(rule, current?.id);
  return rule;
}

function destinationAsFirewallSelector(rule: NatDnatRule): AccessSelector | null {
  if (rule.destination.kind !== "container") return null;
  return {
    type: "container",
    refId: rule.destination.refId,
    refName: rule.destination.refName ?? null,
    label: rule.destination.label ?? rule.destination.refName ?? null,
    composeProject: rule.destination.composeProject ?? null,
    composeService: rule.destination.composeService ?? null,
    composeContainerNumber: rule.destination.composeContainerNumber ?? null
  };
}

async function syncFirewall(rule: NatRule, replacing = false) {
  if (replacing) await removeNatManagedFirewallRule(rule.id);
  if (rule.type !== "dnat" || !rule.createFirewallRule || !rule.enabled || rule.destination.kind !== "container") return;
  const destination = destinationAsFirewallSelector(rule);
  if (!destination) return;
  const containerDestination = rule.destination;
  await addNatManagedFirewallRule(rule.id, {
    sourceCidr: rule.sourceCidr,
    destination,
    protocol: rule.protocol,
    destinationPort: rule.internalPort,
    description: `NAT ${rule.externalIp === "0.0.0.0" ? "*" : rule.externalIp}:${rule.externalPort} → ${containerDestination.label ?? containerDestination.refName ?? "container"}:${rule.internalPort}`
  });
}

function ensureUniqueRouteTable(rule:NatRule,config:NatConfig,ignoreId?:string){
  if(rule.type==="dnat")return;
  const used=new Set(config.rules.filter((r):r is NatOutboundRule=>r.type!=="dnat"&&r.id!==ignoreId).map(r=>Number(r.routeTable)));
  let table=Number(rule.routeTable);
  if(!Number.isInteger(table)||table<28000||table>28999)table=routeTableFromId(rule.id);
  for(let i=0;i<1000&&used.has(table);i++)table=28000+((table-28000+1)%1000);
  if(used.has(table))throw new Error("No free DRM policy-routing table is available");
  rule.routeTable=table;
}

export async function addNatRule(input: any) {
  const rule = await normalizeRule(input);
  const config = await readConfig();
  ensureUniqueRouteTable(rule,config);
  config.rules.push(rule);
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  await render(config);
  await syncFirewall(rule);
  fingerprint = "";
  return rule;
}

export async function updateNatRule(id: string, input: any) {
  const config = await readConfig();
  const index = config.rules.findIndex(r => r.id === id);
  if (index < 0) throw new Error("NAT rule not found");
  const old = config.rules[index];
  const mergedInput = { ...old, ...input };
  const next = await normalizeRule(mergedInput, old);
  ensureUniqueRouteTable(next,config,id);
  if(old.type!=="dnat"&&(next.type==="dnat"||old.routeTable!==next.routeTable))await cleanupPolicyRoute(old);
  config.rules[index] = next;
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  await render(config);
  await removeNatManagedFirewallRule(id);
  await syncFirewall(next);
  fingerprint = "";
  return next;
}

export async function deleteNatRule(id: string) {
  const config = await readConfig();
  const existing=config.rules.find(r=>r.id===id);
  if(existing&&existing.type!=="dnat")await cleanupPolicyRoute(existing);
  const before = config.rules.length;
  config.rules = config.rules.filter(r => r.id !== id);
  if (config.rules.length === before) throw new Error("NAT rule not found");
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  await render(config);
  await removeNatManagedFirewallRule(id);
  fingerprint = "";
}

async function currentFingerprint(config: NatConfig) {
  const [networks, topology, hosts] = await Promise.all([listNetworks(), getTopology(), hostInterfaces()]);
  const rows: any[] = [];
  for (const rule of config.rules.filter(r => r.enabled)) rows.push([rule.id, await resolveRule(rule, networks, topology)]);
  rows.push(["interfaces", hosts.interfaces, hosts.defaultRoutes]);
  return JSON.stringify(rows);
}

export async function refreshNatRules(force = false) {
  if (refreshing) return { changed: false, skipped: true, lastRefreshAt, lastError };
  refreshing = true;
  try {
    const config = await readConfig();
    const nextFingerprint = await currentFingerprint(config);
    if (!force && nextFingerprint === fingerprint) return { changed: false, skipped: false, lastRefreshAt, lastError: null };
    await render(config);
    fingerprint = nextFingerprint;
    lastRefreshAt = new Date().toISOString();
    lastError = null;
    return { changed: true, skipped: false, lastRefreshAt, lastError: null };
  } catch (error) {
    lastError = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    refreshing = false;
  }
}

export function startNatReconciler() {
  if (reconcileTimer) return;
  const intervalMs = Math.max(3000, Number(process.env.DRM_NAT_DYNAMIC_INTERVAL_MS ?? 5000));
  void refreshNatRules(true).catch(e => console.warn("DRM NAT restore warning", e));
  reconcileTimer = setInterval(() => void refreshNatRules(false).catch(e => console.warn("DRM NAT reconcile warning", e)), intervalMs);
  reconcileTimer.unref?.();
}

export async function getNatStatus() {
  const [config, networks, topology, hosts, allNatRules] = await Promise.all([readConfig(), listNetworks(), getTopology(), hostInterfaces(), listAllNatRules()]);
  const runtime: Record<string, ResolvedRule> = {};
  for (const rule of config.rules) runtime[rule.id] = await resolveRule(rule, networks, topology);
  let preChainPresent = false, postChainPresent = false;
  try { preChainPresent = await chainExists(preChain); } catch {}
  try { postChainPresent = await chainExists(postChain); } catch {}
  return {
    config,
    runtime,
    hostInterfaces: hosts.interfaces,
    defaultWanInterface: hosts.defaultWanInterface,
    defaultRoutes:hosts.defaultRoutes,
    networkRefs: networks.map((n: any) => ({ id: n.id, name: n.name, subnets: (n.subnets ?? []).map((x: any) => x.subnet).filter(Boolean) })),
    containerRefs: topology.containers.map((c: any) => ({
      id: c.id,
      name: c.name,
      composeProject: c.compose?.project ?? null,
      composeService: c.compose?.service ?? null,
      composeContainerNumber: c.compose?.containerNumber ?? null,
      networks: (c.networks ?? []).map((n: any) => ({ networkName: n.networkName, ipv4Address: n.ipv4Address }))
    })),
    dynamic: { lastRefreshAt, lastError, intervalMs: Math.max(3000, Number(process.env.DRM_NAT_DYNAMIC_INTERVAL_MS ?? 5000)) },
    engine: { preChain, postChain, preChainPresent, postChainPresent },
    allNatRules
  };
}
