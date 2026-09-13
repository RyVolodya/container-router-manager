import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import type {
  FirewallAction,
  FirewallConfig,
  FirewallProtocol,
  FirewallRule,
  HostInputFirewallRule,
  ContainerAccessRule,
  AccessSelector,
  PublishedPortFirewallRule
} from "./types.js";
import { getTopology, listNetworks } from "./dockerService.js";

const execFileAsync = promisify(execFile);
const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const configPath = `${dataDir}/firewall.json`;
const backupPath = `${dataDir}/firewall.backup.json`;
const appliedPath = `${dataDir}/firewall.applied.json`;
const chain = "DRM-FIREWALL";
const inputChain = "DRM-INPUT";
const chain6 = "DRM6-FIREWALL";
const inputChain6 = "DRM6-INPUT";
const accessRawChain = "DRM-ACCESS-RAW";
const accessRawChain6 = "DRM6-ACCESS-RAW";
const commentPrefix = "DRM:";

async function ip6tables(args: string[]) {
  return execFileAsync("ip6tables", ["-w", "5", ...args], { maxBuffer: 1024 * 1024 });
}

async function iptables(args: string[]) {
  return execFileAsync("iptables", ["-w", "5", ...args], {
    maxBuffer: 1024 * 1024
  });
}

async function iptablesRaw(args:string[]) {
  return execFileAsync("iptables", ["-w","5","-t","raw",...args], {maxBuffer:1024*1024});
}
async function ip6tablesRaw(args:string[]) {
  return execFileAsync("ip6tables", ["-w","5","-t","raw",...args], {maxBuffer:1024*1024});
}


async function conntrack(args: string[]) {
  return execFileAsync("conntrack", args, {
    maxBuffer: 1024 * 1024
  });
}

type FirewallRuleOwner="DRM"|"Docker"|"System-External";
type HostFirewallRule={
  id:string;
  family:4|6;
  chain:string;
  position:number;
  packets:number;
  bytes:number;
  protocol:string;
  source:string;
  destination:string;
  inInterface:string|null;
  outInterface:string|null;
  sourcePort:string|null;
  destinationPort:string|null;
  target:string;
  state:string|null;
  comment:string|null;
  owner:FirewallRuleOwner;
  raw:string;
};

function fwShellTokens(line:string){
  const tokens:string[]=[];
  const re=/"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)/g;
  let match:RegExpExecArray|null;
  while((match=re.exec(line)))tokens.push((match[1]??match[2]??match[3]??"").replace(/\\"/g,'"'));
  return tokens;
}
function fwTokenValue(tokens:string[],...keys:string[]){
  for(const key of keys){
    const i=tokens.indexOf(key);
    if(i>=0&&i+1<tokens.length)return tokens[i+1];
  }
  return null;
}
function fwCleanIface(value:string|null){return value&&value!=="*" ? value : null}
function firewallOwner(chainName:string,tokens:string[]):FirewallRuleOwner{
  const jump=fwTokenValue(tokens,"-j","--jump")??"";
  const comment=fwTokenValue(tokens,"--comment")??"";
  if(chainName.startsWith("DRM")||jump.startsWith("DRM")||comment.startsWith("DRM:")||comment.includes("docker-router-manager"))return "DRM";
  if(chainName==="DOCKER-USER"||chainName.startsWith("DOCKER")||jump.startsWith("DOCKER")||comment.toLowerCase().includes("docker"))return "Docker";
  return "System-External";
}
async function readFilterRules(family:4|6):Promise<HostFirewallRule[]>{
  const bin=family===4?"iptables-save":"ip6tables-save";
  const {stdout}=await execFileAsync(bin,["-t","filter","-c"],{maxBuffer:8*1024*1024});
  const positions=new Map<string,number>();
  const rules:HostFirewallRule[]=[];
  for(const rawLine of stdout.split(/\r?\n/)){
    const line=rawLine.trim();
    if(!line.startsWith("["))continue;
    const match=line.match(/^\[(\d+):(\d+)\]\s+(.+)$/);
    if(!match)continue;
    const packets=Number(match[1]),bytes=Number(match[2]),spec=match[3];
    const tokens=fwShellTokens(spec);
    if(tokens[0]!=="-A"||!tokens[1])continue;
    const chainName=tokens[1];
    const position=(positions.get(chainName)??0)+1;
    positions.set(chainName,position);
    const protocol=fwTokenValue(tokens,"-p","--protocol")??"all";
    const source=fwTokenValue(tokens,"-s","--source")??(family===4?"0.0.0.0/0":"::/0");
    const destination=fwTokenValue(tokens,"-d","--destination")??(family===4?"0.0.0.0/0":"::/0");
    const sourcePort=fwTokenValue(tokens,"--sport","--source-port","--sports");
    const destinationPort=fwTokenValue(tokens,"--dport","--destination-port","--dports");
    const state=fwTokenValue(tokens,"--ctstate","--state");
    const target=fwTokenValue(tokens,"-j","--jump")??"";
    const comment=fwTokenValue(tokens,"--comment");
    rules.push({
      id:`${family}:${chainName}:${position}`,
      family,chain:chainName,position,packets,bytes,protocol,source,destination,
      inInterface:fwCleanIface(fwTokenValue(tokens,"-i","--in-interface")),
      outInterface:fwCleanIface(fwTokenValue(tokens,"-o","--out-interface")),
      sourcePort,destinationPort,target,state,comment,
      owner:firewallOwner(chainName,tokens),
      raw:spec
    });
  }
  return rules;
}
async function listAllFirewallRules(){
  const [v4,v6]=await Promise.all([
    readFilterRules(4).catch(()=>[] as HostFirewallRule[]),
    readFilterRules(6).catch(()=>[] as HostFirewallRule[])
  ]);
  return [...v4,...v6];
}


async function terminatePublishedPortConnections(config: FirewallConfig) {
  for (const rule of (config.publishedPortRules ?? []).filter(
    (r) => r.enabled && (r.action === "DROP" || r.action === "REJECT")
  )) {
    // Negated source matches cannot be represented safely by this conntrack cleanup.
    if (rule.sourceNegate) continue;
    const args = [
      "-D",
      "-p", rule.protocol,
      "--orig-port-dst", String(rule.publishedPort)
    ];

    if (rule.hostIp && rule.hostIp !== "0.0.0.0" && rule.hostIp.includes(".")) {
      args.push("--orig-dst", rule.hostIp);
    }

    if (rule.sourceCidr && !["0.0.0.0/0","::/0"].includes(rule.sourceCidr)) {
      args.push("--orig-src", rule.sourceCidr);
    }

    // A scoped Destination CIDR matches the current post-DNAT/routed destination
    // in the filter table. conntrack deletion by original tuple cannot express
    // that safely for every routed/DNAT case, so do not kill unrelated sessions.
    const family = normalizeFamily(rule.family, familyOfCidr(rule.sourceCidr));
    const anyDestination = family===6 ? "::/0" : "0.0.0.0/0";
    if (rule.destinationCidr && rule.destinationCidr !== anyDestination) {
      continue;
    }

    try {
      await conntrack(args);
    } catch (error: any) {
      const output = `${String(error?.stdout ?? "")}\n${String(error?.stderr ?? "")}`.toLowerCase();

      // conntrack commonly exits non-zero when there are no matching flows.
      // That is not a firewall failure.
      if (!output.includes("0 flow entries")) {
        console.warn(
          `DRM: conntrack cleanup failed for ${rule.protocol}/${rule.publishedPort}:`,
          error instanceof Error ? error.message : String(error)
        );
      }
    }
  }
}


function familyOfCidr(cidr: string): 4 | 6 {
  return cidr.includes(":") ? 6 : 4;
}
function normalizeFamily(value: any, fallback: 4 | 6 | "both" = 4): 4 | 6 | "both" {
  return value === 6 || value === "6" ? 6 : value === "both" ? "both" : value === 4 || value === "4" ? 4 : fallback;
}
function validCidr(cidr: string, family: 4 | 6) {
  if (!cidr || !cidr.includes("/")) return false;
  return family === 6 ? cidr.includes(":") : cidr.includes(".");
}
async function chainExists6(name:string) { try { await ip6tables(["-n","-L",name]); return true; } catch { return false; } }
async function ensureChain6(name:string, parent:string) {
  if (!(await chainExists6(name))) await ip6tables(["-N",name]);
  try { await ip6tables(["-C",parent,"-j",name]); } catch { await ip6tables(["-I",parent,"1","-j",name]); }
}
async function removeJump6(name:string,parent:string) {
  while(true){ try{await ip6tables(["-D",parent,"-j",name]);}catch{break;} }
}
async function chainExists() {
  try {
    await iptables(["-n", "-L", chain]);
    return true;
  } catch {
    return false;
  }
}

async function inputChainExists() {
  try { await iptables(["-n", "-L", inputChain]); return true; }
  catch { return false; }
}

async function ensureInputChain() {
  if (!(await inputChainExists())) await iptables(["-N", inputChain]);
  try { await iptables(["-C", "INPUT", "-j", inputChain]); }
  catch { await iptables(["-I", "INPUT", "1", "-j", inputChain]); }
}

async function removeInputJump() {
  while (true) {
    try { await iptables(["-D", "INPUT", "-j", inputChain]); }
    catch { break; }
  }
}


async function ensureChain() {
  if (!(await chainExists())) {
    await iptables(["-N", chain]);
  }

  // Ensure exactly one jump from DOCKER-USER and keep it first.
  try {
    await iptables(["-C", "DOCKER-USER", "-j", chain]);
  } catch {
    await iptables(["-I", "DOCKER-USER", "1", "-j", chain]);
  }
}

async function removeJump() {
  while (true) {
    try {
      await iptables(["-D", "DOCKER-USER", "-j", chain]);
    } catch {
      break;
    }
  }
}

export async function getFirewallConfig(): Promise<FirewallConfig> {
  await mkdir(dataDir, { recursive: true });
  try {
    const parsed = JSON.parse(await readFile(configPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? [],
      accessRules: parsed.accessRules ?? []
    };
  } catch {
    return {
      enabled: false,
      rules: [],
      publishedPortRules: [],
      hostInputRules: [],
      accessRules: [],
      updatedAt: new Date().toISOString()
    };
  }
}

async function saveConfig(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(configPath, JSON.stringify(config, null, 2));
}

async function saveBackup(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(backupPath, JSON.stringify(config, null, 2));
}

async function getBackup(): Promise<FirewallConfig | null> {
  try {
    const parsed = JSON.parse(await readFile(backupPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? [],
      accessRules: parsed.accessRules ?? []
    };
  } catch {
    return null;
  }
}

async function saveApplied(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(appliedPath, JSON.stringify(config, null, 2));
}

async function getApplied(): Promise<FirewallConfig> {
  try {
    const parsed = JSON.parse(await readFile(appliedPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? [],
      accessRules: parsed.accessRules ?? []
    };
  } catch {
    return {
      enabled: false,
      rules: [],
      publishedPortRules: [],
      hostInputRules: [],
      accessRules: [],
      updatedAt: new Date(0).toISOString()
    };
  }
}

function validateRule(rule: Omit<FirewallRule, "id"> | FirewallRule) {
  if (!rule.sourceNetworkId || !rule.destinationNetworkId) {
    throw new Error("Source and destination networks are required");
  }
  if (rule.sourceNetworkId === rule.destinationNetworkId) {
    throw new Error("Source and destination networks must be different");
  }
  if (!["all", "tcp", "udp", "icmp", "icmpv6"].includes(rule.protocol)) {
    throw new Error("Unsupported protocol");
  }
  if (!["ACCEPT", "DROP", "REJECT"].includes(rule.action)) {
    throw new Error("Unsupported action");
  }
  if (rule.destinationPort != null) {
    if (!["tcp", "udp"].includes(rule.protocol)) {
      throw new Error("Ports are valid only for TCP or UDP");
    }
    if (!Number.isInteger(rule.destinationPort) || rule.destinationPort < 1 || rule.destinationPort > 65535) {
      throw new Error("Destination port must be 1..65535");
    }
  }
}

export async function addFirewallRule(input: {
  family?: 4 | 6 | "both";
  sourceNetworkId: string;
  destinationNetworkId: string;
  protocol: FirewallProtocol;
  destinationPort?: number | null;
  action: FirewallAction;
  enabled?: boolean;
  description?: string;
}) {
  validateRule({ ...input, enabled: input.enabled ?? true } as FirewallRule);
  const config = await getFirewallConfig();
  const currentNetworks = await listNetworks();
  const sourceNetwork = currentNetworks.find(n => n.id === input.sourceNetworkId || n.name === input.sourceNetworkId);
  const destinationNetwork = currentNetworks.find(n => n.id === input.destinationNetworkId || n.name === input.destinationNetworkId);
  if (!sourceNetwork || !destinationNetwork) throw new Error("Selected Docker network no longer exists");
  const rule: FirewallRule = {
    id: randomUUID(),
    family: normalizeFamily(input.family, 4),
    sourceNetworkId: sourceNetwork.id,
    destinationNetworkId: destinationNetwork.id,
    sourceNetworkName: sourceNetwork.name,
    destinationNetworkName: destinationNetwork.name,
    protocol: input.protocol,
    destinationPort: input.destinationPort ?? null,
    action: input.action,
    enabled: input.enabled ?? true,
    description: input.description?.trim() ?? ""
  };
  config.rules.push(rule);
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  return rule;
}

export async function deleteFirewallRule(id: string) {
  const config = await getFirewallConfig();
  const before = config.rules.length;
  config.rules = config.rules.filter((r) => r.id !== id);
  if (before === config.rules.length) throw new Error("Rule not found");
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
}


function validatePublishedPortRule(rule: Omit<PublishedPortFirewallRule, "id"> | PublishedPortFirewallRule) {
  if (!rule.containerId || !rule.containerName) throw new Error("Container is required");
  if (!["tcp", "udp"].includes(rule.protocol)) throw new Error("Published port protocol must be TCP or UDP");
  if (!Number.isInteger(rule.publishedPort) || rule.publishedPort < 1 || rule.publishedPort > 65535) {
    throw new Error("Published port must be 1..65535");
  }
  if (!Number.isInteger(rule.containerPort) || rule.containerPort < 1 || rule.containerPort > 65535) {
    throw new Error("Container port must be 1..65535");
  }
  if (!["ACCEPT", "DROP", "REJECT"].includes(rule.action)) throw new Error("Unsupported action");
  const family = normalizeFamily(rule.family, familyOfCidr(rule.sourceCidr));
  if (family === "both" || !validCidr(rule.sourceCidr, family)) throw new Error("Source CIDR does not match address family");
  const destinationCidr = rule.destinationCidr?.trim() || (family === 6 ? "::/0" : "0.0.0.0/0");
  if (!validCidr(destinationCidr, family)) throw new Error("Destination CIDR does not match address family");
}

export async function addPublishedPortRule(input: {
  family?: 4 | 6;
  containerId: string;
  containerName: string;
  protocol: "tcp" | "udp";
  publishedPort: number;
  hostIp: string;
  containerPort: number;
  interfaceName?: string;
  sourceCidr?: string;
  sourceNegate?: boolean;
  destinationCidr?: string;
  action: FirewallAction;
  enabled?: boolean;
  description?: string;
}) {
  const rule: PublishedPortFirewallRule = {
    id: randomUUID(),
    family: normalizeFamily(input.family, (input.hostIp||"").includes(":") ? 6 : 4) as 4|6,
    containerId: input.containerId,
    containerName: input.containerName,
    protocol: input.protocol,
    publishedPort: input.publishedPort,
    hostIp: input.hostIp || "0.0.0.0",
    containerPort: input.containerPort,
    interfaceName: String(input.interfaceName || "*").trim() || "*",
    sourceCidr: input.sourceCidr || ((input.family===6 || (input.hostIp||"").includes(":")) ? "::/0" : "0.0.0.0/0"),
    destinationCidr: input.destinationCidr?.trim() || ((input.family===6 || (input.hostIp||"").includes(":")) ? "::/0" : "0.0.0.0/0"),
    action: input.action,
    enabled: input.enabled ?? true,
    description: input.description?.trim() ?? ""
  };
  validatePublishedPortRule(rule);

  // Verify this mapping currently exists in Docker.
  const topology = await getTopology();
  const container = topology.containers.find((c) => c.id === rule.containerId);
  const exists = container?.ports.some(
    (p) =>
      p.protocol === rule.protocol &&
      p.port === rule.containerPort &&
      p.published.some(
        (b) => b.hostPort === rule.publishedPort && (b.hostIp || "0.0.0.0") === rule.hostIp
      )
  );
  if (!exists) throw new Error("Selected Docker published port mapping no longer exists");

  const config = await getFirewallConfig();
  config.publishedPortRules.push(rule);
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  return rule;
}

export async function updatePublishedPortRule(id:string,input:any){
  const config=await getFirewallConfig();
  const index=config.publishedPortRules.findIndex(r=>r.id===id);
  if(index<0)throw new Error("Published port rule not found");
  const old=config.publishedPortRules[index];
  const next:PublishedPortFirewallRule={
    ...old,
    ...input,
    id:old.id,
    family:normalizeFamily(input.family??old.family,(input.hostIp??old.hostIp??"").includes(":")?6:4) as 4|6,
    interfaceName:String(input.interfaceName??old.interfaceName??"*").trim()||"*",
    sourceCidr:String(input.sourceCidr??old.sourceCidr),
    sourceNegate:input.sourceNegate===undefined?Boolean(old.sourceNegate):Boolean(input.sourceNegate),
    destinationCidr:String(input.destinationCidr??old.destinationCidr??"").trim() || (((input.family??old.family)===6 || String(input.hostIp??old.hostIp??"").includes(":"))?"::/0":"0.0.0.0/0"),
    description:String(input.description??old.description??"").trim(),
    enabled:input.enabled===undefined?old.enabled:Boolean(input.enabled)
  };
  validatePublishedPortRule(next);
  config.publishedPortRules[index]=next;
  config.updatedAt=new Date().toISOString();
  await saveConfig(config);
  return next;
}

export async function deletePublishedPortRule(id: string) {
  const config = await getFirewallConfig();
  const before = config.publishedPortRules.length;
  config.publishedPortRules = config.publishedPortRules.filter((r) => r.id !== id);
  if (before === config.publishedPortRules.length) throw new Error("Published port rule not found");
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
}


function validateHostInputRule(rule: Omit<HostInputFirewallRule, "id"> | HostInputFirewallRule) {
  if (!rule.interfaceName) throw new Error("Interface is required");
  if (!["all","tcp","udp","icmp","icmpv6"].includes(rule.protocol)) throw new Error("Unsupported protocol");
  if (!["ACCEPT","DROP","REJECT"].includes(rule.action)) throw new Error("Unsupported action");
  const family=normalizeFamily(rule.family, familyOfCidr(rule.sourceCidr));
  if(family!=="both" && !validCidr(rule.sourceCidr,family)) throw new Error("Source CIDR does not match address family");
  if (rule.destinationPort != null) {
    if (!["tcp","udp"].includes(rule.protocol)) throw new Error("Destination port requires TCP or UDP");
    if (!Number.isInteger(rule.destinationPort) || rule.destinationPort < 1 || rule.destinationPort > 65535) throw new Error("Destination port must be 1..65535");
  }
}

export async function addHostInputRule(input: {
  family?:4|6|"both"; interfaceName?: string; localAddress?: string|null; protocol:FirewallProtocol;
  destinationPort?: number|null; sourceCidr?: string; sourceNegate?:boolean; action:FirewallAction; enabled?:boolean; description?:string;
}) {
  const rule:HostInputFirewallRule={
    id:randomUUID(), family:normalizeFamily(input.family,4), interfaceName:input.interfaceName||"*", localAddress:input.localAddress||null,
    protocol:input.protocol, destinationPort:input.destinationPort??null, sourceCidr:input.sourceCidr||"0.0.0.0/0", sourceNegate:Boolean(input.sourceNegate),
    action:input.action, enabled:input.enabled??true, description:input.description?.trim()??""
  };
  validateHostInputRule(rule);
  const config=await getFirewallConfig();
  config.hostInputRules.push(rule); config.updatedAt=new Date().toISOString(); await saveConfig(config); return rule;
}

export async function deleteHostInputRule(id:string) {
  const config=await getFirewallConfig();
  const before=config.hostInputRules.length;
  config.hostInputRules=config.hostInputRules.filter(r=>r.id!==id);
  if(before===config.hostInputRules.length) throw new Error("Host INPUT rule not found");
  config.updatedAt=new Date().toISOString(); await saveConfig(config);
}

async function buildInputRuleCommands(config:FirewallConfig, family:4) {
  const commands:string[][]=[["-A",inputChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment",`${commentPrefix}input-state`,"-j","ACCEPT"]];
  for(const rule of (config.hostInputRules??[]).filter(r=>r.enabled && [4,"both"].includes(normalizeFamily(r.family,4) as any))){
    validateHostInputRule(rule);
    const args=["-A",inputChain]; if(rule.sourceNegate)args.push("!"); args.push("-s",rule.sourceCidr);
    if(rule.interfaceName!=="*") args.push("-i",rule.interfaceName);
    if(rule.localAddress && rule.localAddress.includes(".")) args.push("-d",rule.localAddress);
    if(rule.protocol!=="all") args.push("-p",rule.protocol==="icmpv6"?"icmp":rule.protocol);
    if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
    args.push("-m","comment","--comment",`${commentPrefix}input:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  commands.push(["-A",inputChain,"-m","comment","--comment",`${commentPrefix}input-return`,"-j","RETURN"]); return commands;
}
async function buildInputRuleCommands6(config:FirewallConfig) {
  const commands:string[][]=[["-A",inputChain6,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment","DRM6:input-state","-j","ACCEPT"]];
  // Essential ICMPv6 control traffic: ND, RA/RS and Packet Too Big must not be accidentally broken.
  for(const type of ["1","2","3","4","133","134","135","136"]) commands.push(["-A",inputChain6,"-p","ipv6-icmp","--icmpv6-type",type,"-m","comment","--comment","DRM6:essential-icmpv6","-j","ACCEPT"]);
  for(const rule of (config.hostInputRules??[]).filter(r=>r.enabled && [6,"both"].includes(normalizeFamily(r.family,4) as any))){
    const source=normalizeFamily(rule.family,4)==="both" ? "::/0" : rule.sourceCidr;
    const args=["-A",inputChain6,"-s",source];
    if(rule.interfaceName!=="*") args.push("-i",rule.interfaceName);
    if(rule.localAddress && rule.localAddress.includes(":")) args.push("-d",rule.localAddress);
    if(rule.protocol!=="all") args.push("-p",rule.protocol==="icmpv6"||rule.protocol==="icmp"?"ipv6-icmp":rule.protocol);
    if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
    args.push("-m","comment","--comment",`DRM6:input:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  commands.push(["-A",inputChain6,"-m","comment","--comment","DRM6:input-return","-j","RETURN"]); return commands;
}

async function getHostNetworkRefs() {
  let interfaces:Array<{name:string;addresses:string[]}>=[]; let defaultWanInterface:string|null=null;
  let hostPorts:Array<{protocol:"tcp"|"udp";listenAddress:string;port:number}>=[];
  try{
    const {stdout}=await execFileAsync("ip",["-j","address","show"],{maxBuffer:1024*1024});
    interfaces=(JSON.parse(stdout) as any[]).filter(x=>x.ifname&&x.ifname!=="lo").map(x=>({
      name:String(x.ifname), addresses:(x.addr_info??[]).filter((a:any)=>a.family==="inet"||a.family==="inet6").map((a:any)=>`${a.local}/${a.prefixlen}`)
    })).sort((a,b)=>a.name.localeCompare(b.name));
  }catch{}
  try{
    const {stdout}=await execFileAsync("ip",["-j","route","show","default"],{maxBuffer:1024*1024});
    defaultWanInterface=(JSON.parse(stdout) as any[])[0]?.dev??null;
  }catch{}
  try{
    const {stdout}=await execFileAsync("ss",["-H","-lntu","-n"],{maxBuffer:1024*1024});
    const refs=new Map<string,{protocol:"tcp"|"udp";listenAddress:string;port:number}>();
    for(const line of stdout.split("\n").filter(Boolean)){
      const fields=line.trim().split(/\s+/); const proto=fields[0]?.startsWith("tcp")?"tcp":fields[0]?.startsWith("udp")?"udp":null;
      if(!proto)continue; const local=fields[4]??""; let address=""; let port=0;
      const v6=local.match(/^\[([^\]]+)\]:(\d+)$/);
      if(v6){address=v6[1];port=Number(v6[2]);}
      else {const pos=local.lastIndexOf(":"); if(pos>=0){address=local.slice(0,pos)||"*";port=Number(local.slice(pos+1));}}
      if(!Number.isInteger(port)||port<1)continue;
      refs.set(`${proto}|${address}|${port}`,{protocol:proto,listenAddress:address,port});
    }
    hostPorts=[...refs.values()].sort((a,b)=>a.port-b.port||a.protocol.localeCompare(b.protocol));
  }catch{}
  return {interfaces,defaultWanInterface,hostPorts};
}


function normalizeHostCidr(value:string,family:4){
  const v=value.trim();
  if(!v)return "";
  return v.includes("/")?v:`${v}/32`;
}
function normalizeHostCidr6(value:string){
  const v=value.trim();
  if(!v)return "";
  return v.includes("/")?v:`${v}/128`;
}
function validateSelector(selector:AccessSelector){
  if(!["custom","docker-network","container","wireguard"].includes(selector.type)) throw new Error("Unsupported selector type");
  if(selector.type==="custom" && !selector.value?.trim()) throw new Error("Custom selector requires an IP address or CIDR");
  if(["docker-network","container"].includes(selector.type) && !selector.refId) throw new Error("Selected object no longer exists");
  if(selector.type==="wireguard" && !selector.value?.trim()) throw new Error("WireGuard selector requires a subnet");
}
function validateAccessRule(rule:Omit<ContainerAccessRule,"id">|ContainerAccessRule){
  if(![4,6,"both"].includes(rule.family)) throw new Error("Invalid address family");
  validateSelector(rule.source); validateSelector(rule.destination);
  if(!["all","tcp","udp","icmp","icmpv6"].includes(rule.protocol)) throw new Error("Unsupported protocol");
  if(!["ACCEPT","DROP","REJECT"].includes(rule.action)) throw new Error("Unsupported action");
  if(rule.destinationPort!=null){
    if(!["tcp","udp"].includes(rule.protocol)) throw new Error("Destination port requires TCP or UDP");
    if(!Number.isInteger(rule.destinationPort)||rule.destinationPort<1||rule.destinationPort>65535) throw new Error("Destination port must be 1..65535");
  }
}
function makeSelector(input:any):AccessSelector{
  return {
    type:String(input?.type??"custom") as any,
    refId:input?.refId?String(input.refId):null,
    refName:input?.refName?String(input.refName).trim():null,
    value:input?.value?String(input.value).trim():null,
    label:input?.label?String(input.label).trim():null,
    composeProject:input?.composeProject?String(input.composeProject).trim():null,
    composeService:input?.composeService?String(input.composeService).trim():null,
    composeContainerNumber:input?.composeContainerNumber?String(input.composeContainerNumber).trim():null
  };
}

async function enrichSelector(selector:AccessSelector):Promise<AccessSelector>{
  if(selector.type==="docker-network"){
    const networks=await listNetworks();
    const n=networks.find((x:any)=>x.id===selector.refId||x.name===selector.refName||x.name===selector.label);
    if(n)return {...selector,refId:n.id,refName:n.name,label:selector.label||n.name};
  }
  if(selector.type==="container"){
    const topology=await getTopology();
    const c=topology.containers.find((x:any)=>x.id===selector.refId||x.name===selector.refName||x.name===selector.label);
    if(c)return {
      ...selector,
      refId:c.id,
      refName:c.name,
      label:selector.label||c.name,
      composeProject:c.compose?.project??selector.composeProject??null,
      composeService:c.compose?.service??selector.composeService??null,
      composeContainerNumber:c.compose?.containerNumber??selector.composeContainerNumber??null
    };
  }
  return selector;
}
export async function addContainerAccessRule(input:any){
  const rule:ContainerAccessRule={
    id:randomUUID(),family:normalizeFamily(input.family,4),
    source:await enrichSelector(makeSelector(input.source)),sourceNegate:Boolean(input.sourceNegate),destination:await enrichSelector(makeSelector(input.destination)),
    protocol:String(input.protocol??"all") as FirewallProtocol,
    destinationPort:input.destinationPort==null||input.destinationPort===""?null:Number(input.destinationPort),
    action:String(input.action??"DROP") as FirewallAction,
    enabled:input.enabled??true,description:String(input.description??"").trim()
  };
  validateAccessRule(rule);
  const config=await getFirewallConfig(); config.accessRules.push(rule); config.updatedAt=new Date().toISOString(); await saveConfig(config); return rule;
}
export async function updateContainerAccessRule(id:string,input:any){
  const config=await getFirewallConfig(); const current=config.accessRules.find(r=>r.id===id); if(!current)throw new Error("Container access rule not found");
  const next:ContainerAccessRule={
    ...current,
    family:input.family===undefined?current.family:normalizeFamily(input.family,current.family),
    source:input.source===undefined?current.source:await enrichSelector(makeSelector(input.source)),
    sourceNegate:input.sourceNegate===undefined?Boolean(current.sourceNegate):Boolean(input.sourceNegate),
    destination:input.destination===undefined?current.destination:await enrichSelector(makeSelector(input.destination)),
    protocol:input.protocol===undefined?current.protocol:String(input.protocol) as FirewallProtocol,
    destinationPort:input.destinationPort===undefined?current.destinationPort:(input.destinationPort==null||input.destinationPort===""?null:Number(input.destinationPort)),
    action:input.action===undefined?current.action:String(input.action) as FirewallAction,
    enabled:input.enabled===undefined?current.enabled:Boolean(input.enabled),
    description:input.description===undefined?current.description:String(input.description).trim()
  };
  validateAccessRule(next); Object.assign(current,next); config.updatedAt=new Date().toISOString(); await saveConfig(config); return current;
}
export async function deleteContainerAccessRule(id:string){
  const config=await getFirewallConfig(); const before=config.accessRules.length; config.accessRules=config.accessRules.filter(r=>r.id!==id);
  if(before===config.accessRules.length)throw new Error("Container access rule not found");
  config.updatedAt=new Date().toISOString(); await saveConfig(config);
}
export async function reorderContainerAccessRules(ids:string[]){
  const config=await getFirewallConfig();
  const map=new Map(config.accessRules.map(r=>[r.id,r])); const ordered:ContainerAccessRule[]=[];
  for(const id of ids){const r=map.get(id);if(r){ordered.push(r);map.delete(id);}}
  ordered.push(...config.accessRules.filter(r=>map.has(r.id)));
  config.accessRules=ordered; config.updatedAt=new Date().toISOString(); await saveConfig(config); return config.accessRules;
}

function reorderByIds<T extends {id:string}>(items:T[],ids:string[]){
  const map=new Map(items.map(r=>[r.id,r])); const ordered:T[]=[];
  for(const id of ids){const r=map.get(id);if(r){ordered.push(r);map.delete(id);}}
  ordered.push(...items.filter(r=>map.has(r.id))); return ordered;
}
export async function reorderFirewallNetworkRules(ids:string[]){
  const config=await getFirewallConfig(); config.rules=reorderByIds(config.rules,ids); config.updatedAt=new Date().toISOString(); await saveConfig(config); return config.rules;
}
export async function reorderPublishedPortRules(ids:string[]){
  const config=await getFirewallConfig(); config.publishedPortRules=reorderByIds(config.publishedPortRules,ids); config.updatedAt=new Date().toISOString(); await saveConfig(config); return config.publishedPortRules;
}
export async function reorderHostInputRules(ids:string[]){
  const config=await getFirewallConfig(); config.hostInputRules=reorderByIds(config.hostInputRules,ids); config.updatedAt=new Date().toISOString(); await saveConfig(config); return config.hostInputRules;
}


function cidrNetworkAddress(cidr:string):string{
  const raw=String(cidr||"").trim();
  const parts=raw.split("/");
  if(parts.length!==2)return raw;
  const address=parts[0], prefix=Number(parts[1]);
  if(address.includes(".")){
    if(!Number.isInteger(prefix)||prefix<0||prefix>32)return raw;
    const octets=address.split(".").map(Number);
    if(octets.length!==4||octets.some(x=>!Number.isInteger(x)||x<0||x>255))return raw;
    let value=((octets[0]<<24)>>>0)+((octets[1]<<16)>>>0)+((octets[2]<<8)>>>0)+(octets[3]>>>0);
    const mask=prefix===0?0:(0xffffffff << (32-prefix))>>>0;
    value=(value & mask)>>>0;
    return `${(value>>>24)&255}.${(value>>>16)&255}.${(value>>>8)&255}.${value&255}/${prefix}`;
  }
  if(address.includes(":")){
    if(!Number.isInteger(prefix)||prefix<0||prefix>128)return raw;
    try{
      const [leftRaw,rightRaw=""]=address.split("::");
      if(address.split("::").length>2)return raw;
      const expandPart=(part:string)=>part?part.split(":").filter(Boolean):[];
      const left=expandPart(leftRaw),right=expandPart(rightRaw);
      const fill=Math.max(0,8-left.length-right.length);
      const groups=[...left,...Array(fill).fill("0"),...right];
      if(groups.length!==8)return raw;
      let value=0n;
      for(const group of groups){
        const n=BigInt(parseInt(group||"0",16));
        value=(value<<16n)|n;
      }
      const hostBits=128-prefix;
      const mask=prefix===0?0n:((1n<<128n)-1n)^((1n<<BigInt(hostBits))-1n);
      value=value&mask;
      const out:string[]=[];
      for(let i=0;i<8;i++){
        const shift=BigInt((7-i)*16);
        out.push(Number((value>>shift)&0xffffn).toString(16));
      }
      // Compact the longest zero run for display.
      let bestStart=-1,bestLen=0,currentStart=-1,currentLen=0;
      for(let i=0;i<=8;i++){
        if(i<8&&out[i]==="0"){
          if(currentStart<0)currentStart=i;
          currentLen++;
        }else{
          if(currentLen>bestLen&&currentLen>1){bestStart=currentStart;bestLen=currentLen;}
          currentStart=-1;currentLen=0;
        }
      }
      let rendered:string;
      if(bestStart>=0){
        const before=out.slice(0,bestStart).join(":");
        const after=out.slice(bestStart+bestLen).join(":");
        rendered=`${before}::${after}`;
        if(rendered.startsWith(":::"))rendered=rendered.slice(1);
        if(rendered.endsWith(":::"))rendered=rendered.slice(0,-1);
      }else rendered=out.join(":");
      return `${rendered}/${prefix}`;
    }catch{return raw;}
  }
  return raw;
}

async function readWireGuardRefs(){
  try{
    const raw=JSON.parse(await readFile(`${dataDir}/wireguard/state.json`,"utf8")) as any;
    const refs:any[]=[];
    const seen=new Set<string>();

    const add=(ref:any)=>{
      const key=`${ref.interfaceName}|${ref.kind}|${ref.id}|${ref.cidr}`;
      if(seen.has(key))return;
      seen.add(key);refs.push(ref);
    };

    for(const iface of (raw.interfaces??[])){
      const interfaceCidrs=[...(iface.addresses??[]),iface.address,iface.ipv6Address]
        .filter((x:any)=>typeof x==="string"&&x.trim())
        .map((x:any)=>cidrNetworkAddress(String(x)));
      for(const cidr of [...new Set<string>(interfaceCidrs)]){
        const family=cidr.includes(":")?6:4;
        add({id:`${iface.name}|tunnel|${cidr}`,interfaceName:iface.name,name:`${iface.name} tunnel`,cidr,family,kind:"tunnel"});
      }

      for(const peer of (iface.peers??[])){
        const peerAddresses=[peer.clientAddress,peer.clientIpv6Address]
          .filter((x:any)=>typeof x==="string"&&x.trim());
        for(const cidrRaw of peerAddresses){
          const family=String(cidrRaw).includes(":")?6:4;
          const cidr=family===6?normalizeHostCidr6(String(cidrRaw).split("/")[0]):normalizeHostCidr(String(cidrRaw).split("/")[0],4);
          add({
            id:`${iface.name}|peer|${peer.id}|${cidr}`,
            interfaceName:iface.name,
            name:`${iface.name} · ${peer.name||"peer"}`,
            cidr,family,kind:"peer"
          });
        }

        for(const cidr of (peer.remoteNetworks??[])){
          add({
            id:`${iface.name}|remote|${peer.id}|${cidr}`,
            interfaceName:iface.name,
            name:`${iface.name} · ${peer.name||"peer"} remote`,
            cidr:String(cidr),
            family:String(cidr).includes(":")?6:4,
            kind:"remote"
          });
        }
      }
    }
    return refs;
  }catch{return [];}
}

async function resolveSelector(selector:AccessSelector,family:4|6,networks:any[],topology:any):Promise<string[]>{
  if(selector.type==="custom"||selector.type==="wireguard"){
    const raw=String(selector.value??"").trim(); if(!raw)return [];
    if(family===4 && !raw.includes(":"))return [normalizeHostCidr(raw,4)];
    if(family===6 && raw.includes(":"))return [normalizeHostCidr6(raw)];
    return [];
  }
  if(selector.type==="docker-network"){
    const n=networks.find((x:any)=>
      x.id===selector.refId ||
      (selector.refName && x.name===selector.refName) ||
      (!selector.refName && selector.label && x.name===selector.label)
    );
    if(!n)return [];
    return cidrs(n.subnets??[],family);
  }
  if(selector.type==="container"){
    const composeMatch=(x:any)=>
      Boolean(selector.composeProject&&selector.composeService&&
        x.compose?.project===selector.composeProject&&
        x.compose?.service===selector.composeService&&
        String(x.compose?.containerNumber??"1")===String(selector.composeContainerNumber??"1"));
    const c=topology.containers.find((x:any)=>
      x.id===selector.refId ||
      composeMatch(x) ||
      (selector.refName && x.name===selector.refName) ||
      (!selector.refName && selector.label && x.name===selector.label)
    );
    if(!c)return [];
    const values:string[]=(c.networks??[])
      .flatMap((n:any)=>family===4?[n.ipv4Address]:[n.ipv6Address])
      .filter((value:any): value is string => typeof value === "string" && value.length > 0);
    return Array.from(new Set<string>(values.map((v:string)=>family===4?normalizeHostCidr(v.split("/")[0],4):normalizeHostCidr6(v.split("/")[0]))));
  }
  return [];
}
function selectorTargetsDocker(selector:AccessSelector){return selector.type==="docker-network"||selector.type==="container";}

async function buildAccessRuleCommands(config:FirewallConfig,family:4|6,networks:any[],topology:any){
  const target=family===6?chain6:chain; const prefix=family===6?"DRM6:":"DRM:";
  const commands:string[][]=[];
  for(const rule of (config.accessRules??[]).filter(r=>r.enabled&&[family,"both"].includes(normalizeFamily(r.family,4) as any))){
    validateAccessRule(rule);
    const sources=await resolveSelector(rule.source,family,networks,topology);
    const destinations=await resolveSelector(rule.destination,family,networks,topology);
    for(const source of sources)for(const destination of destinations){
      const args=["-A",target]; if(rule.sourceNegate)args.push("!"); args.push("-s",source,"-d",destination);
      if(rule.protocol!=="all")args.push("-p",family===6&&(rule.protocol==="icmp"||rule.protocol==="icmpv6")?"ipv6-icmp":rule.protocol==="icmpv6"?"icmp":rule.protocol);
      if(rule.destinationPort!=null)args.push("--dport",String(rule.destinationPort));
      args.push("-m","comment","--comment",`${prefix}access:${rule.id}`,"-j",rule.action); commands.push(args);
    }
  }
  return commands;
}
async function buildAccessRawCommands(config:FirewallConfig,family:4|6,networks:any[],topology:any){
  const target=family===6?accessRawChain6:accessRawChain; const commands:string[][]=[];
  // Raw ACCEPT is only a Docker direct-routing exception. Final policy remains in DRM-FIREWALL/DRM6-FIREWALL.
  for(const rule of (config.accessRules??[]).filter(r=>r.enabled&&r.action==="ACCEPT"&&selectorTargetsDocker(r.destination)&&[family,"both"].includes(normalizeFamily(r.family,4) as any))){
    const sources=await resolveSelector(rule.source,family,networks,topology);
    const destinations=await resolveSelector(rule.destination,family,networks,topology);
    for(const source of sources)for(const destination of destinations){
      const rawArgs=["-A",target]; if(rule.sourceNegate)rawArgs.push("!"); rawArgs.push("-s",source,"-d",destination,"-m","comment","--comment",`${family===6?"DRM6":"DRM"}:access-raw:${rule.id}`,"-j","ACCEPT"); commands.push(rawArgs);
    }
  }
  commands.push(["-A",target,"-j","RETURN"]); return commands;
}
async function ensureAccessRawChains(){
  try{await iptablesRaw(["-n","-L",accessRawChain]);}catch{await iptablesRaw(["-N",accessRawChain]);}
  try{await ip6tablesRaw(["-n","-L",accessRawChain6]);}catch{await ip6tablesRaw(["-N",accessRawChain6]);}
  while(true){try{await iptablesRaw(["-D","PREROUTING","-j",accessRawChain]);}catch{break;}}
  while(true){try{await ip6tablesRaw(["-D","PREROUTING","-j",accessRawChain6]);}catch{break;}}
  await iptablesRaw(["-I","PREROUTING","1","-j",accessRawChain]);
  await ip6tablesRaw(["-I","PREROUTING","1","-j",accessRawChain6]);
}
async function removeAccessRawJumps(){
  while(true){try{await iptablesRaw(["-D","PREROUTING","-j",accessRawChain]);}catch{break;}}
  while(true){try{await ip6tablesRaw(["-D","PREROUTING","-j",accessRawChain6]);}catch{break;}}
}

type RuleCounter={packets:number;bytes:number};
function addCounter(result:Record<string,RuleCounter>,id:string,packets:number,bytes:number){
  const current=result[id]??{packets:0,bytes:0}; current.packets+=packets;current.bytes+=bytes;result[id]=current;
}
async function allRuleCounters(){
  const result:Record<string,RuleCounter>={};
  const scans:Array<[typeof iptables,string]>=[
    [iptables,chain],[iptables,inputChain],[ip6tables,chain6],[ip6tables,inputChain6]
  ];
  for(const [runner,target] of scans){
    try{
      const {stdout}=await runner(["-nvxL",target]);
      for(const line of stdout.split("\n")){
        const head=line.match(/^\s*(\d+)\s+(\d+)\s+/); if(!head)continue;
        const comment=line.match(/\/\*\s+(DRM6?:[^\s*]+)\s+\*\//); if(!comment)continue;
        const token=comment[1];
        let id:string|null=null;
        let m=token.match(/^DRM6?:published:(.+)$/); if(m)id=`published:${m[1]}`;
        m=token.match(/^DRM6?:input:(.+)$/); if(m)id=`input:${m[1]}`;
        m=token.match(/^DRM6?:access:(.+)$/); if(m)id=`access:${m[1]}`;
        // Docker network policy comments are DRM:<uuid> / DRM6:<uuid>.
        m=token.match(/^DRM6?:(.+)$/);
        if(!id && m && !["state","return","input-state","input-return","essential-icmpv6"].includes(m[1]) && !m[1].startsWith("published:") && !m[1].startsWith("input:") && !m[1].startsWith("access:")) id=`network:${m[1]}`;
        if(id)addCounter(result,id,Number(head[1]),Number(head[2]));
      }
    }catch{}
  }
  return result;
}

async function accessCounters(){
  const result:Record<string,{packets:number;bytes:number}>={};
  for(const [family,runner,target] of [[4,iptables,chain],[6,ip6tables,chain6]] as const){
    try{
      const {stdout}=await runner(["-nvxL",target]);
      for(const line of stdout.split("\n")){
        const m=line.match(/^\s*(\d+)\s+(\d+).*\/\*\s+DRM6?:access:([^\s*]+)\s+\*\//);
        if(!m)continue; const id=m[3]; const current=result[id]??{packets:0,bytes:0};
        current.packets+=Number(m[1]); current.bytes+=Number(m[2]); result[id]=current;
      }
    }catch{}
  }
  return result;
}

function cidrs(subnets: Array<{ subnet: string | null }>, family:4|6) {
  return subnets.map(s=>s.subnet).filter((x):x is string=>Boolean(x && (family===6 ? x.includes(":") : x.includes("."))));
}

async function buildRuleCommands(config: FirewallConfig, family:4|6) {
  const networks=await listNetworks();
  const byId=new Map(networks.map(n=>[n.id,n]));
  const byName=new Map(networks.map(n=>[n.name,n]));
  const targetChain=family===6?chain6:chain; const prefix=family===6?"DRM6:":commentPrefix;
  const commands:string[][]=[["-A",targetChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment",`${prefix}state`,"-j","ACCEPT"]];
  for(const rule of (config.publishedPortRules??[]).filter(r=>r.enabled && normalizeFamily(r.family,(r.hostIp||"").includes(":")?6:4)===family)){
    validatePublishedPortRule(rule);
    const destinationCidr=rule.destinationCidr?.trim() || (family===6?"::/0":"0.0.0.0/0");
    const args=["-A",targetChain];
    if(rule.interfaceName && rule.interfaceName!=="*") args.push("-i",rule.interfaceName);
    if(rule.sourceNegate) args.push("!");
    args.push("-s",rule.sourceCidr,"-d",destinationCidr,"-p",rule.protocol,"-m","conntrack","--ctstate","NEW","--ctorigdstport",String(rule.publishedPort));
    if(rule.hostIp && !["0.0.0.0","::"].includes(rule.hostIp) && (family===6?rule.hostIp.includes(":"):rule.hostIp.includes("."))) args.push("--ctorigdst",rule.hostIp);
    args.push("-m","comment","--comment",`${prefix}published:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  for(const rule of config.rules.filter(r=>r.enabled && [family,"both"].includes(normalizeFamily(r.family,4) as any))){
    validateRule(rule);
    const src=byId.get(rule.sourceNetworkId) || (rule.sourceNetworkName ? byName.get(rule.sourceNetworkName) : undefined);
    const dst=byId.get(rule.destinationNetworkId) || (rule.destinationNetworkName ? byName.get(rule.destinationNetworkName) : undefined);
    if(!src||!dst) throw new Error(`Network for rule ${rule.id} no longer exists`);
    const srcs=cidrs(src.subnets,family),dsts=cidrs(dst.subnets,family);
    // A "both" rule applies to whichever families both networks actually provide.
    if(!srcs.length||!dsts.length) continue;
    for(const source of srcs) for(const destination of dsts){
      const args=["-A",targetChain,"-s",source,"-d",destination];
      if(rule.protocol!=="all") args.push("-p",family===6 && (rule.protocol==="icmp"||rule.protocol==="icmpv6")?"ipv6-icmp":rule.protocol==="icmpv6"?"icmp":rule.protocol);
      if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
      if(rule.action==="ACCEPT") args.push("-m","conntrack","--ctstate","NEW");
      args.push("-m","comment","--comment",`${prefix}${rule.id}`,"-j",rule.action); commands.push(args);
    }
  }
  commands.push(["-A",targetChain,"-m","comment","--comment",`${prefix}return`,"-j","RETURN"]); return commands;
}

async function render(config: FirewallConfig) {
  await ensureChain(); await ensureInputChain();
  await ensureChain6(chain6,"DOCKER-USER"); await ensureChain6(inputChain6,"INPUT");
  await ensureAccessRawChains();

  await iptables(["-F",chain]); await iptables(["-F",inputChain]);
  await ip6tables(["-F",chain6]); await ip6tables(["-F",inputChain6]);
  await iptablesRaw(["-F",accessRawChain]); await ip6tablesRaw(["-F",accessRawChain6]);

  if(!config.enabled){
    await removeJump(); await removeInputJump();
    await removeJump6(chain6,"DOCKER-USER"); await removeJump6(inputChain6,"INPUT");
    await removeAccessRawJumps();
    return;
  }

  try{await iptables(["-C","DOCKER-USER","-j",chain]);}catch{await iptables(["-I","DOCKER-USER","1","-j",chain]);}
  try{await iptables(["-C","INPUT","-j",inputChain]);}catch{await iptables(["-I","INPUT","1","-j",inputChain]);}
  try{await ip6tables(["-C","DOCKER-USER","-j",chain6]);}catch{await ip6tables(["-I","DOCKER-USER","1","-j",chain6]);}
  try{await ip6tables(["-C","INPUT","-j",inputChain6]);}catch{await ip6tables(["-I","INPUT","1","-j",inputChain6]);}

  const [networks,topology]=await Promise.all([listNetworks(),getTopology()]);

  // First-match Container Access rules run before the generic ESTABLISHED rule.
  // This lets a newly applied DROP also block an already established forwarded flow.
  for(const args of await buildAccessRuleCommands(config,4,networks,topology)) await iptables(args);
  for(const args of await buildRuleCommands(config,4)) await iptables(args);
  for(const args of await buildInputRuleCommands(config,4)) await iptables(args);

  for(const args of await buildAccessRuleCommands(config,6,networks,topology)) await ip6tables(args);
  for(const args of await buildRuleCommands(config,6)) await ip6tables(args);
  for(const args of await buildInputRuleCommands6(config)) await ip6tables(args);

  for(const args of await buildAccessRawCommands(config,4,networks,topology)) await iptablesRaw(args);
  for(const args of await buildAccessRawCommands(config,6,networks,topology)) await ip6tablesRaw(args);
}

export async function applyFirewall() {
  const draft = await getFirewallConfig();
  const previousApplied = await getApplied();
  await saveBackup(previousApplied);

  const next: FirewallConfig = {
    ...draft,
    rules: draft.rules.map((r) => ({ ...r })),
    publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (draft.hostInputRules ?? []).map((r) => ({ ...r })),
    accessRules: (draft.accessRules ?? []).map((r) => ({...r, source:{...r.source}, destination:{...r.destination}})),
    enabled: true,
    updatedAt: new Date().toISOString()
  };

  try {
    await render(next);
    await saveApplied(next);
    await saveConfig(next);

    // Make DROP/REJECT apply to already-established published-port sessions.
    await terminatePublishedPortConnections(next);

    return getFirewallStatus();
  } catch (error) {
    try {
      await render(previousApplied);
      await saveApplied(previousApplied);
    } catch {
      // Preserve the original apply error.
    }
    throw error;
  }
}

export async function disableFirewall() {
  const draft = await getFirewallConfig();
  const previousApplied = await getApplied();
  await saveBackup(previousApplied);

  const next: FirewallConfig = {
    ...draft,
    rules: draft.rules.map((r) => ({ ...r })),
    publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (draft.hostInputRules ?? []).map((r) => ({ ...r })),
    accessRules: (draft.accessRules ?? []).map((r) => ({...r, source:{...r.source}, destination:{...r.destination}})),
    enabled: false,
    updatedAt: new Date().toISOString()
  };

  await render(next);
  await saveApplied(next);
  await saveConfig(next);
  return getFirewallStatus();
}

export async function rollbackFirewall() {
  const backup = await getBackup();
  if (!backup) throw new Error("No rollback snapshot exists");

  const restored: FirewallConfig = {
    ...backup,
    rules: backup.rules.map((r) => ({ ...r })),
    publishedPortRules: (backup.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (backup.hostInputRules ?? []).map((r) => ({ ...r })),
    accessRules: (backup.accessRules ?? []).map((r) => ({...r, source:{...r.source}, destination:{...r.destination}})),
    updatedAt: new Date().toISOString()
  };

  await render(restored);
  await saveApplied(restored);
  await saveConfig(restored);
  await terminatePublishedPortConnections(restored);
  return getFirewallStatus();
}


let dynamicFirewallTimer:NodeJS.Timeout|null=null;
let dynamicFirewallFingerprint="";
let dynamicFirewallRefreshAt:string|null=null;
let dynamicFirewallRefreshError:string|null=null;
let dynamicFirewallRefreshing=false;

async function selectorFingerprint(config:FirewallConfig){
  if(!config.enabled)return "disabled";
  const [networks,topology]=await Promise.all([listNetworks(),getTopology()]);
  const rows:any[]=[];
  for(const rule of (config.accessRules??[]).filter(r=>r.enabled)){
    for(const family of ([4,6] as const)){
      if(![family,"both"].includes(normalizeFamily(rule.family,4) as any))continue;
      rows.push([
        rule.id,family,
        await resolveSelector(rule.source,family,networks,topology),
        await resolveSelector(rule.destination,family,networks,topology)
      ]);
    }
  }
  for(const rule of (config.rules??[]).filter(r=>r.enabled)){
    const src=networks.find((n:any)=>n.id===rule.sourceNetworkId||(rule.sourceNetworkName&&n.name===rule.sourceNetworkName));
    const dst=networks.find((n:any)=>n.id===rule.destinationNetworkId||(rule.destinationNetworkName&&n.name===rule.destinationNetworkName));
    rows.push(["network-rule",rule.id,src?.id,src?.subnets,dst?.id,dst?.subnets]);
  }
  return JSON.stringify(rows);
}

export async function refreshDynamicFirewallRules(force=false){
  if(dynamicFirewallRefreshing)return {changed:false,skipped:true,lastRefreshAt:dynamicFirewallRefreshAt,error:dynamicFirewallRefreshError};
  dynamicFirewallRefreshing=true;
  try{
    const applied=await getApplied();
    if(!applied.enabled){
      dynamicFirewallFingerprint="disabled";
      dynamicFirewallRefreshError=null;
      return {changed:false,skipped:false,lastRefreshAt:dynamicFirewallRefreshAt,error:null};
    }
    const fingerprint=await selectorFingerprint(applied);
    if(!force&&fingerprint===dynamicFirewallFingerprint){
      dynamicFirewallRefreshError=null;
      return {changed:false,skipped:false,lastRefreshAt:dynamicFirewallRefreshAt,error:null};
    }
    await render(applied);
    dynamicFirewallFingerprint=fingerprint;
    dynamicFirewallRefreshAt=new Date().toISOString();
    dynamicFirewallRefreshError=null;
    return {changed:true,skipped:false,lastRefreshAt:dynamicFirewallRefreshAt,error:null};
  }catch(error){
    dynamicFirewallRefreshError=error instanceof Error?error.message:String(error);
    throw error;
  }finally{
    dynamicFirewallRefreshing=false;
  }
}

export function startDynamicFirewallReconciler(){
  if(dynamicFirewallTimer)return;
  const intervalMs=Math.max(3000,Number(process.env.DRM_FIREWALL_DYNAMIC_INTERVAL_MS??5000));
  void refreshDynamicFirewallRules(true).catch(e=>console.warn("DRM dynamic firewall sync warning",e));
  dynamicFirewallTimer=setInterval(()=>{
    void refreshDynamicFirewallRules(false).catch(e=>console.warn("DRM dynamic firewall sync warning",e));
  },intervalMs);
  dynamicFirewallTimer.unref?.();
}

async function accessRuleRuntime(config:FirewallConfig,networks:any[],topology:any){
  const result:Record<string,any>={};
  for(const rule of (config.accessRules??[])){
    const families=(rule.family==="both"?[4,6]:[rule.family]) as Array<4|6>;
    const sourceResolved:string[]=[];
    const destinationResolved:string[]=[];
    for(const family of families){
      sourceResolved.push(...await resolveSelector(rule.source,family,networks,topology));
      destinationResolved.push(...await resolveSelector(rule.destination,family,networks,topology));
    }
    const source=[...new Set(sourceResolved)];
    const destination=[...new Set(destinationResolved)];
    const sourceOk=source.length>0;
    const destinationOk=destination.length>0;
    result[rule.id]={
      source,destination,resolved:sourceOk&&destinationOk,
      message:!sourceOk&&!destinationOk?"Source and destination are currently unavailable":
              !sourceOk?"Source is currently unavailable":
              !destinationOk?"Destination is currently unavailable":
              "Resolved from current Docker state"
    };
  }
  return result;
}

export async function getFirewallStatus() {
  const config = await getFirewallConfig();
  const applied = await getApplied();
  const pendingChanges =
    JSON.stringify({
      enabled: config.enabled,
      rules: config.rules,
      publishedPortRules: config.publishedPortRules ?? [],
      hostInputRules: config.hostInputRules ?? [],
      accessRules: config.accessRules ?? []
    }) !==
    JSON.stringify({
      enabled: applied.enabled,
      rules: applied.rules,
      publishedPortRules: applied.publishedPortRules ?? [],
      hostInputRules: applied.hostInputRules ?? [],
      accessRules: applied.accessRules ?? []
    });

  let installedRules: string[] = [];
  let installedInputRules: string[] = [];
  let chainPresent = false;
  let jumpPresent = false;
  let inputChainPresent = false;
  let inputJumpPresent = false;
  let error: string | null = null;
  let installedRules6:string[]=[]; let installedInputRules6:string[]=[]; let chainPresent6=false; let jumpPresent6=false; let inputChainPresent6=false; let inputJumpPresent6=false;

  try {
    chainPresent = await chainExists();
    if (chainPresent) {
      const { stdout } = await iptables(["-S", chain]);
      installedRules = stdout
        .split("\n")
        .map((x: string) => x.trim())
        .filter(Boolean);
    }
    try {
      await iptables(["-C", "DOCKER-USER", "-j", chain]);
      jumpPresent = true;
    } catch {
      jumpPresent = false;
    }
    inputChainPresent=await inputChainExists();
    if(inputChainPresent){
      const {stdout}=await iptables(["-S",inputChain]);
      installedInputRules=stdout.split("\n").map((x:string)=>x.trim()).filter(Boolean);
    }
    try{await iptables(["-C","INPUT","-j",inputChain]);inputJumpPresent=true;}catch{inputJumpPresent=false;}

    chainPresent6=await chainExists6(chain6); inputChainPresent6=await chainExists6(inputChain6);
    if(chainPresent6){const {stdout}=await ip6tables(["-S",chain6]);installedRules6=stdout.split("\n").map(x=>x.trim()).filter(Boolean);}
    if(inputChainPresent6){const {stdout}=await ip6tables(["-S",inputChain6]);installedInputRules6=stdout.split("\n").map(x=>x.trim()).filter(Boolean);}
    try{await ip6tables(["-C","DOCKER-USER","-j",chain6]);jumpPresent6=true;}catch{}
    try{await ip6tables(["-C","INPUT","-j",inputChain6]);inputJumpPresent6=true;}catch{}
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const [networks, topology, allFirewallRules] = await Promise.all([listNetworks(), getTopology(), listAllFirewallRules()]);
  const networkRefs = networks
    .filter((n) => n.driver === "bridge")
    .map((n) => ({
      id: n.id,
      name: n.name,
      refName: n.name,
      subnets: n.subnets.map((s) => s.subnet).filter((x): x is string => Boolean(x))
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));

  const publishedPortRefs = topology.containers
    .flatMap((container) =>
      container.ports.flatMap((port) =>
        port.published
          .filter(() => port.protocol === "tcp" || port.protocol === "udp")
          .map((binding) => ({
            containerId: container.id,
            containerName: container.name,
            protocol: port.protocol as "tcp" | "udp",
            publishedPort: binding.hostPort,
            hostIp: binding.hostIp || "0.0.0.0",
            containerPort: port.port
          }))
      )
    )
    .filter((port) => Number.isInteger(port.publishedPort) && port.publishedPort > 0)
    .sort((a, b) =>
      a.containerName.localeCompare(b.containerName) ||
      a.publishedPort - b.publishedPort ||
      a.protocol.localeCompare(b.protocol) ||
      a.hostIp.localeCompare(b.hostIp)
    );

  const hostRefs=await getHostNetworkRefs();
  const wireguardRefs=await readWireGuardRefs();
  const containerRefs=topology.containers.map(container=>({
    id:container.id,
    name:container.name,
    refName:container.name,
    composeProject:container.compose?.project??null,
    composeService:container.compose?.service??null,
    composeContainerNumber:container.compose?.containerNumber??null,
    addresses:container.networks.flatMap(n=>[
      n.ipv4Address?{family:4,address:n.ipv4Address.includes("/")?n.ipv4Address:`${n.ipv4Address}/32`,networkName:n.networkName}:null,
      n.ipv6Address?{family:6,address:n.ipv6Address.includes("/")?n.ipv6Address:`${n.ipv6Address}/128`,networkName:n.networkName}:null
    ]).filter(Boolean)
  })).sort((a,b)=>a.name.localeCompare(b.name));
  const counters=await accessCounters();
  const ruleCounters=await allRuleCounters();
  const accessRuleResolution=await accessRuleRuntime(config,networks,topology);

  return {
    engine: "iptables + ip6tables",
    managedChain: `${chain} / ${chain6}`,
    config,
    applied,
    pendingChanges,
    lastAppliedAt: applied.updatedAt === new Date(0).toISOString() ? null : applied.updatedAt,
    networkRefs,
    containerRefs,
    wireguardRefs,
    accessCounters:counters,
    accessRuleResolution,
    dynamicFirewall:{
      lastRefreshAt:dynamicFirewallRefreshAt,
      lastError:dynamicFirewallRefreshError,
      intervalMs:Math.max(3000,Number(process.env.DRM_FIREWALL_DYNAMIC_INTERVAL_MS??5000))
    },
    ruleCounters,
    allFirewallRules,
    publishedPortRefs,
    hostInterfaces:hostRefs.interfaces,
    defaultWanInterface:hostRefs.defaultWanInterface,
    hostPortRefs:hostRefs.hostPorts,
    runtime: {
      chainPresent,
      jumpPresent,
      installedRules,
      inputChainPresent,
      inputJumpPresent,
      installedInputRules,
      chainPresent6,jumpPresent6,installedRules6,inputChainPresent6,inputJumpPresent6,installedInputRules6,
      error
    }
  };
}

export async function addNatManagedFirewallRule(natRuleId:string,input:{sourceCidr:string;destination:AccessSelector;protocol:"tcp"|"udp";destinationPort:number;description:string}){
  const config=await getFirewallConfig();
  config.accessRules=config.accessRules.filter(r=>r.managedByNatRuleId!==natRuleId);
  const rule:ContainerAccessRule={
    id:randomUUID(),family:4,
    source:{type:"custom",value:input.sourceCidr,label:input.sourceCidr},
    destination:await enrichSelector(input.destination),
    protocol:input.protocol,destinationPort:input.destinationPort,
    action:"ACCEPT",enabled:true,description:input.description,managedByNatRuleId:natRuleId
  };
  validateAccessRule(rule);
  config.accessRules.push(rule);config.updatedAt=new Date().toISOString();await saveConfig(config);

  const applied=await getApplied();
  if(applied.enabled){
    applied.accessRules=applied.accessRules.filter(r=>r.managedByNatRuleId!==natRuleId);
    applied.accessRules.push({...rule});applied.updatedAt=new Date().toISOString();
    await saveApplied(applied);await render(applied);
  }
  return rule;
}

export async function removeNatManagedFirewallRule(natRuleId:string){
  const config=await getFirewallConfig();
  const before=config.accessRules.length;
  config.accessRules=config.accessRules.filter(r=>r.managedByNatRuleId!==natRuleId);
  if(config.accessRules.length!==before){config.updatedAt=new Date().toISOString();await saveConfig(config);}
  const applied=await getApplied();
  const appliedBefore=applied.accessRules.length;
  applied.accessRules=applied.accessRules.filter(r=>r.managedByNatRuleId!==natRuleId);
  if(applied.accessRules.length!==appliedBefore){
    applied.updatedAt=new Date().toISOString();await saveApplied(applied);
    if(applied.enabled)await render(applied);
  }
}
