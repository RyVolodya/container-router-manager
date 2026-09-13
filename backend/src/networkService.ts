import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dockerDelete, dockerPost } from "./dockerClient.js";
import { listNetworks } from "./dockerService.js";
import { cleanupManagedVlanIfUnused, ensureManagedVlan, listHostInterfaces } from "./vlanService.js";

const execFileAsync = promisify(execFile);

export const PRIVATE_IPV4_POOLS = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16"
] as const;

type Range = { start:number; end:number; label:string; cidr:string };

function ipv4ToInt(ip:string):number {
  const parts=ip.split(".");
  if(parts.length!==4) throw new Error(`Invalid IPv4 address: ${ip}`);
  let value=0;
  for(const part of parts){
    if(!/^\d+$/.test(part)) throw new Error(`Invalid IPv4 address: ${ip}`);
    const n=Number(part);
    if(n<0||n>255) throw new Error(`Invalid IPv4 address: ${ip}`);
    value=(value*256+n)>>>0;
  }
  return value>>>0;
}

function intToIpv4(value:number):string {
  const v=value>>>0;
  return `${(v>>>24)&255}.${(v>>>16)&255}.${(v>>>8)&255}.${v&255}`;
}

function parseCidr(cidr:string):Range {
  const [ip,prefixRaw]=cidr.trim().split("/");
  const prefix=Number(prefixRaw);
  if(!Number.isInteger(prefix)||prefix<0||prefix>32) throw new Error(`Invalid IPv4 CIDR: ${cidr}`);
  const value=ipv4ToInt(ip);
  const mask=prefix===0?0:(0xffffffff << (32-prefix))>>>0;
  const start=(value & mask)>>>0;
  const size=2**(32-prefix);
  const end=start+size-1;
  if(end>0xffffffff) throw new Error(`Invalid IPv4 CIDR: ${cidr}`);
  return {start,end,label:cidr,cidr:`${intToIpv4(start)}/${prefix}`};
}

function overlaps(a:Range,b:Range){ return a.start<=b.end && b.start<=a.end; }

function firstUsable(cidr:string):string {
  const r=parseCidr(cidr);
  if(r.end-r.start<2) throw new Error("Subnet is too small to assign a gateway");
  return intToIpv4(r.start+1);
}

function validatePrefix(pool:string,prefixLength:number){
  const poolPrefix=Number(pool.split("/")[1]);
  if(!Number.isInteger(prefixLength)||prefixLength<poolPrefix||prefixLength>30){
    throw new Error(`Subnet size must be between /${poolPrefix} and /30 for ${pool}`);
  }
}

async function hostIpv4Ranges():Promise<Range[]> {
  const ranges:Range[]=[];
  try {
    const [{stdout:routeRaw},{stdout:addrRaw}]=await Promise.all([
      execFileAsync("ip",["-j","-4","route","show","table","main"],{maxBuffer:1024*1024}),
      execFileAsync("ip",["-j","-4","addr","show"],{maxBuffer:1024*1024})
    ]);
    const routes=JSON.parse(routeRaw) as any[];
    for(const route of routes){
      const dst=String(route.dst??"");
      if(!dst||dst==="default"||!dst.includes("/")) continue;
      try{ const r=parseCidr(dst); ranges.push({...r,label:`Host route ${dst}`}); }catch{}
    }
    const links=JSON.parse(addrRaw) as any[];
    for(const link of links){
      for(const info of link.addr_info??[]){
        if(info.family!=="inet"||!info.local||info.prefixlen==null) continue;
        const cidr=`${info.local}/${info.prefixlen}`;
        try{ const r=parseCidr(cidr); ranges.push({...r,label:`Host interface ${link.ifname} ${r.cidr}`}); }catch{}
      }
    }
  } catch(error) {
    // Docker conflicts are still checked if iproute2 data cannot be read.
    console.warn("DRM network conflict scan: cannot read host IPv4 routes/interfaces", error);
  }
  return ranges;
}

async function occupiedIpv4Ranges():Promise<Range[]> {
  const networks=await listNetworks();
  const ranges:Range[]=[];
  for(const network of networks){
    for(const cfg of network.subnets){
      if(!cfg.subnet || cfg.subnet.includes(":")) continue;
      try{
        const r=parseCidr(cfg.subnet);
        ranges.push({...r,label:`Docker network ${network.name} ${r.cidr}`});
      }catch{}
    }
  }
  ranges.push(...await hostIpv4Ranges());

  // Deduplicate identical ranges while retaining a useful label.
  const seen=new Set<string>();
  return ranges.filter(r=>{
    const key=`${r.start}-${r.end}`;
    if(seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function occupiedDockerIpv4Ranges():Promise<Range[]> {
  const networks=await listNetworks(); const ranges:Range[]=[];
  for(const network of networks){for(const cfg of network.subnets){if(!cfg.subnet||cfg.subnet.includes(":"))continue;try{const r=parseCidr(cfg.subnet);ranges.push({...r,label:`Docker network ${network.name} ${r.cidr}`})}catch{}}}
  return ranges;
}

async function validateExternalSubnet(subnet:string,gateway?:string|null){
  const candidate=parseCidr(subnet); const conflict=(await occupiedDockerIpv4Ranges()).find(r=>overlaps(candidate,r));
  if(conflict)throw new Error(`${candidate.cidr} conflicts with ${conflict.label}`);
  let normalizedGateway=String(gateway??"").trim(); if(!normalizedGateway)normalizedGateway=firstUsable(candidate.cidr);
  const g=ipv4ToInt(normalizedGateway); if(g<=candidate.start||g>=candidate.end)throw new Error(`Gateway ${normalizedGateway} must be a usable address inside ${candidate.cidr}`);
  return {subnet:candidate.cidr,gateway:normalizedGateway};
}

export async function getDockerNetworkParents(){
  const interfaces=await listHostInterfaces();
  return interfaces.filter((x:any)=>x.kind===null||x.kind==="bond"||x.kind==="team"||x.kind==="vlan").map((x:any)=>({name:x.name,kind:x.kind,state:x.state,up:x.up,vlanId:x.vlanId,parent:x.parent,managed:x.managed}));
}

export async function suggestBridgeSubnet(pool:string,prefixLength:number) {
  if(!PRIVATE_IPV4_POOLS.includes(pool as any)) throw new Error("Unsupported private IPv4 pool");
  validatePrefix(pool,prefixLength);

  const poolRange=parseCidr(pool);
  const occupied=await occupiedIpv4Ranges();
  const blockSize=2**(32-prefixLength);

  for(let start=poolRange.start; start+blockSize-1<=poolRange.end; start+=blockSize){
    const candidate:Range={start,end:start+blockSize-1,label:"candidate",cidr:`${intToIpv4(start)}/${prefixLength}`};
    if(!occupied.some(r=>overlaps(candidate,r))){
      return {
        pool,
        prefixLength,
        subnet:candidate.cidr,
        gateway:firstUsable(candidate.cidr),
        conflicts:[]
      };
    }
  }
  throw new Error(`No free /${prefixLength} subnet is available in ${pool}`);
}

export async function validateBridgeSubnet(subnet:string,gateway?:string|null) {
  const candidate=parseCidr(subnet);
  const occupied=await occupiedIpv4Ranges();
  const conflict=occupied.find(r=>overlaps(candidate,r));
  if(conflict){
    throw new Error(`${candidate.cidr} conflicts with ${conflict.label}`);
  }

  let normalizedGateway=String(gateway??"").trim();
  if(!normalizedGateway) normalizedGateway=firstUsable(candidate.cidr);
  const gatewayInt=ipv4ToInt(normalizedGateway);
  if(gatewayInt<=candidate.start||gatewayInt>=candidate.end){
    throw new Error(`Gateway ${normalizedGateway} must be a usable address inside ${candidate.cidr}`);
  }

  return {subnet:candidate.cidr,gateway:normalizedGateway};
}

function validateNetworkName(name:string){
  const value=name.trim();
  if(!value) throw new Error("Network name is required");
  if(value.length>128) throw new Error("Network name is too long");
  if(!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value)){
    throw new Error("Network name may contain letters, numbers, dot, underscore and dash");
  }
  if(["bridge","host","none"].includes(value)) throw new Error(`${value} is a protected Docker network name`);
  return value;
}

export async function createDockerNetwork(input:any){
  const name=validateNetworkName(String(input?.name??""));
  const existing=await listNetworks(); if(existing.some(n=>n.name===name))throw new Error(`Docker network ${name} already exists`);
  const driver=(["bridge","macvlan","ipvlan"].includes(String(input?.driver))?String(input.driver):"bridge") as "bridge"|"macvlan"|"ipvlan";
  const allocation=input?.allocation==="manual"?"manual":"automatic";
  let subnet:string;let gateway:string;let parent:string|null=null;let vlanId:number|null=null;let vlanInterface:string|null=null;let createdVlan=false;

  if(driver==="bridge"){
    if(allocation==="automatic"){
      const pool=String(input?.pool??"10.0.0.0/8"); const prefixLength=Number(input?.prefixLength??24); const suggestion=await suggestBridgeSubnet(pool,prefixLength); subnet=suggestion.subnet;gateway=suggestion.gateway;
    }else{const validated=await validateBridgeSubnet(String(input?.subnet??""),input?.gateway);subnet=validated.subnet;gateway=validated.gateway}
  }else{
    if(allocation!=="manual")throw new Error(`${driver} networks require the VLAN/LAN subnet and gateway to be entered manually`);
    const validated=await validateExternalSubnet(String(input?.subnet??""),input?.gateway);subnet=validated.subnet;gateway=validated.gateway;
    parent=String(input?.parent??"").trim(); if(!parent)throw new Error(`Parent interface is required for ${driver}`);
    const available=await listHostInterfaces(); if(!available.some((x:any)=>x.name===parent))throw new Error(`Parent interface ${parent} does not exist`);
    if(input?.vlanId!==undefined&&input?.vlanId!==null&&String(input.vlanId).trim()!==""){
      vlanId=Number(input.vlanId); const vlan=await ensureManagedVlan(parent,vlanId); vlanInterface=vlan.name;createdVlan=vlan.created;parent=vlan.name;
    }
  }

  const options:Record<string,string>={};
  if(driver==="macvlan"&&parent){options.parent=parent;options.macvlan_mode=String(input?.mode??"bridge")}
  if(driver==="ipvlan"&&parent){options.parent=parent;options.ipvlan_mode=String(input?.mode??"l2")}
  try{
    const result=await dockerPost<{Id:string;Warning?:string}>("/networks/create",{
      Name:name,Driver:driver,CheckDuplicate:true,Internal:Boolean(input?.internal),Attachable:Boolean(input?.attachable),EnableIPv6:false,
      ...(Object.keys(options).length?{Options:options}:{}),
      IPAM:{Driver:"default",Config:[{Subnet:subnet,Gateway:gateway}]},
      Labels:{"com.drm.managed":"true","com.drm.created-by":"docker-router-manager",...(vlanId?{"com.drm.vlan-id":String(vlanId),"com.drm.vlan-interface":String(parent),"com.drm.vlan-managed":"true"}:{})}
    });
    return {id:result.Id,name,driver,subnet,gateway,parent,vlanId,mode:driver==="macvlan"?(options.macvlan_mode??null):driver==="ipvlan"?(options.ipvlan_mode??null):null,warning:result.Warning??null};
  }catch(error){
    if(createdVlan&&vlanInterface){try{await cleanupManagedVlanIfUnused(vlanInterface)}catch{}}
    throw error;
  }
}

// Backward-compatible export used by older callers.
export const createBridgeNetwork=createDockerNetwork;

export async function deleteDockerNetwork(id:string){
  const networks=await listNetworks();
  const network=networks.find(n=>n.id===id||n.name===id);
  if(!network) throw new Error("Docker network not found");
  if(["bridge","host","none"].includes(network.name)) throw new Error(`${network.name} is a protected Docker network`);
  if(network.ingress) throw new Error("Docker ingress network cannot be deleted");
  if(network.containers.length){
    throw new Error(`Network ${network.name} still has ${network.containers.length} attached container(s)`);
  }
  const vlanInterface=(network as any).managedVlanInterface||(network as any).labels?.["com.drm.vlan-interface"]||null;
  await dockerDelete(`/networks/${encodeURIComponent(network.id)}`);
  if(vlanInterface){try{await cleanupManagedVlanIfUnused(String(vlanInterface))}catch(error){console.warn(`DRM VLAN cleanup warning for ${vlanInterface}`,error)}}
}


type ContainerNetworkIpInfo={
  networkId:string;
  networkName:string;
  subnet:string;
  gateway:string|null;
  usedIps:Array<{ip:string;containerId:string;containerName:string}>;
  nextFreeIp:string|null;
};

function normalizeAttachedIp(value:string|null|undefined):string|null{
  if(!value)return null;
  const ip=String(value).split('/')[0]?.trim()??'';
  if(!ip||ip.includes(':'))return null;
  try{ipv4ToInt(ip);return ip;}catch{return null;}
}

function networkIpv4Config(network:any){
  const cfg=(network.subnets??[]).find((x:any)=>x.subnet&&!String(x.subnet).includes(':'));
  if(!cfg?.subnet)throw new Error(`Network ${network.name} has no managed IPv4 subnet`);
  const parsed=parseCidr(String(cfg.subnet));
  return {range:parsed,subnet:parsed.cidr,gateway:cfg.gateway?String(cfg.gateway):null};
}

function usedIpv4Map(network:any){
  const used=new Map<number,{ip:string;containerId:string;containerName:string}>();
  for(const endpoint of network.containers??[]){
    const ip=normalizeAttachedIp(endpoint.ipv4Address);
    if(!ip)continue;
    used.set(ipv4ToInt(ip),{ip,containerId:String(endpoint.id),containerName:String(endpoint.name??endpoint.id)});
  }
  return used;
}

function validateContainerIpv4(network:any,ip:string,excludeContainerId?:string){
  const {range,subnet,gateway}=networkIpv4Config(network);
  const value=ipv4ToInt(ip);
  if(value<=range.start||value>=range.end)throw new Error(`IP ${ip} must be a usable address inside ${subnet}`);
  if(gateway&&value===ipv4ToInt(gateway))throw new Error(`IP ${ip} is the gateway of ${subnet}`);
  const used=usedIpv4Map(network);
  const owner=used.get(value);
  if(owner&&owner.containerId!==excludeContainerId){
    throw new Error(`IP ${ip} is already used by container ${owner.containerName}`);
  }
  return {ip:intToIpv4(value),subnet,gateway};
}

function findNextFreeContainerIpv4(network:any,excludeContainerId?:string,avoidIp?:string|null):string{
  const {range,gateway}=networkIpv4Config(network);
  const gatewayValue=gateway?ipv4ToInt(gateway):null;
  const used=usedIpv4Map(network);
  const avoidValue=avoidIp?ipv4ToInt(avoidIp):null;
  // Start at the first usable address, skipping gateway/used/current addresses.
  for(let value=range.start+1;value<range.end;value++){
    if(gatewayValue!==null&&value===gatewayValue)continue;
    if(avoidValue!==null&&value===avoidValue)continue;
    const owner=used.get(value);
    if(owner&&owner.containerId!==excludeContainerId)continue;
    return intToIpv4(value);
  }
  throw new Error(`No free IPv4 address is available in ${range.cidr}`);
}

async function getNetworkForContainerManagement(networkId:string){
  const networks=await listNetworks();
  const network=networks.find(n=>n.id===networkId||n.name===networkId);
  if(!network)throw new Error('Docker network not found');
  if(['host','none'].includes(network.name)||['host','null'].includes(network.driver)){
    throw new Error(`Network ${network.name} does not support managed container IP allocation`);
  }
  return network;
}

export async function getContainerNetworkIpInfo(networkId:string,excludeContainerId?:string):Promise<ContainerNetworkIpInfo>{
  const network=await getNetworkForContainerManagement(networkId);
  const {subnet,gateway}=networkIpv4Config(network);
  const used=Array.from(usedIpv4Map(network).values()).filter(x=>x.containerId!==excludeContainerId);
  let nextFreeIp:string|null=null;
  try{nextFreeIp=findNextFreeContainerIpv4(network,excludeContainerId);}catch{}
  return {networkId:network.id,networkName:network.name,subnet,gateway,usedIps:used,nextFreeIp};
}

function validateContainerId(id:string){
  const value=id.trim();
  if(!value)throw new Error('Container ID is required');
  if(!/^[A-Za-z0-9_.-]+$/.test(value))throw new Error('Invalid container ID');
  return value;
}

export async function connectContainerNetwork(containerIdRaw:string,networkId:string,input:any){
  const containerId=validateContainerId(containerIdRaw);
  const network=await getNetworkForContainerManagement(networkId);
  if(network.containers.some((x:any)=>x.id===containerId))throw new Error(`Container is already connected to ${network.name}`);
  const allocation=input?.allocation==='manual'?'manual':'automatic';
  const ip=allocation==='manual'
    ? validateContainerIpv4(network,String(input?.ipv4Address??''),containerId).ip
    : findNextFreeContainerIpv4(network,containerId);

  await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`,{
    Container:containerId,
    EndpointConfig:{IPAMConfig:{IPv4Address:ip}}
  });
  return {containerId,networkId:network.id,networkName:network.name,ipv4Address:ip};
}

export async function disconnectContainerNetwork(containerIdRaw:string,networkId:string,force=false){
  const containerId=validateContainerId(containerIdRaw);
  const network=await getNetworkForContainerManagement(networkId);
  if(!network.containers.some((x:any)=>x.id===containerId))throw new Error(`Container is not connected to ${network.name}`);
  await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/disconnect`,{Container:containerId,Force:Boolean(force)});
  return {containerId,networkId:network.id,networkName:network.name};
}

export async function changeContainerNetworkIpv4(containerIdRaw:string,networkId:string,input:any){
  const containerId=validateContainerId(containerIdRaw);
  const network=await getNetworkForContainerManagement(networkId);
  const endpoint=network.containers.find((x:any)=>x.id===containerId);
  if(!endpoint)throw new Error(`Container is not connected to ${network.name}`);
  const oldIp=normalizeAttachedIp(endpoint.ipv4Address);
  const allocation=input?.allocation==='manual'?'manual':'automatic';
  const newIp=allocation==='manual'
    ? validateContainerIpv4(network,String(input?.ipv4Address??''),containerId).ip
    : findNextFreeContainerIpv4(network,containerId,oldIp);
  if(oldIp===newIp)return {containerId,networkId:network.id,networkName:network.name,ipv4Address:newIp,changed:false};

  await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/disconnect`,{Container:containerId,Force:false});
  try{
    await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`,{
      Container:containerId,EndpointConfig:{IPAMConfig:{IPv4Address:newIp}}
    });
  }catch(error){
    // Best-effort rollback to the original endpoint address.
    try{
      const rollbackConfig=oldIp?{IPAMConfig:{IPv4Address:oldIp}}:{};
      await dockerPost<void>(`/networks/${encodeURIComponent(network.id)}/connect`,{Container:containerId,EndpointConfig:rollbackConfig});
    }catch(rollbackError){
      throw new Error(`Failed to set ${newIp}; rollback also failed: ${rollbackError instanceof Error?rollbackError.message:String(rollbackError)}`);
    }
    throw error;
  }
  return {containerId,networkId:network.id,networkName:network.name,ipv4Address:newIp,previousIpv4Address:oldIp,changed:true};
}
