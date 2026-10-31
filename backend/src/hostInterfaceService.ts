import { execFile, spawn } from "node:child_process";
import { createConnection } from "node:net";
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { deleteManagedVlan, ensureManagedVlan, listHostInterfaces } from "./vlanService.js";
import { routingTableForInterface } from "./vrfService.js";

const execFileAsync=promisify(execFile);
const dataDir=process.env.DRM_DATA_DIR??"/data";
const configPath=`${dataDir}/host-interfaces.json`;
const pendingPath=`${dataDir}/host-interface-pending.json`;
const dhcpScriptPath=`${dataDir}/drm-udhcpc.sh`;
const agentSocket=process.env.DRM_NETWORK_AGENT_SOCKET??"/run/drm-network-agent/agent.sock";
const rollbackMs=Math.max(15000,Number(process.env.DRM_INTERFACE_ROLLBACK_MS??60000));

type InterfaceMode="dhcp"|"static";
type Ipv6Config={dns:string[];enabled:boolean;mode:"static"|"auto";address:string|null;gateway:string|null;metric:number|null;slaac:boolean;dhcpv6:boolean;addDefaultRoute:boolean};
type ManagedHostInterface={dns4:string[];name:string;mode:InterfaceMode;address:string|null;gateway:string|null;metric:number|null;addDefaultRoute:boolean;vlan:{parent:string;vlanId:number}|null;enabled:boolean;createdAt:string;updatedAt:string;ipv6?:Ipv6Config|null};
type SavedConfig={interfaces:ManagedHostInterface[];updatedAt:string};
type Snapshot={dnsServers:string[];addresses:string[];defaultRoutes:Array<{gateway?:string;metric?:number}>;linkUp:boolean;ipv6Addresses:string[];ipv6Routes:any[];ipv6Sysctls:Record<string,string>};
type PendingChange={family:4|6;token:string;interfaceName:string;previousManaged:ManagedHostInterface|null;snapshot:Snapshot;desired:ManagedHostInterface;expiresAt:string;createdAt:string};

let pending:PendingChange|null=null;
let rollbackTimer:NodeJS.Timeout|null=null;

async function recoverPending(){
 // The agent owns IPv6 rollback timing; never trust a stale backend token.
 try {
   const candidate=pending ?? JSON.parse(await readFile(pendingPath,"utf8")) as PendingChange;
   if(candidate.family!==6)return;
   const state=await networkAgent("status");
   if(state.pending?.token===candidate.token){pending=candidate;return;}
   pending=null;
   await unlink(pendingPath).catch(()=>{});
 } catch(e) {
   // No pending file is normal; an unavailable agent must not silently
   // discard a pending operation.
   if(pending)console.warn("DRM host agent state check failed",e);
 }
}
async function ip(args:string[]){const {stdout}=await execFileAsync("ip",args,{maxBuffer:1024*1024});return stdout;}
async function readConfig():Promise<SavedConfig>{await mkdir(dataDir,{recursive:true});try{const parsed=JSON.parse(await readFile(configPath,"utf8")) as SavedConfig;return {interfaces:Array.isArray(parsed.interfaces)?parsed.interfaces.map((x:any)=>({...x,addDefaultRoute:x.addDefaultRoute!==false})):[],updatedAt:parsed.updatedAt??new Date(0).toISOString()}}catch{return {interfaces:[],updatedAt:new Date(0).toISOString()}}}
async function saveConfig(config:SavedConfig){await mkdir(dataDir,{recursive:true});await writeFile(configPath,JSON.stringify(config,null,2)+"\n","utf8");}
function validateName(v:any){const n=String(v??"").trim();if(!n||n==="lo"||!/^[A-Za-z0-9_.:-]+$/.test(n))throw new Error("Invalid host interface");return n}
function validateAddress(v:any){const a=String(v??"").trim(),[ipPart,prefixRaw]=a.split("/"),prefix=Number(prefixRaw);if(isIP(ipPart)!==4||!Number.isInteger(prefix)||prefix<1||prefix>32)throw new Error("Static IPv4 address must use CIDR notation, for example 192.168.10.2/24");return a}
function validateGateway(v:any){const g=String(v??"").trim();if(g&&isIP(g)!==4)throw new Error("Gateway must be an IPv4 address");return g||null}
function validateMetric(v:any){if(v===null||v===undefined||v==="")return null;const m=Number(v);if(!Number.isInteger(m)||m<0)throw new Error("Metric must be a non-negative integer");return m}
function validateDns(raw:any, family:4|6):string[]{
 const values=Array.isArray(raw)?raw:String(raw??"").split(",");
 const dns=values.map((v:any)=>String(v).trim()).filter(Boolean);
 if(dns.length>8||dns.some(v=>isIP(v)!==family))throw new Error(`DNS servers must be valid IPv${family} addresses (comma-separated, max 8)`);
 return [...new Set(dns)];
}
async function liveDns(name:string):Promise<string[]>{
 try{const state=await networkAgent("get_dns",{interface:name});return Array.isArray(state.servers)?state.servers.filter((v:unknown)=>typeof v==="string"&&isIP(v)>0):[]}catch{return []}
}
async function setLiveDns(name:string,dns:string[]){
 await networkAgent("set_dns",{interface:name,servers:dns});
}
async function detailedLink(name:string){const rows=JSON.parse(await ip(["-d","-j","link","show","dev",name])) as any[];return rows[0]??null}
async function assertManageable(name:string){const row=await detailedLink(name);if(!row)throw new Error(`Interface ${name} does not exist`);const kind=row.linkinfo?.info_kind??null;if(["bridge","veth","wireguard","tun","dummy"].includes(kind)||name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth"))throw new Error(`Interface ${name} cannot be managed here`)}

async function networkAgent(operation:string, payload:Record<string,unknown>={}):Promise<any>{
 return new Promise((resolve,reject)=>{
   const socket=createConnection(agentSocket);
   let buffer="";
   const timeout=setTimeout(()=>{socket.destroy();reject(new Error("DRM host network agent timeout"))},12000);
   let finished=false;
   const finish=(error?:Error,result?:any)=>{if(finished)return;finished=true;clearTimeout(timeout);socket.destroy();if(error)reject(error);else resolve(result)};
   socket.on("connect",()=>socket.write(JSON.stringify({operation,...payload})+"\n"));
   socket.on("data",chunk=>{buffer+=chunk.toString();if(buffer.includes("\n")){try{const response=JSON.parse(buffer.split("\n")[0]);if(!response.ok)finish(new Error(String(response.error)));else finish(undefined,response.result)}catch(e){finish(e as Error)}}});
   socket.on("error",error=>finish(new Error(`DRM host network agent unavailable: ${error.message}. Install host-agent/install.sh on the host first.`)));
   socket.on("end",()=>{if(!finished)finish(new Error("DRM host agent closed connection"))});
 });
}
async function sysctl(name:string,key:string,value?:string){const p=`${process.env.HOST_PROC_SYS??"/host/proc/sys"}/net/ipv6/conf/${name}/${key}`;if(value!==undefined){await writeFile(p,value);return value}return (await readFile(p,"utf8")).trim()}
async function getIpv6Sysctls(name:string){const out:Record<string,string>={};for(const k of ["accept_ra","autoconf","accept_ra_defrtr","use_tempaddr"]){try{out[k]=await sysctl(name,k)}catch{}}return out}
async function stopDhcp6(name:string){const p=`${dataDir}/dhcp6-${name}.pid`;try{const pid=Number((await readFile(p,"utf8")).trim());if(pid)process.kill(pid,"SIGTERM")}catch{}try{await unlink(p)}catch{}}
async function startDhcp6(name:string){await stopDhcp6(name);const pid=`${dataDir}/dhcp6-${name}.pid`;const child=spawn("dhclient",["-6","-nw","-pf",pid,name],{detached:true,stdio:"ignore"});child.on("error",e=>console.error(`DHCPv6 ${name}:`,e));child.unref()}
async function clearIpv6(name:string){await ip(["-6","addr","flush","dev",name,"scope","global"]);const raw=JSON.parse(await ip(["-j","-6","route","show","default","dev",name])) as any[];for(const r of raw){try{await ip(["-6","route","del","default",...(r.gateway?["via",r.gateway]:[]),"dev",name])}catch{}}}
// IPv6 Apply is exclusively delegated to the host networkd agent.
async function snapshot(name:string):Promise<Snapshot>{
  const [a,r,l,a6,r6,sys]=await Promise.all([ip(["-j","-4","addr","show","dev",name]),ip(["-j","-4","route","show","default","dev",name]),ip(["-j","link","show","dev",name]),ip(["-j","-6","addr","show","dev",name]),ip(["-j","-6","route","show","default","dev",name]),getIpv6Sysctls(name)]);
  const aa=JSON.parse(a) as any[],rr=JSON.parse(r) as any[],ll=JSON.parse(l) as any[];
  return {dnsServers:await liveDns(name),addresses:(aa[0]?.addr_info??[]).filter((x:any)=>x.family==="inet"&&x.scope==="global").map((x:any)=>`${x.local}/${x.prefixlen}`),defaultRoutes:rr.map((x:any)=>({gateway:x.gateway,metric:x.metric})),linkUp:Boolean(ll[0]?.flags?.includes("UP")),ipv6Addresses:(JSON.parse(a6)[0]?.addr_info??[]).filter((x:any)=>x.family==="inet6"&&x.scope!=="link").map((x:any)=>`${x.local}/${x.prefixlen}`),ipv6Routes:JSON.parse(r6),ipv6Sysctls:sys};
}
async function stopDhcp(name:string){const pidFile=`${dataDir}/udhcpc-${name}.pid`;try{const pid=Number((await readFile(pidFile,"utf8")).trim());if(pid)try{process.kill(pid,"SIGTERM")}catch{}}catch{}try{await unlink(pidFile)}catch{}}
async function ensureDhcpScript(){
  await mkdir(dataDir,{recursive:true});
  const script=`#!/bin/sh
prefix_from_mask(){ echo "$1" | awk -F. '{n=0;for(i=1;i<=4;i++){v=$i;while(v>0){n+=v%2;v=int(v/2)}}print n}'; }
case "$1" in
 deconfig)
  ip -4 addr flush dev "$interface" scope global || true
  if [ "\${DRM_DHCP_ADD_DEFAULT_ROUTE:-1}" = "1" ]; then
    while ip -4 route del default dev "$interface" 2>/dev/null; do :; done
  fi
 ;;
 bound|renew)
  prefix="$(prefix_from_mask "$subnet")"
  ip link set dev "$interface" up || true
  ip -4 addr flush dev "$interface" scope global || true
  ip -4 addr add "$ip/$prefix" dev "$interface"
  if [ "\${DRM_DHCP_ADD_DEFAULT_ROUTE:-1}" = "1" ]; then
    route_table="\${DRM_DHCP_ROUTE_TABLE:-main}"
    while ip -4 route del table "$route_table" default dev "$interface" 2>/dev/null; do :; done
    first_router=""
    for candidate in $router; do first_router="$candidate"; break; done
    if [ -n "$first_router" ]; then
      ip -4 route replace table "$route_table" default via "$first_router" dev "$interface" metric "\${DRM_DHCP_METRIC:-100}" || \
      ip -4 route add table "$route_table" default via "$first_router" dev "$interface" metric "\${DRM_DHCP_METRIC:-100}" || true
    fi
  else
    while ip -4 route del default dev "$interface" 2>/dev/null; do :; done
  fi
 ;;
esac
exit 0
`;
  await writeFile(dhcpScriptPath,script,{encoding:"utf8",mode:0o755});
}
async function startDhcp(name:string,metric:number|null,addDefaultRoute:boolean){await stopDhcp(name);await ensureDhcpScript();const vrfTable=await routingTableForInterface(name);const pidFile=`${dataDir}/udhcpc-${name}.pid`;const child=spawn("udhcpc",["-b","-q","-i",name,"-p",pidFile,"-s",dhcpScriptPath],{detached:true,stdio:"ignore",env:{...process.env,DRM_DHCP_METRIC:String(metric??100),DRM_DHCP_ADD_DEFAULT_ROUTE:addDefaultRoute?"1":"0",DRM_DHCP_ROUTE_TABLE:vrfTable?String(vrfTable):"main"}});child.unref()}
async function clearIpv4(name:string){await ip(["-4","addr","flush","dev",name,"scope","global"]);while(true){try{await ip(["-4","route","del","default","dev",name])}catch{break}}}
async function applyRuntime(c:ManagedHostInterface, family:4|6=4){
  await assertManageable(c.name);await ip(["link","set","dev",c.name,"up"]);
  if(family===6){throw new Error("IPv6 changes must use DRM host network agent Safe Apply")}
  const vrfTable=await routingTableForInterface(c.name);
  if(c.mode==="dhcp"){await clearIpv4(c.name);await startDhcp(c.name,c.metric,c.addDefaultRoute);return}
  await stopDhcp(c.name);await clearIpv4(c.name);if(!c.address)throw new Error("Static address is required");
  await ip(["-4","addr","add",c.address,"dev",c.name]);
  if(c.gateway){
    const args=["-4","route","replace",...(vrfTable?["table",String(vrfTable)]:[]),"default","via",c.gateway,"dev",c.name];
    if(c.metric!==null)args.push("metric",String(c.metric));await ip(args)
  }
}
async function restoreSnapshot(name:string,s:Snapshot,family:4|6=4){if(family===6){await stopDhcp6(name);await sysctl(name,"accept_ra","0");await clearIpv6(name);for(const a of s.ipv6Addresses)try{await ip(["-6","addr","add",a,"dev",name])}catch{}for(const r of s.ipv6Routes)try{await ip(["-6","route","replace","default",...(r.gateway?["via",r.gateway]:[]),"dev",name,...(r.metric!==undefined?["metric",String(r.metric)]:[])])}catch{}for(const [k,v] of Object.entries(s.ipv6Sysctls))try{await sysctl(name,k,v)}catch{}return}await stopDhcp(name);await clearIpv4(name);if(s.linkUp)await ip(["link","set","dev",name,"up"]);for(const a of s.addresses)await ip(["-4","addr","add",a,"dev",name]);for(const r of s.defaultRoutes){const args=["-4","route","add","default"];if(r.gateway)args.push("via",r.gateway);args.push("dev",name);if(r.metric!==undefined)args.push("metric",String(r.metric));try{await ip(args)}catch{}}}
function cancelTimer(){if(rollbackTimer){clearTimeout(rollbackTimer);rollbackTimer=null}}
function scheduleRollback(){cancelTimer();if(!pending)return;const delay=Math.max(0,new Date(pending.expiresAt).getTime()-Date.now());rollbackTimer=setTimeout(()=>{void rollbackPendingInterfaceChange().catch(e=>console.error("DRM interface auto-rollback failed",e))},delay);rollbackTimer.unref?.()}

function normalizeIpv6(input:any):Ipv6Config{
 const mode=input?.mode==="static"?"static":"auto";
 const address=String(input?.address??"").trim();const gateway=String(input?.gateway??"").trim();
 if(mode==="static"&&(isIP(address.split("/")[0])!==6||!/^\d+$/.test(address.split("/")[1]??"")||Number(address.split("/")[1])>128))throw new Error("Invalid static IPv6 address/prefix");
 if(mode==="static"&&input?.addDefaultRoute===true&&gateway)throw new Error("Use either a manual IPv6 gateway or an RA gateway, not both");
 if(gateway&&isIP(gateway)!==6)throw new Error("Invalid IPv6 gateway");
 if(mode==="auto"&&!input?.slaac&&!input?.dhcpv6)throw new Error("Select SLAAC or DHCPv6");
 return {enabled:true,mode,address:mode==="static"?address:null,gateway:mode==="static"?(gateway||null):null,metric:validateMetric(input?.metric),slaac:mode==="auto"&&Boolean(input?.slaac),dhcpv6:mode==="auto"&&Boolean(input?.dhcpv6),addDefaultRoute:input?.addDefaultRoute===true,dns:validateDns(input?.dns,6)};
}
async function normalizeInput(input:any):Promise<ManagedHostInterface>{
  const mode:InterfaceMode=input?.mode==="dhcp"?"dhcp":"static";let name=validateName(input?.name);let vlan:ManagedHostInterface["vlan"]=null;
  if(input?.vlan?.parent&&input?.vlan?.vlanId){const created=await ensureManagedVlan(input.vlan.parent,input.vlan.vlanId);name=created.name;vlan={parent:String(input.vlan.parent),vlanId:Number(input.vlan.vlanId)}}
  await assertManageable(name);
  return {name,mode,dns4:validateDns(input?.dns4,4),address:input?.family===6?null:mode==="static"?validateAddress(input?.address):null,gateway:input?.family===6?null:mode==="static"?validateGateway(input?.gateway):null,metric:validateMetric(input?.metric),addDefaultRoute:input?.addDefaultRoute!==false,vlan,enabled:true,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),ipv6:input?.ipv6?normalizeIpv6(input.ipv6):null};
}
export async function getHostInterfaceManagementStatus(){
  await recoverPending();
  const [managed,linksRaw,addrRaw,routeRaw,vlanRows]=await Promise.all([readConfig(),ip(["-d","-j","link","show"]),ip(["-j","addr","show"]),ip(["-j","route","show","table","all"]),listHostInterfaces()]);
  const links=JSON.parse(linksRaw) as any[],addresses=JSON.parse(addrRaw) as any[],routes=JSON.parse(routeRaw) as any[],byAddr=new Map(addresses.map((x:any)=>[x.ifname,x]));
  const interfaces=await Promise.all(links.filter((x:any)=>{const name=x.ifname??"",kind=x.linkinfo?.info_kind??null;if(name==="lo"||name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth"))return false;return kind===null||kind==="vlan"}).map(async (x:any)=>{const runtimeDns=await liveDns(x.ifname);const addr:any=byAddr.get(x.ifname);const ipv4Rows=(addr?.addr_info??[]).filter((a:any)=>a.family==="inet");const ipv4=ipv4Rows.map((a:any)=>`${a.local}/${a.prefixlen}`);const ipv4ActualMode=ipv4Rows.length?(ipv4Rows.some((a:any)=>a.dynamic||a.valid_life_time!==undefined&&a.valid_life_time!==4294967295&&a.valid_life_time!=="forever")?"DHCP":"STATIC"):"NONE";const ipv6=(addr?.addr_info??[]).filter((a:any)=>a.family==="inet6").map((a:any)=>`${a.local}/${a.prefixlen}`);const defaults=routes.filter((r:any)=>(r.dst==="default"||!r.dst)&&r.dev===x.ifname);const vm=vlanRows.find((v:any)=>v.name===x.ifname);return {name:x.ifname,index:x.ifindex,kind:x.linkinfo?.info_kind??"physical",state:x.operstate??"UNKNOWN",up:Boolean(x.flags?.includes("UP")),mac:x.address??null,mtu:x.mtu??null,ipv4,ipv6,ipv4ActualMode:(managed.interfaces.find(m=>m.name===x.ifname)?.mode==="dhcp"?"DHCP":ipv4ActualMode),defaultRoutes:defaults,vlanId:vm?.vlanId??null,parent:vm?.parent??null,managedVlan:Boolean(vm?.managed),dns4:runtimeDns.filter(x=>isIP(x)===4),dns6:runtimeDns.filter(x=>isIP(x)===6),managedConfig:managed.interfaces.find(m=>m.name===x.ifname)??null}})).then(rows=>rows.sort((a:any,b:any)=>a.name.localeCompare(b.name)));
  return {interfaces,managed:managed.interfaces,pending,rollbackMs,generatedAt:new Date().toISOString()};
}
export async function applyHostInterfaceChange(input:any){
 await recoverPending();
 if(pending)throw new Error(`Another interface change is waiting for confirmation on ${pending.interfaceName}`);
 const desired=await normalizeInput(input),current=await readConfig(),previousManaged=current.interfaces.find(x=>x.name===desired.name)??null;
 const family:4|6=input?.family===6?6:4;
 const snap=await snapshot(desired.name);
 if(family===6){
   if(!desired.ipv6)throw new Error("Missing IPv6 configuration");
   desired.mode=previousManaged?.mode??"static";desired.address=previousManaged?.address??null;
   desired.gateway=previousManaged?.gateway??null;desired.metric=previousManaged?.metric??null;
   desired.addDefaultRoute=previousManaged?.addDefaultRoute??true;desired.dns4=previousManaged?.dns4??[];
   if(previousManaged?.mode==="static"&&previousManaged.address){
     await networkAgent("persist_ipv4",{interface:desired.name,config:{mode:"static",address:previousManaged.address,gateway:previousManaged.gateway,metric:previousManaged.metric,addDefaultRoute:previousManaged.addDefaultRoute,dns:previousManaged.dns4??[]}});
   }
   const token=randomUUID();
   await networkAgent("apply",{interface:desired.name,config:desired.ipv6,token});
   pending={family,token,interfaceName:desired.name,previousManaged,snapshot:snap,desired,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()};
   await writeFile(pendingPath,JSON.stringify(pending),"utf8");
 } else {
   desired.ipv6=previousManaged?.ipv6??null;
   const token=randomUUID();
   await stopDhcp(desired.name); // Kill legacy udhcpc, never start a second DHCPv4 client.
   await networkAgent("apply_ipv4",{interface:desired.name,token,config:{mode:desired.mode,address:desired.address,gateway:desired.gateway,metric:desired.metric,addDefaultRoute:desired.addDefaultRoute,dns:desired.dns4??[]}});
   pending={family,token,interfaceName:desired.name,previousManaged,snapshot:snap,desired,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+rollbackMs).toISOString()};
   scheduleRollback();
 }
 return {token:pending.token,interfaceName:pending.interfaceName,expiresAt:pending.expiresAt,status:await getHostInterfaceManagementStatus()};
}
export async function confirmHostInterfaceChange(tokenInput:any){
 await recoverPending();
 const token=String(tokenInput??"");
 if(!pending||pending.token!==token)throw new Error("Pending interface change was not found or token is invalid");
 const change=pending;
 if(change.family===6)await networkAgent("confirm",{token});
 cancelTimer();
 if(change.family===4){
   await networkAgent("confirm_ipv4",{interface:change.interfaceName,token:change.token});
 }
 const current=await readConfig(),desired={...change.desired,updatedAt:new Date().toISOString(),createdAt:change.previousManaged?.createdAt??change.desired.createdAt};
 current.interfaces=current.interfaces.filter(x=>x.name!==desired.name);current.interfaces.push(desired);current.updatedAt=new Date().toISOString();
 await saveConfig(current);pending=null;
 if(change.family===6)await unlink(pendingPath).catch(()=>{});
 return getHostInterfaceManagementStatus();
}
export async function rollbackPendingInterfaceChange(tokenInput?:any){
 await recoverPending();
 if(!pending)return getHostInterfaceManagementStatus();
 if(tokenInput!==undefined&&String(tokenInput)!==pending.token)throw new Error("Pending interface change token is invalid");
 const change=pending;
 if(change.family===6)await networkAgent("rollback",{token:change.token});
 else {await networkAgent("rollback_ipv4",{interface:change.interfaceName,token:change.token});await restoreSnapshot(change.interfaceName,change.snapshot,change.family);await setLiveDns(change.interfaceName,change.snapshot.dnsServers).catch(()=>{});}
 pending=null;cancelTimer();if(change.family===6)await unlink(pendingPath).catch(()=>{});return getHostInterfaceManagementStatus();
}
export async function forgetManagedHostInterface(nameInput:any){const name=validateName(nameInput);if(pending?.interfaceName===name)throw new Error("Confirm or rollback the pending change first");const current=await readConfig(),before=current.interfaces.length;current.interfaces=current.interfaces.filter(x=>x.name!==name);if(current.interfaces.length===before)throw new Error(`Interface ${name} is not managed by DRM`);current.updatedAt=new Date().toISOString();await saveConfig(current);await stopDhcp(name);await stopDhcp6(name);return getHostInterfaceManagementStatus()}

export async function deleteHostVlanInterface(nameInput:any){
  const name=validateName(nameInput);
  if(pending?.interfaceName===name)throw new Error("Confirm or rollback the pending interface change first");
  const current=await readConfig();
  const managed=current.interfaces.find(x=>x.name===name)??null;

  // deleteManagedVlan validates DRM ownership and blocks deletion while a Docker network uses this VLAN.
  // Save host-interface persistence only after the Linux VLAN was removed successfully.
  await stopDhcp(name);
  await deleteManagedVlan(name);

  if(managed){
    current.interfaces=current.interfaces.filter(x=>x.name!==name);
    current.updatedAt=new Date().toISOString();
    await saveConfig(current);
  }
  return getHostInterfaceManagementStatus();
}

export async function restoreManagedHostInterfaces(){const current=await readConfig();for(const c of current.interfaces.filter(x=>x.enabled)){try{if(c.vlan)await ensureManagedVlan(c.vlan.parent,c.vlan.vlanId);if(c.mode!=="dhcp")await applyRuntime(c);/* IPv6 settings are persisted in host networkd drop-ins and restored by networkd itself. */}catch(error){console.warn(`DRM host interface restore failed for ${c.name}`,error)}}}
