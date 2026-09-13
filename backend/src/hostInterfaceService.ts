import { execFile, spawn } from "node:child_process";
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
const dhcpScriptPath=`${dataDir}/drm-udhcpc.sh`;
const rollbackMs=Math.max(15000,Number(process.env.DRM_INTERFACE_ROLLBACK_MS??60000));

type InterfaceMode="dhcp"|"static";
type ManagedHostInterface={name:string;mode:InterfaceMode;address:string|null;gateway:string|null;metric:number|null;addDefaultRoute:boolean;vlan:{parent:string;vlanId:number}|null;enabled:boolean;createdAt:string;updatedAt:string};
type SavedConfig={interfaces:ManagedHostInterface[];updatedAt:string};
type Snapshot={addresses:string[];defaultRoutes:Array<{gateway?:string;metric?:number}>;linkUp:boolean};
type PendingChange={token:string;interfaceName:string;previousManaged:ManagedHostInterface|null;snapshot:Snapshot;desired:ManagedHostInterface;expiresAt:string;createdAt:string};

let pending:PendingChange|null=null;
let rollbackTimer:NodeJS.Timeout|null=null;

async function ip(args:string[]){const {stdout}=await execFileAsync("ip",args,{maxBuffer:1024*1024});return stdout;}
async function readConfig():Promise<SavedConfig>{await mkdir(dataDir,{recursive:true});try{const parsed=JSON.parse(await readFile(configPath,"utf8")) as SavedConfig;return {interfaces:Array.isArray(parsed.interfaces)?parsed.interfaces.map((x:any)=>({...x,addDefaultRoute:x.addDefaultRoute!==false})):[],updatedAt:parsed.updatedAt??new Date(0).toISOString()}}catch{return {interfaces:[],updatedAt:new Date(0).toISOString()}}}
async function saveConfig(config:SavedConfig){await mkdir(dataDir,{recursive:true});await writeFile(configPath,JSON.stringify(config,null,2)+"\n","utf8");}
function validateName(v:any){const n=String(v??"").trim();if(!n||n==="lo"||!/^[A-Za-z0-9_.:-]+$/.test(n))throw new Error("Invalid host interface");return n}
function validateAddress(v:any){const a=String(v??"").trim(),[ipPart,prefixRaw]=a.split("/"),prefix=Number(prefixRaw);if(isIP(ipPart)!==4||!Number.isInteger(prefix)||prefix<1||prefix>32)throw new Error("Static IPv4 address must use CIDR notation, for example 192.168.10.2/24");return a}
function validateGateway(v:any){const g=String(v??"").trim();if(g&&isIP(g)!==4)throw new Error("Gateway must be an IPv4 address");return g||null}
function validateMetric(v:any){if(v===null||v===undefined||v==="")return null;const m=Number(v);if(!Number.isInteger(m)||m<0)throw new Error("Metric must be a non-negative integer");return m}
async function detailedLink(name:string){const rows=JSON.parse(await ip(["-d","-j","link","show","dev",name])) as any[];return rows[0]??null}
async function assertManageable(name:string){const row=await detailedLink(name);if(!row)throw new Error(`Interface ${name} does not exist`);const kind=row.linkinfo?.info_kind??null;if(["bridge","veth","wireguard","tun","dummy"].includes(kind)||name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth"))throw new Error(`Interface ${name} cannot be managed here`)}

async function snapshot(name:string):Promise<Snapshot>{
  const [a,r,l]=await Promise.all([ip(["-j","-4","addr","show","dev",name]),ip(["-j","-4","route","show","default","dev",name]),ip(["-j","link","show","dev",name])]);
  const aa=JSON.parse(a) as any[],rr=JSON.parse(r) as any[],ll=JSON.parse(l) as any[];
  return {addresses:(aa[0]?.addr_info??[]).filter((x:any)=>x.family==="inet"&&x.scope==="global").map((x:any)=>`${x.local}/${x.prefixlen}`),defaultRoutes:rr.map((x:any)=>({gateway:x.gateway,metric:x.metric})),linkUp:Boolean(ll[0]?.flags?.includes("UP"))};
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
async function applyRuntime(c:ManagedHostInterface){
  await assertManageable(c.name);await ip(["link","set","dev",c.name,"up"]);
  const vrfTable=await routingTableForInterface(c.name);
  if(c.mode==="dhcp"){await clearIpv4(c.name);await startDhcp(c.name,c.metric,c.addDefaultRoute);return}
  await stopDhcp(c.name);await clearIpv4(c.name);if(!c.address)throw new Error("Static address is required");
  await ip(["-4","addr","add",c.address,"dev",c.name]);
  if(c.gateway){
    const args=["-4","route","replace",...(vrfTable?["table",String(vrfTable)]:[]),"default","via",c.gateway,"dev",c.name];
    if(c.metric!==null)args.push("metric",String(c.metric));await ip(args)
  }
}
async function restoreSnapshot(name:string,s:Snapshot){await stopDhcp(name);await clearIpv4(name);if(s.linkUp)await ip(["link","set","dev",name,"up"]);for(const a of s.addresses)await ip(["-4","addr","add",a,"dev",name]);for(const r of s.defaultRoutes){const args=["-4","route","add","default"];if(r.gateway)args.push("via",r.gateway);args.push("dev",name);if(r.metric!==undefined)args.push("metric",String(r.metric));try{await ip(args)}catch{}}}
function cancelTimer(){if(rollbackTimer){clearTimeout(rollbackTimer);rollbackTimer=null}}
function scheduleRollback(){cancelTimer();if(!pending)return;const delay=Math.max(0,new Date(pending.expiresAt).getTime()-Date.now());rollbackTimer=setTimeout(()=>{void rollbackPendingInterfaceChange().catch(e=>console.error("DRM interface auto-rollback failed",e))},delay);rollbackTimer.unref?.()}

async function normalizeInput(input:any):Promise<ManagedHostInterface>{
  const mode:InterfaceMode=input?.mode==="dhcp"?"dhcp":"static";let name=validateName(input?.name);let vlan:ManagedHostInterface["vlan"]=null;
  if(input?.vlan?.parent&&input?.vlan?.vlanId){const created=await ensureManagedVlan(input.vlan.parent,input.vlan.vlanId);name=created.name;vlan={parent:String(input.vlan.parent),vlanId:Number(input.vlan.vlanId)}}
  await assertManageable(name);
  return {name,mode,address:mode==="static"?validateAddress(input?.address):null,gateway:mode==="static"?validateGateway(input?.gateway):null,metric:validateMetric(input?.metric),addDefaultRoute:input?.addDefaultRoute!==false,vlan,enabled:true,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
}
export async function getHostInterfaceManagementStatus(){
  const [managed,linksRaw,addrRaw,routeRaw,vlanRows]=await Promise.all([readConfig(),ip(["-d","-j","link","show"]),ip(["-j","-4","addr","show"]),ip(["-j","-4","route","show","table","all"]),listHostInterfaces()]);
  const links=JSON.parse(linksRaw) as any[],addresses=JSON.parse(addrRaw) as any[],routes=JSON.parse(routeRaw) as any[],byAddr=new Map(addresses.map((x:any)=>[x.ifname,x]));
  const interfaces=links.filter((x:any)=>{const name=x.ifname??"",kind=x.linkinfo?.info_kind??null;if(name==="lo"||name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth"))return false;return kind===null||kind==="vlan"}).map((x:any)=>{const addr:any=byAddr.get(x.ifname);const ipv4=(addr?.addr_info??[]).filter((a:any)=>a.family==="inet").map((a:any)=>`${a.local}/${a.prefixlen}`);const defaults=routes.filter((r:any)=>(r.dst==="default"||!r.dst)&&r.dev===x.ifname);const vm=vlanRows.find((v:any)=>v.name===x.ifname);return {name:x.ifname,index:x.ifindex,kind:x.linkinfo?.info_kind??"physical",state:x.operstate??"UNKNOWN",up:Boolean(x.flags?.includes("UP")),mac:x.address??null,mtu:x.mtu??null,ipv4,defaultRoutes:defaults,vlanId:vm?.vlanId??null,parent:vm?.parent??null,managedVlan:Boolean(vm?.managed),managedConfig:managed.interfaces.find(m=>m.name===x.ifname)??null}}).sort((a:any,b:any)=>a.name.localeCompare(b.name));
  return {interfaces,managed:managed.interfaces,pending,rollbackMs,generatedAt:new Date().toISOString()};
}
export async function applyHostInterfaceChange(input:any){if(pending)throw new Error(`Another interface change is waiting for confirmation on ${pending.interfaceName}`);const desired=await normalizeInput(input),current=await readConfig(),previousManaged=current.interfaces.find(x=>x.name===desired.name)??null,snap=await snapshot(desired.name);await applyRuntime(desired);pending={token:randomUUID(),interfaceName:desired.name,previousManaged,snapshot:snap,desired,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+rollbackMs).toISOString()};scheduleRollback();return {token:pending.token,interfaceName:desired.name,expiresAt:pending.expiresAt,status:await getHostInterfaceManagementStatus()}}
export async function confirmHostInterfaceChange(tokenInput:any){const token=String(tokenInput??"");if(!pending||pending.token!==token)throw new Error("Pending interface change was not found or token is invalid");cancelTimer();const current=await readConfig(),desired={...pending.desired,updatedAt:new Date().toISOString(),createdAt:pending.previousManaged?.createdAt??pending.desired.createdAt};current.interfaces=current.interfaces.filter(x=>x.name!==desired.name);current.interfaces.push(desired);current.updatedAt=new Date().toISOString();await saveConfig(current);pending=null;return getHostInterfaceManagementStatus()}
export async function rollbackPendingInterfaceChange(tokenInput?:any){if(!pending)return getHostInterfaceManagementStatus();if(tokenInput!==undefined&&String(tokenInput)!==pending.token)throw new Error("Pending interface change token is invalid");const change=pending;pending=null;cancelTimer();await restoreSnapshot(change.interfaceName,change.snapshot);return getHostInterfaceManagementStatus()}
export async function forgetManagedHostInterface(nameInput:any){const name=validateName(nameInput);if(pending?.interfaceName===name)throw new Error("Confirm or rollback the pending change first");const current=await readConfig(),before=current.interfaces.length;current.interfaces=current.interfaces.filter(x=>x.name!==name);if(current.interfaces.length===before)throw new Error(`Interface ${name} is not managed by DRM`);current.updatedAt=new Date().toISOString();await saveConfig(current);await stopDhcp(name);return getHostInterfaceManagementStatus()}

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

export async function restoreManagedHostInterfaces(){const current=await readConfig();for(const c of current.interfaces.filter(x=>x.enabled)){try{if(c.vlan)await ensureManagedVlan(c.vlan.parent,c.vlan.vlanId);await applyRuntime(c)}catch(error){console.warn(`DRM host interface restore failed for ${c.name}`,error)}}}
