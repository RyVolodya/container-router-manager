import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
const execFileAsync=promisify(execFile),dataDir=process.env.DRM_DATA_DIR??"/data",configPath=`${dataDir}/vrfs.json`,hostProcSys=process.env.HOST_PROC_SYS??"/proc/sys";
const tableMin=29000,tableMax=29999;
export type ManagedVrf={id:string;name:string;table:number;interfaces:string[];enabled:boolean;description:string;createdAt:string;updatedAt:string};
type Config={vrfs:ManagedVrf[];updatedAt:string};
async function ip(args:string[]){return (await execFileAsync("ip",args,{maxBuffer:2*1024*1024})).stdout}

async function safeWrite(path:string,value:string){try{await writeFile(path,value)}catch(e){console.warn("DRM VRF sysctl write failed",path,e)}}
async function enableL3mdevHostAccess(){
  // Services listening in the default namespace must remain reachable from VRF interfaces.
  await Promise.all([
    safeWrite(`${hostProcSys}/net/ipv4/tcp_l3mdev_accept`,"1\n"),
    safeWrite(`${hostProcSys}/net/ipv4/udp_l3mdev_accept`,"1\n")
  ]);
}
async function copyDockerReachabilityRoutes(table:number){
  // A VRF default route would otherwise win before the main table for DNAT traffic
  // destined to Docker bridge networks (including the DRM frontend).
  let rows:any[]=[];
  try{rows=JSON.parse(await ip(["-j","-4","route","show","table","main"])) as any[]}catch{return}
  for(const r of rows){
    const dev=String(r.dev??"");
    const dst=String(r.dst??"");
    if(!dst||dst==="default"||!(dev==="docker0"||dev.startsWith("br-")))continue;
    const args=["-4","route","replace","table",String(table),dst,"dev",dev];
    if(r.scope)args.push("scope",String(r.scope));
    if(r.prefsrc)args.push("src",String(r.prefsrc));
    try{await ip(args)}catch(e){console.warn("DRM VRF Docker reachability route failed",table,dst,dev,e)}
  }
}
async function captureInterfaceDefaults(name:string){
  try{return JSON.parse(await ip(["-j","-4","route","show","default","dev",name])) as any[]}catch{return []}
}
async function restoreInterfaceDefaultsToVrf(name:string,table:number,rows:any[]){
  for(const r of rows){
    const args=["-4","route","replace","table",String(table),"default"];
    if(r.gateway)args.push("via",String(r.gateway));
    args.push("dev",name);
    if(r.metric!==undefined)args.push("metric",String(r.metric));
    try{await ip(args)}catch(e){console.warn("DRM VRF default route restore failed",name,table,e)}
  }
}
function normalize(x:any):ManagedVrf{return {id:String(x.id??randomUUID()),name:String(x.name??""),table:Number(x.table),interfaces:Array.isArray(x.interfaces)?x.interfaces.map(String):[],enabled:x.enabled!==false,description:String(x.description??""),createdAt:x.createdAt??new Date().toISOString(),updatedAt:x.updatedAt??new Date().toISOString()}}
async function readConfig():Promise<Config>{await mkdir(dataDir,{recursive:true});try{const p=JSON.parse(await readFile(configPath,"utf8"));return {vrfs:Array.isArray(p.vrfs)?p.vrfs.map(normalize):[],updatedAt:p.updatedAt??new Date(0).toISOString()}}catch{return {vrfs:[],updatedAt:new Date(0).toISOString()}}}
async function saveConfig(c:Config){c.updatedAt=new Date().toISOString();await mkdir(dataDir,{recursive:true});await writeFile(configPath,JSON.stringify(c,null,2)+"\n")}
function validName(v:any){const n=String(v??"").trim();if(!/^[A-Za-z0-9_.-]{1,15}$/.test(n)||n==="lo")throw new Error("VRF name must be 1-15 characters");return n}
function validTable(v:any){const n=Number(v);if(!Number.isInteger(n)||n<tableMin||n>tableMax)throw new Error(`VRF table must be ${tableMin}-${tableMax}`);return n}
async function links(){return JSON.parse(await ip(["-d","-j","link","show"])) as any[]}
async function assertInterface(name:string,ignore?:string){const rows=await links(),r=rows.find(x=>x.ifname===name);if(!r)throw new Error(`Interface ${name} does not exist`);if(name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth")||["bridge","veth","vrf"].includes(r.linkinfo?.info_kind))throw new Error(`Interface ${name} cannot be attached to a DRM VRF`);if(r.master&&r.master!==ignore)throw new Error(`Interface ${name} is already attached to ${r.master}`)}
async function ensureDevice(v:ManagedVrf){let ok=false;try{const r=(JSON.parse(await ip(["-d","-j","link","show","dev",v.name])) as any[])[0];ok=r?.linkinfo?.info_kind==="vrf"&&Number(r?.linkinfo?.info_data?.table)===v.table;if(r&&!ok)await ip(["link","del","dev",v.name])}catch{}if(!ok)await ip(["link","add",v.name,"type","vrf","table",String(v.table)]);await ip(["link","set","dev",v.name,"up"])}
async function attach(v:ManagedVrf){
  await enableL3mdevHostAccess();
  await ensureDevice(v);
  await copyDockerReachabilityRoutes(v.table);
  for(const n of v.interfaces){
    await assertInterface(n,v.name);
    const defaults=await captureInterfaceDefaults(n);
    await ip(["link","set","dev",n,"master",v.name]);
    await ip(["link","set","dev",n,"up"]);
    await restoreInterfaceDefaultsToVrf(n,v.table,defaults);
  }
}
async function removeRuntime(v:ManagedVrf){
  for(const n of v.interfaces)try{await ip(["link","set","dev",n,"nomaster"])}catch{}
  try{await ip(["link","del","dev",v.name])}catch{}
  try{await ip(["-4","route","flush","table",String(v.table)])}catch{}
  try{await ip(["-6","route","flush","table",String(v.table)])}catch{}
}
export async function getVrfStatus(){const config=await readConfig();let runtime:any[]=[];try{const r=await links();runtime=r.filter(x=>x.linkinfo?.info_kind==="vrf").map(x=>({name:x.ifname,table:Number(x.linkinfo?.info_data?.table),state:x.operstate??"UNKNOWN",interfaces:r.filter(y=>y.master===x.ifname).map(y=>y.ifname)}))}catch{}return {tableRange:{min:tableMin,max:tableMax},config,runtime}}
export async function createVrf(input:any){const c=await readConfig(),name=validName(input.name),table=validTable(input.table),interfaces=Array.isArray(input.interfaces)?[...new Set<string>(input.interfaces.map(String))]:[];if(c.vrfs.some(v=>v.name===name))throw new Error(`VRF ${name} already exists`);if(c.vrfs.some(v=>v.table===table))throw new Error(`Routing table ${table} is already used`);for(const n of interfaces)await assertInterface(n);const now=new Date().toISOString(),v:ManagedVrf={id:randomUUID(),name,table,interfaces,enabled:true,description:String(input.description??""),createdAt:now,updatedAt:now};await attach(v);c.vrfs.push(v);await saveConfig(c);return v}
export async function updateVrf(id:string,input:any){const c=await readConfig(),i=c.vrfs.findIndex(v=>v.id===id);if(i<0)throw new Error("VRF not found");const old=c.vrfs[i],name=validName(input.name??old.name),table=validTable(input.table??old.table),interfaces=Array.isArray(input.interfaces)?[...new Set<string>(input.interfaces.map(String))]:old.interfaces,enabled=input.enabled===undefined?old.enabled:Boolean(input.enabled);if(c.vrfs.some(v=>v.id!==id&&v.name===name))throw new Error(`VRF ${name} already exists`);if(c.vrfs.some(v=>v.id!==id&&v.table===table))throw new Error(`Routing table ${table} is already used`);for(const n of interfaces)await assertInterface(n,old.name);await removeRuntime(old);const next={...old,name,table,interfaces,enabled,description:String(input.description??old.description),updatedAt:new Date().toISOString()};if(enabled)await attach(next);c.vrfs[i]=next;await saveConfig(c);return next}
export async function deleteVrf(id:string){const c=await readConfig(),v=c.vrfs.find(x=>x.id===id);if(!v)throw new Error("VRF not found");await removeRuntime(v);c.vrfs=c.vrfs.filter(x=>x.id!==id);await saveConfig(c)}
export async function restoreVrfs(){const c=await readConfig();for(const v of c.vrfs.filter(v=>v.enabled))try{await attach(v)}catch(e){console.warn("DRM VRF restore failed",v.name,e)}}
export async function findVrfByInterface(name:string){const c=await readConfig();return c.vrfs.find(v=>v.enabled&&v.interfaces.includes(name))??null}
export async function routingTableForInterface(name:string){const vrf=await findVrfByInterface(name);return vrf?vrf.table:null}
export async function syncVrfReachabilityRoutes(){
  const c=await readConfig();
  for(const v of c.vrfs.filter(v=>v.enabled))await copyDockerReachabilityRoutes(v.table);
}
