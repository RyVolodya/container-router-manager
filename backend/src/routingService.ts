import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";

const execFileAsync=promisify(execFile);
const dataDir=process.env.DRM_DATA_DIR??"/data";
const routesPath=`${dataDir}/routes.json`;
const hostProcSys=process.env.HOST_PROC_SYS??"/proc/sys";

type RouteFamily=4|6;
type ManagedRoute={id:string;family:RouteFamily;destination:string;gateway?:string|null;dev?:string|null;metric?:number|null;table?:number|null;enabled:boolean};

async function ip(args:string[]){const {stdout}=await execFileAsync("ip",args,{maxBuffer:1024*1024});return stdout;}
function familyFromDestination(destination:string):RouteFamily{return destination.includes(":")?6:4;}
function normalizeManagedRoute(raw:any):ManagedRoute{return {id:String(raw.id??randomUUID()),family:raw.family===6?6:familyFromDestination(String(raw.destination??"")),destination:String(raw.destination??""),gateway:raw.gateway||null,dev:raw.dev||null,metric:raw.metric==null?null:Number(raw.metric),table:raw.table==null?null:Number(raw.table),enabled:raw.enabled!==false};}
async function readManagedRoutes():Promise<ManagedRoute[]>{await mkdir(dataDir,{recursive:true});try{return (JSON.parse(await readFile(routesPath,"utf8")) as any[]).map(normalizeManagedRoute)}catch{return[]}}
async function saveManagedRoutes(routes:ManagedRoute[]){await mkdir(dataDir,{recursive:true});await writeFile(routesPath,JSON.stringify(routes,null,2));}
async function readForward(family:RouteFamily){const path=family===4?`${hostProcSys}/net/ipv4/ip_forward`:`${hostProcSys}/net/ipv6/conf/all/forwarding`;try{return (await readFile(path,"utf8")).trim()==="1"}catch{return false}}
async function writeForward(family:RouteFamily,enabled:boolean){const path=family===4?`${hostProcSys}/net/ipv4/ip_forward`:`${hostProcSys}/net/ipv6/conf/all/forwarding`;await writeFile(path,enabled?"1\n":"0\n");}

function validateIpForFamily(value:string,family:RouteFamily,label:string){const plain=value.split("/")[0];if(isIP(plain)!==family)throw new Error(`${label} must be IPv${family} address`);}
function validateRoute(input:any){
  if(!input.destination||typeof input.destination!=="string")throw new Error("Destination is required");
  const family:RouteFamily=input.family===6?6:input.family===4?4:familyFromDestination(input.destination);
  const [destIp,prefixRaw]=String(input.destination).split("/"); const prefix=Number(prefixRaw);
  if(isIP(destIp)!==family||!Number.isInteger(prefix)||prefix<0||(family===4&&prefix>32)||(family===6&&prefix>128))throw new Error(`Invalid IPv${family} destination`);
  if(!input.gateway&&!input.dev)throw new Error("Gateway or interface is required");
  if(input.gateway)validateIpForFamily(String(input.gateway),family,"Gateway");
  if(input.metric!=null&&(!Number.isInteger(Number(input.metric))||Number(input.metric)<0))throw new Error("Metric must be >= 0");
  if(input.table!=null&&(!Number.isInteger(Number(input.table))||Number(input.table)<1))throw new Error("Routing table must be a positive integer");
  return family;
}
async function applyOne(route:ManagedRoute){const args=[route.family===6?"-6":"-4","route","replace"];if(route.table!=null)args.push("table",String(route.table));args.push(route.destination);if(route.gateway)args.push("via",route.gateway);if(route.dev)args.push("dev",route.dev);if(route.metric!=null)args.push("metric",String(route.metric));await ip(args);}
async function deleteOne(route:ManagedRoute){const args=[route.family===6?"-6":"-4","route","del"];if(route.table!=null)args.push("table",String(route.table));args.push(route.destination);if(route.gateway)args.push("via",route.gateway);if(route.dev)args.push("dev",route.dev);try{await ip(args)}catch{}}

export async function getRoutingStatus(){
  const [v4Raw,v6Raw,addrRaw,linkRaw,managed,ipForward,ipForward6]=await Promise.all([
    ip(["-j","-4","route","show","table","main"]),ip(["-j","-6","route","show","table","main"]),ip(["-j","addr","show"]),ip(["-j","link","show"]),readManagedRoutes(),readForward(4),readForward(6)
  ]);
  const routes4=(JSON.parse(v4Raw) as any[]).map(r=>({...r,family:4}));
  const routes6=(JSON.parse(v6Raw) as any[]).map(r=>({...r,family:6}));
  return {ipForward,ipForward6,routes:[...routes4,...routes6],routes4,routes6,addresses:JSON.parse(addrRaw),links:JSON.parse(linkRaw),managedRoutes:managed};
}
export async function setIpForward(enabled:boolean){await writeForward(4,enabled);return getRoutingStatus();}
export async function setIpForward6(enabled:boolean){await writeForward(6,enabled);return getRoutingStatus();}
export async function addManagedRoute(input:any){const family=validateRoute(input);const route:ManagedRoute={id:randomUUID(),family,destination:String(input.destination),gateway:input.gateway||null,dev:input.dev||null,metric:input.metric==null?null:Number(input.metric),table:input.table==null?null:Number(input.table),enabled:true};await applyOne(route);const routes=await readManagedRoutes();routes.push(route);await saveManagedRoutes(routes);return route;}
export async function updateManagedRoute(id:string,input:any){const routes=await readManagedRoutes();const index=routes.findIndex(r=>r.id===id);if(index<0)throw new Error("Route not found");const old=routes[index];const family=validateRoute(input);const updated:ManagedRoute={...old,family,destination:String(input.destination),gateway:input.gateway||null,dev:input.dev||null,metric:input.metric==null?null:Number(input.metric),table:input.table==null?null:Number(input.table),enabled:input.enabled!==false};await deleteOne(old);if(updated.enabled)await applyOne(updated);routes[index]=updated;await saveManagedRoutes(routes);return updated;}
export async function deleteManagedRoute(id:string){const routes=await readManagedRoutes();const route=routes.find(r=>r.id===id);if(!route)throw new Error("Route not found");await deleteOne(route);await saveManagedRoutes(routes.filter(r=>r.id!==id));}
export async function restoreManagedRoutes(){const routes=await readManagedRoutes();for(const route of routes.filter(r=>r.enabled)){try{await applyOne(route)}catch(e){console.warn("DRM route restore failed",route.destination,e)}}}
