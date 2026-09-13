import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { listNetworks } from "./dockerService.js";

const execFileAsync=promisify(execFile);
const dataDir=process.env.DRM_DATA_DIR??"/data";
const storePath=join(dataDir,"managed-vlans.json");

type ManagedVlan={name:string;parent:string;vlanId:number;createdAt:string};

type LinkRow={ifindex:number;ifname:string;mtu?:number;operstate?:string;flags?:string[];link_index?:number;linkinfo?:{info_kind?:string;info_data?:{id?:number}}};

async function loadManaged():Promise<ManagedVlan[]>{
  try{return JSON.parse(await fs.readFile(storePath,"utf8")) as ManagedVlan[];}catch{return []}
}
async function saveManaged(rows:ManagedVlan[]){await fs.mkdir(dirname(storePath),{recursive:true});await fs.writeFile(storePath,JSON.stringify(rows,null,2)+"\n","utf8")}
async function links():Promise<LinkRow[]>{
  const {stdout}=await execFileAsync("ip",["-d","-j","link","show"],{maxBuffer:1024*1024});
  return JSON.parse(stdout) as LinkRow[];
}
function validateVlanId(value:any){const id=Number(value);if(!Number.isInteger(id)||id<1||id>4094)throw new Error("VLAN ID must be between 1 and 4094");return id}
function validateParent(value:any){const name=String(value??"").trim();if(!name||name==="lo")throw new Error("A physical parent interface is required");if(!/^[A-Za-z0-9_.:-]+$/.test(name))throw new Error("Invalid parent interface name");return name}
function vlanName(parent:string,id:number){const name=`${parent}.${id}`;if(name.length>15)throw new Error(`VLAN interface name ${name} exceeds Linux 15-character limit`);return name}

export async function listHostInterfaces(){
  const all=await links();
  const byIndex=new Map(all.map(x=>[x.ifindex,x.ifname]));
  const managed=new Set((await loadManaged()).map(x=>x.name));
  return all.filter(x=>x.ifname!=="lo").map(x=>({
    name:x.ifname,index:x.ifindex,mtu:x.mtu??null,state:x.operstate??"UNKNOWN",up:(x.flags??[]).includes("UP"),
    kind:x.linkinfo?.info_kind??null,parent:x.link_index?byIndex.get(x.link_index)??null:null,
    vlanId:x.linkinfo?.info_kind==="vlan"?Number(x.linkinfo.info_data?.id??0)||null:null,
    managed:managed.has(x.ifname)
  })).sort((a,b)=>a.name.localeCompare(b.name));
}

export async function ensureManagedVlan(parentInput:any,vlanInput:any){
  const parent=validateParent(parentInput);const vlanId=validateVlanId(vlanInput);const name=vlanName(parent,vlanId);
  const all=await links();
  const parentLink=all.find(x=>x.ifname===parent);if(!parentLink)throw new Error(`Parent interface ${parent} does not exist`);
  const existing=all.find(x=>x.ifname===name);
  if(existing){
    if(existing.linkinfo?.info_kind!=="vlan"||Number(existing.linkinfo.info_data?.id)!==vlanId)throw new Error(`Interface ${name} already exists and is not VLAN ${vlanId}`);
    try{await execFileAsync("ip",["link","set","dev",name,"up"])}catch{}
    const rows=await loadManaged();
    return {name,parent,vlanId,created:false,managed:rows.some(x=>x.name===name)};
  }
  await execFileAsync("ip",["link","add","link",parent,"name",name,"type","vlan","id",String(vlanId)]);
  await execFileAsync("ip",["link","set","dev",name,"up"]);
  const rows=await loadManaged();
  if(!rows.some(x=>x.name===name)){rows.push({name,parent,vlanId,createdAt:new Date().toISOString()});await saveManaged(rows)}
  return {name,parent,vlanId,created:true,managed:true};
}

export async function deleteManagedVlan(nameInput:any,force=false){
  const name=String(nameInput??"").trim();
  const rows=await loadManaged(); const row=rows.find(x=>x.name===name);
  if(!row)throw new Error(`VLAN interface ${name} is not managed by DRM`);
  const networks=await listNetworks();
  const users=networks.filter((n:any)=>n.parent===name||n.options?.parent===name);
  if(users.length&&!force)throw new Error(`VLAN interface ${name} is used by Docker network(s): ${users.map((x:any)=>x.name).join(", ")}`);
  try{await execFileAsync("ip",["link","delete",name])}catch(error:any){
    const msg=String(error?.stderr??error?.message??error); if(!msg.includes("Cannot find device")&&!msg.includes("does not exist"))throw error;
  }
  await saveManaged(rows.filter(x=>x.name!==name));
}

export async function cleanupManagedVlanIfUnused(name:string){
  const rows=await loadManaged(); if(!rows.some(x=>x.name===name))return false;
  const networks=await listNetworks(); if(networks.some((n:any)=>n.parent===name||n.options?.parent===name))return false;
  await deleteManagedVlan(name); return true;
}

export async function restoreManagedVlans(){
  const rows=await loadManaged();
  for(const row of rows){
    try{
      const all=await links(); if(all.some(x=>x.ifname===row.name)){await execFileAsync("ip",["link","set","dev",row.name,"up"]);continue}
      if(!all.some(x=>x.ifname===row.parent)){console.warn(`DRM VLAN restore: parent ${row.parent} is unavailable for ${row.name}`);continue}
      await execFileAsync("ip",["link","add","link",row.parent,"name",row.name,"type","vlan","id",String(row.vlanId)]);
      await execFileAsync("ip",["link","set","dev",row.name,"up"]);
    }catch(error){console.warn(`DRM VLAN restore failed for ${row.name}`,error)}
  }
}
