import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import QRCode from "qrcode";
const hostProcSys = process.env.HOST_PROC_SYS || "/host-proc-sys";

const dataDir=process.env.DRM_DATA_DIR ?? "/data";
const wgDir=`${dataDir}/wireguard`;
const statePath=`${wgDir}/state.json`;

type Peer={
  id:string;
  name:string;
  mode?:"remote-access"|"site-to-site";
  enabled?:boolean;
  publicKey:string;
  privateKey?:string;
  serverAllowedIps:string[];
  clientAllowedIps:string[];
  clientAddress?:string;
  clientIpv6Address?:string;
  remoteNetworks?:string[];
  endpoint?:string;
  endpointHost?:string;
  endpointPort?:number;
  dns?:string;
  persistentKeepalive:number;
};

type WgAccessPolicy={
  enabled:boolean;
  dockerCidrs:string[];
  lanCidrs:string[];
  internet:boolean;
  nat:boolean;
  wanInterface?:string;
  internet6?:boolean;
  nat66?:boolean;
  wanInterface6?:string;
};

type WgInterface={
  name:string;
  address?:string; // legacy v0.9.0 field
  ipv6Address?:string;
  addresses?:string[];
  listenPort:number;
  mtu:number;
  privateKey:string;
  publicKey:string;
  peers:Peer[];
  accessPolicy?:WgAccessPolicy;
};

type WgState={interfaces:WgInterface[]};

async function run(cmd:string,args:string[],stdin?:string){
  return await new Promise<string>((resolve,reject)=>{
    const child=spawn(cmd,args,{stdio:["pipe","pipe","pipe"]});
    let stdout="";
    let stderr="";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data",(chunk:string)=>{stdout+=chunk;});
    child.stderr.on("data",(chunk:string)=>{stderr+=chunk;});
    child.on("error",reject);
    child.on("close",code=>code===0?resolve(stdout.trim()):reject(new Error(`${cmd} ${args.join(" ")} failed with code ${code}: ${stderr.trim()}`)));
    if(stdin!==undefined) child.stdin.write(stdin);
    child.stdin.end();
  });
}

function uniq(values:string[]){return [...new Set(values.filter(Boolean))];}
function cidrFamily(cidr:string){return cidr.includes(":")?6:cidr.includes(".")?4:0;}
function autoIpv6GatewayFromIpv4(ipv4Cidr:string){
  const [ip]=ipv4Cidr.split("/");
  const o=ip.split(".").map(Number);
  if(o.length!==4 || o.some(x=>!Number.isInteger(x)||x<0||x>255)) return "fd42:8::1/64";
  // Create a stable ULA /64 from the two middle IPv4 octets.
  const a=o[1].toString(16);
  const b=o[2].toString(16);
  return b==="0" ? `fd42:${a}::1/64` : `fd42:${a}:${b}::1/64`;
}
function autoIpv6PeerFromGateway(gatewayCidr:string,index:number){
  const base=gatewayCidr.split("/")[0];
  const host=Math.max(2,index+2).toString(16);
  if(base.endsWith("::1")) return `${base.slice(0,-1)}${host}/128`;
  const pos=base.lastIndexOf(":");
  return pos>=0 ? `${base.slice(0,pos+1)}${host}/128` : undefined;
}
function normalizeInterface(item:WgInterface){
  const addresses=uniq([
    ...(item.addresses??[]),
    ...(item.address?[item.address]:[]),
    ...(item.ipv6Address?[item.ipv6Address]:[])
  ]);
  return {...item,addresses};
}
async function load():Promise<WgState>{
  await mkdir(wgDir,{recursive:true});
  try{
    const parsed=JSON.parse(await readFile(statePath,"utf8")) as WgState;
    return {interfaces:(parsed.interfaces??[]).map(normalizeInterface)};
  }catch{return{interfaces:[]};}
}
async function save(state:WgState){
  const normalized={interfaces:state.interfaces.map(normalizeInterface)};
  await mkdir(wgDir,{recursive:true});
  await writeFile(statePath,JSON.stringify(normalized,null,2),{mode:0o600});
}
function validName(name:string){if(!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(name)) throw new Error("Invalid interface name");}
function validateCidr(cidr:string){
  const [ip,prefixRaw]=cidr.trim().split("/");
  const fam=isIP(ip); const prefix=Number(prefixRaw);
  if(!fam || !Number.isInteger(prefix) || prefix<0 || (fam===4&&prefix>32) || (fam===6&&prefix>128)) throw new Error(`Invalid CIDR: ${cidr}`);
  return fam;
}

function peerMode(peer:Peer){return peer.mode??"remote-access";}
function peerEnabled(peer:Peer){return peer.enabled!==false;}
function peerRemoteNetworks(peer:Peer){return uniq((peer.remoteNetworks??[]).map(x=>x.trim())).filter(Boolean);}
function computedServerAllowedIps(peer:Peer){
  if(peerMode(peer)!=="site-to-site") return uniq(peer.serverAllowedIps??[]);
  return uniq([peer.clientAddress??"",peer.clientIpv6Address??"",...peerRemoteNetworks(peer)]).filter(Boolean);
}
function cidrRange(cidr:string):{family:4|6;start:bigint;end:bigint}{
  const [ip,prefixRaw]=cidr.split('/'); const prefix=Number(prefixRaw); const family=isIP(ip) as 4|6;
  if(family===4){
    const o=ip.split('.').map(Number); let value=0n; for(const n of o)value=(value<<8n)|BigInt(n);
    const bits=32n; const host=bits-BigInt(prefix); const mask=host===32n?0n:((1n<<bits)-1n)^((1n<<host)-1n); const start=value&mask; const end=start+((1n<<host)-1n); return{family,start,end};
  }
  const expand=(addr:string)=>{const [l,r='']=addr.split('::');const la=l?l.split(':'):[];const ra=r?r.split(':'):[];const missing=8-la.length-ra.length;return [...la,...Array(Math.max(0,missing)).fill('0'),...ra].map(x=>parseInt(x||'0',16));};
  const h=expand(ip); let value=0n; for(const n of h)value=(value<<16n)|BigInt(n); const bits=128n; const host=bits-BigInt(prefix); const mask=host===128n?0n:((1n<<bits)-1n)^((1n<<host)-1n); const start=value&mask; const end=start+((1n<<host)-1n); return{family,start,end};
}
function cidrOverlaps(a:string,b:string){const A=cidrRange(a),B=cidrRange(b);return A.family===B.family && A.start<=B.end && B.start<=A.end;}
function validatePeerOverlap(item:WgInterface,candidate:Peer,excludeId?:string){
  const cand=computedServerAllowedIps(candidate); cand.forEach(validateCidr);
  for(const other of item.peers){if(other.id===excludeId || !peerEnabled(other))continue; for(const a of cand)for(const b of computedServerAllowedIps(other)){if(cidrOverlaps(a,b))throw new Error(`AllowedIPs overlap: ${a} conflicts with peer ${other.name} (${b})`);}}
}
async function removePeerRoutes(item:WgInterface,networks:string[]){
  for(const cidr of networks){
    try{await run('ip',[cidrFamily(cidr)===6?'-6':'-4','route','del',cidr,'dev',item.name]);}catch{}
  }
}
async function syncPeerRoutes(item:WgInterface){
  // Remove only routes previously managed by site-to-site peers in current state, then recreate enabled ones.
  // Route ownership is identified by destination+wg interface. Errors on missing routes are harmless.
  for(const peer of item.peers){
    for(const cidr of peerRemoteNetworks(peer)){
      try{await run('ip',[cidrFamily(cidr)===6?'-6':'-4','route','del',cidr,'dev',item.name]);}catch{}
    }
  }
  for(const peer of item.peers.filter(p=>peerEnabled(p)&&peerMode(p)==='site-to-site')){
    for(const cidr of peerRemoteNetworks(peer)){
      validateCidr(cidr); await run('ip',[cidrFamily(cidr)===6?'-6':'-4','route','replace',cidr,'dev',item.name]);
    }
  }
}
async function genKeyPair(){const privateKey=await run("wg",["genkey"]);const publicKey=await run("wg",["pubkey"],privateKey+"\n");return{privateKey,publicKey};}
async function keyFile(name:string,key:string){const path=`${wgDir}/${name}.key`;await writeFile(path,key+"\n",{mode:0o600});return path;}

const wgForwardChain="DRM-WG-FORWARD";
const wgNatChain="DRM-WG-NAT";
const wgRawChain="DRM-WG-RAW";
const wg6ForwardChain="DRM-WG6-FORWARD";
const wg6NatChain="DRM-WG6-NAT";
const wg6RawChain="DRM-WG6-RAW";

async function ipt(args:string[]){return run("iptables",["-w","5",...args]);}
async function iptNat(args:string[]){return run("iptables",["-w","5","-t","nat",...args]);}
async function iptRaw(args:string[]){return run("iptables",["-w","5","-t","raw",...args]);}
async function ip6t(args:string[]){return run("ip6tables",["-w","5",...args]);}
async function ip6tNat(args:string[]){return run("ip6tables",["-w","5","-t","nat",...args]);}
async function ip6tRaw(args:string[]){return run("ip6tables",["-w","5","-t","raw",...args]);}

async function chainExists(fn:(a:string[])=>Promise<string>,name:string){try{await fn(["-n","-L",name]);return true}catch{return false;}}
async function ensureJump(fn:(a:string[])=>Promise<string>,parent:string,chain:string,position="1"){
  while(true){try{await fn(["-D",parent,"-j",chain]);}catch{break;}}
  await fn(["-I",parent,position,"-j",chain]);
}

async function ensureAccessChains(){
  if(!(await chainExists(ipt,wgForwardChain))) await ipt(["-N",wgForwardChain]);
  if(!(await chainExists(iptNat,wgNatChain))) await iptNat(["-N",wgNatChain]);
  if(!(await chainExists(iptRaw,wgRawChain))) await iptRaw(["-N",wgRawChain]);
  if(!(await chainExists(ip6t,wg6ForwardChain))) await ip6t(["-N",wg6ForwardChain]);
  // ip6tables nat exists on supported modern kernels; failure is tolerated later when NAT66 is unused.
  try{if(!(await chainExists(ip6tNat,wg6NatChain))) await ip6tNat(["-N",wg6NatChain]);}catch{}
  if(!(await chainExists(ip6tRaw,wg6RawChain))) await ip6tRaw(["-N",wg6RawChain]);

  // Docker v28+ may add raw/PREROUTING drops for direct access to container IPs.
  // Our exception must run before those Docker-generated drops.
  await ensureJump(iptRaw,"PREROUTING",wgRawChain,"1");
  await ensureJump(ip6tRaw,"PREROUTING",wg6RawChain,"1");

  // Keep DOCKER-USER before DRM WireGuard forwarding. Insert DRM after it if present.
  while(true){try{await ipt(["-D","FORWARD","-j",wgForwardChain]);}catch{break;}}
  let pos4=1;
  try{
    const rules=(await ipt(["-S","FORWARD"])).split("\n").filter(x=>x.startsWith("-A FORWARD "));
    const idx=rules.findIndex(x=>x.includes("-j DOCKER-USER"));
    pos4=idx>=0?idx+2:1;
  }catch{}
  await ipt(["-I","FORWARD",String(pos4),"-j",wgForwardChain]);

  while(true){try{await ip6t(["-D","FORWARD","-j",wg6ForwardChain]);}catch{break;}}
  let pos6=1;
  try{
    const rules=(await ip6t(["-S","FORWARD"])).split("\n").filter(x=>x.startsWith("-A FORWARD "));
    const idx=rules.findIndex(x=>x.includes("-j DOCKER-USER"));
    pos6=idx>=0?idx+2:1;
  }catch{}
  await ip6t(["-I","FORWARD",String(pos6),"-j",wg6ForwardChain]);

  try{await iptNat(["-C","POSTROUTING","-j",wgNatChain]);}catch{await iptNat(["-I","POSTROUTING","1","-j",wgNatChain]);}
  try{await ip6tNat(["-C","POSTROUTING","-j",wg6NatChain]);}catch{try{await ip6tNat(["-I","POSTROUTING","1","-j",wg6NatChain]);}catch{}}
}

function addressesForFamily(item:WgInterface,family:4|6){return normalizeInterface(item).addresses!.filter(x=>cidrFamily(x)===family);}
function cidrsForFamily(values:string[],family:4|6){return values.filter(x=>cidrFamily(x)===family);}

async function applyAccessPolicies(state:WgState){
  await ensureAccessChains();
  await ipt(["-F",wgForwardChain]); await iptNat(["-F",wgNatChain]); await iptRaw(["-F",wgRawChain]);
  await ip6t(["-F",wg6ForwardChain]); await ip6tRaw(["-F",wg6RawChain]);
  try{await ip6tNat(["-F",wg6NatChain]);}catch{}

  await ipt(["-A",wgForwardChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"]);
  await ip6t(["-A",wg6ForwardChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"]);

  const active=state.interfaces.filter(i=>i.accessPolicy?.enabled);
  if(active.some(i=>addressesForFamily(i,4).length)){try{await writeFile(`${hostProcSys}/net/ipv4/ip_forward`,"1\n");}catch(e){console.warn("DRM IPv4 forwarding enable failed",e)}}
  if(active.some(i=>addressesForFamily(i,6).length)){try{await writeFile(`${hostProcSys}/net/ipv6/conf/all/forwarding`,"1\n");}catch(e){console.warn("DRM IPv6 forwarding enable failed",e)}}

  for(const item of active){
    const p=item.accessPolicy!;
    const src4=addressesForFamily(item,4)[0];
    const src6=addressesForFamily(item,6)[0];
    const remote4=uniq(item.peers.filter(x=>peerEnabled(x)&&peerMode(x)==="site-to-site").flatMap(peerRemoteNetworks).filter(x=>cidrFamily(x)===4));
    const remote6=uniq(item.peers.filter(x=>peerEnabled(x)&&peerMode(x)==="site-to-site").flatMap(peerRemoteNetworks).filter(x=>cidrFamily(x)===6));
    const docker4=cidrsForFamily(p.dockerCidrs,4);
    const docker6=cidrsForFamily(p.dockerCidrs,6);
    const lan4=cidrsForFamily(p.lanCidrs,4);
    const lan6=cidrsForFamily(p.lanCidrs,6);

    if(src4){
      // raw exception specifically for selected Docker networks: bypass Docker direct-IP raw drops.
      for(const cidr of docker4){
        await iptRaw(["-A",wgRawChain,"-i",item.name,"-s",src4,"-d",cidr,"-m","comment","--comment",`DRM:wg-raw:${item.name}:docker`,"-j","ACCEPT"]);
      }
      for(const cidr of [...docker4,...lan4]){
        await ipt(["-A",wgForwardChain,"-i",item.name,"-s",src4,"-d",cidr,"-m","comment","--comment",`DRM:wg:${item.name}:route`,"-j","ACCEPT"]);
      }
      if(p.internet){
        if(!p.wanInterface) throw new Error(`IPv4 WAN interface is required for ${item.name}`);
        await ipt(["-A",wgForwardChain,"-i",item.name,"-s",src4,"-o",p.wanInterface,"-m","comment","--comment",`DRM:wg:${item.name}:internet`,"-j","ACCEPT"]);
        if(p.nat) await iptNat(["-A",wgNatChain,"-s",src4,"-o",p.wanInterface,"-m","comment","--comment",`DRM:wg-nat:${item.name}`,"-j","MASQUERADE"]);
      }
      for(const remote of remote4){
        for(const cidr of docker4) await iptRaw(["-A",wgRawChain,"-i",item.name,"-s",remote,"-d",cidr,"-m","comment","--comment",`DRM:wg-raw:${item.name}:site`,"-j","ACCEPT"]);
        for(const cidr of [...docker4,...lan4]) await ipt(["-A",wgForwardChain,"-i",item.name,"-s",remote,"-d",cidr,"-m","comment","--comment",`DRM:wg:${item.name}:site`,"-j","ACCEPT"]);
        await ipt(["-A",wgForwardChain,"-i",item.name,"-s",remote,"-m","comment","--comment",`DRM:wg:${item.name}:site-default-drop`,"-j","DROP"]);
      }
      await ipt(["-A",wgForwardChain,"-i",item.name,"-s",src4,"-m","comment","--comment",`DRM:wg:${item.name}:default-drop`,"-j","DROP"]);
    }

    if(src6){
      for(const cidr of docker6){
        await ip6tRaw(["-A",wg6RawChain,"-i",item.name,"-s",src6,"-d",cidr,"-m","comment","--comment",`DRM:wg6-raw:${item.name}:docker`,"-j","ACCEPT"]);
      }
      for(const cidr of [...docker6,...lan6]){
        await ip6t(["-A",wg6ForwardChain,"-i",item.name,"-s",src6,"-d",cidr,"-m","comment","--comment",`DRM:wg6:${item.name}:route`,"-j","ACCEPT"]);
      }
      if(p.internet6){
        const wan6=p.wanInterface6||p.wanInterface;
        if(!wan6) throw new Error(`IPv6 WAN interface is required for ${item.name}`);
        await ip6t(["-A",wg6ForwardChain,"-i",item.name,"-s",src6,"-o",wan6,"-m","comment","--comment",`DRM:wg6:${item.name}:internet`,"-j","ACCEPT"]);
        if(p.nat66){
          try{await ip6tNat(["-A",wg6NatChain,"-s",src6,"-o",wan6,"-m","comment","--comment",`DRM:wg6-nat:${item.name}`,"-j","MASQUERADE"]);}
          catch(e){throw new Error(`IPv6 NAT66 is unavailable on this host: ${e instanceof Error?e.message:String(e)}`);}
        }
      }
      for(const remote of remote6){
        for(const cidr of docker6) await ip6tRaw(["-A",wg6RawChain,"-i",item.name,"-s",remote,"-d",cidr,"-m","comment","--comment",`DRM:wg6-raw:${item.name}:site`,"-j","ACCEPT"]);
        for(const cidr of [...docker6,...lan6]) await ip6t(["-A",wg6ForwardChain,"-i",item.name,"-s",remote,"-d",cidr,"-m","comment","--comment",`DRM:wg6:${item.name}:site`,"-j","ACCEPT"]);
        await ip6t(["-A",wg6ForwardChain,"-i",item.name,"-s",remote,"-m","comment","--comment",`DRM:wg6:${item.name}:site-default-drop`,"-j","DROP"]);
      }
      await ip6t(["-A",wg6ForwardChain,"-i",item.name,"-s",src6,"-m","comment","--comment",`DRM:wg6:${item.name}:default-drop`,"-j","DROP"]);
    }
  }

  await iptRaw(["-A",wgRawChain,"-j","RETURN"]); await ip6tRaw(["-A",wg6RawChain,"-j","RETURN"]);
  await ipt(["-A",wgForwardChain,"-j","RETURN"]); await ip6t(["-A",wg6ForwardChain,"-j","RETURN"]);
}

async function getHostRoutingHints(){
  let defaultWanInterface:string|undefined;
  let defaultWanInterface6:string|undefined;
  let interfaces:string[]=[];
  try{defaultWanInterface=(JSON.parse(await run("ip",["-j","-4","route","show","default"])) as any[])[0]?.dev;}catch{}
  try{defaultWanInterface6=(JSON.parse(await run("ip",["-j","-6","route","show","default"])) as any[])[0]?.dev;}catch{}
  try{interfaces=(JSON.parse(await run("ip",["-j","link","show"])) as any[]).map(x=>String(x.ifname)).filter(x=>x!=="lo").sort();}catch{}
  return{defaultWanInterface,defaultWanInterface6,interfaces};
}

export async function setWireGuardAccessPolicy(iface:string,input:any){
  validName(iface);
  const state=await load();
  const item=state.interfaces.find(i=>i.name===iface);
  if(!item) throw new Error("Interface not found");
  const dockerCidrs=(input.dockerCidrs??[]).map(String).filter(Boolean); dockerCidrs.forEach(validateCidr);
  const lanCidrs=(input.lanCidrs??[]).map(String).filter(Boolean); lanCidrs.forEach(validateCidr);
  item.accessPolicy={
    enabled:Boolean(input.enabled),dockerCidrs,lanCidrs,
    internet:Boolean(input.internet),nat:Boolean(input.nat),wanInterface:input.wanInterface?String(input.wanInterface):undefined,
    internet6:Boolean(input.internet6),nat66:Boolean(input.nat66),wanInterface6:input.wanInterface6?String(input.wanInterface6):undefined
  };
  await save(state); await applyAccessPolicies(state); return getWireGuardStatus();
}

function endpointString(peer:Peer){
  if(peer.endpointHost && peer.endpointPort){
    const host=peer.endpointHost.includes(":")&&!peer.endpointHost.startsWith("[")?`[${peer.endpointHost}]`:peer.endpointHost;
    return `${host}:${peer.endpointPort}`;
  }
  return peer.endpoint;
}
function endpointParts(peer:Peer){
  if(peer.endpointHost&&peer.endpointPort)return{endpointHost:peer.endpointHost,endpointPort:peer.endpointPort};
  const raw=peer.endpoint??""; const ipv6=raw.match(/^\[([^\]]+)\]:(\d+)$/); if(ipv6)return{endpointHost:ipv6[1],endpointPort:Number(ipv6[2])};
  const pos=raw.lastIndexOf(":"); if(pos>0&&/^\d+$/.test(raw.slice(pos+1)))return{endpointHost:raw.slice(0,pos),endpointPort:Number(raw.slice(pos+1))};
  return{endpointHost:raw||undefined,endpointPort:undefined};
}

async function applyInterface(item:WgInterface){
  validName(item.name);
  const normalized=normalizeInterface(item);
  if(!normalized.addresses?.length) throw new Error("At least one WireGuard interface address is required");
  normalized.addresses.forEach(validateCidr);
  try{await run("ip",["link","show","dev",item.name]);}catch{await run("ip",["link","add","dev",item.name,"type","wireguard"]);}
  const kf=await keyFile(item.name,item.privateKey);
  await run("wg",["set",item.name,"private-key",kf,"listen-port",String(item.listenPort)]);
  try{await run("ip",["address","flush","dev",item.name,"scope","global"]);}catch{}
  for(const address of normalized.addresses) await run("ip",["address","add",address,"dev",item.name]);
  await run("ip",["link","set","dev",item.name,"mtu",String(item.mtu),"up"]);
  for(const peer of item.peers){
    if(!peerEnabled(peer)){try{await run("wg",["set",item.name,"peer",peer.publicKey,"remove"]);}catch{};continue;}
    const allowed=computedServerAllowedIps(peer); validatePeerOverlap(item,peer,peer.id);
    const args=["set",item.name,"peer",peer.publicKey];
    if(allowed.length) args.push("allowed-ips",allowed.join(","));
    const endpoint=endpointString(peer); if(endpoint) args.push("endpoint",endpoint);
    if(peer.persistentKeepalive>0) args.push("persistent-keepalive",String(peer.persistentKeepalive));
    await run("wg",args);
  }
  await syncPeerRoutes(item);
}

export async function restoreWireGuard(){
  const state=await load();
  for(const item of state.interfaces){try{await applyInterface(item);}catch(e){console.warn("DRM WG restore failed",item.name,e);}}
  try{await applyAccessPolicies(state);}catch(e){console.warn("DRM WG access restore failed",e);}
}

type PeerRuntime={endpoint:string|null;remoteIp:string|null;remotePort:number|null;latestHandshake:number;latestHandshakeAt:string|null;handshakeAgeSeconds:number|null;rxBytes:number;txBytes:number;status:"active"|"idle"|"never";};
function splitRuntimeEndpoint(endpoint:string){
  if(!endpoint||endpoint==="(none)")return{remoteIp:null,remotePort:null};
  const ipv6=endpoint.match(/^\[([^\]]+)\]:(\d+)$/); if(ipv6)return{remoteIp:ipv6[1],remotePort:Number(ipv6[2])};
  const pos=endpoint.lastIndexOf(":"); if(pos>0&&/^\d+$/.test(endpoint.slice(pos+1)))return{remoteIp:endpoint.slice(0,pos),remotePort:Number(endpoint.slice(pos+1))};
  return{remoteIp:endpoint,remotePort:null};
}
function emptyPeerRuntime():PeerRuntime{return{endpoint:null,remoteIp:null,remotePort:null,latestHandshake:0,latestHandshakeAt:null,handshakeAgeSeconds:null,rxBytes:0,txBytes:0,status:"never"};}
async function getRuntimePeers(){
  const result=new Map<string,Map<string,PeerRuntime>>();
  try{
    const raw=await run("wg",["show","all","dump"]); const now=Math.floor(Date.now()/1000);
    for(const line of raw.split("\n").filter(Boolean)){
      const f=line.split("\t"); if(f.length<9)continue;
      const [iface,publicKey,_psk,endpoint,_allowedIps,handshakeRaw,rxRaw,txRaw]=f;
      const latestHandshake=Number(handshakeRaw||0); const age=latestHandshake>0?Math.max(0,now-latestHandshake):null; const remote=splitRuntimeEndpoint(endpoint);
      const runtime:PeerRuntime={endpoint:endpoint&&endpoint!=="(none)"?endpoint:null,remoteIp:remote.remoteIp,remotePort:remote.remotePort,latestHandshake,latestHandshakeAt:latestHandshake>0?new Date(latestHandshake*1000).toISOString():null,handshakeAgeSeconds:age,rxBytes:Number(rxRaw||0),txBytes:Number(txRaw||0),status:latestHandshake===0?"never":(age!==null&&age<=180?"active":"idle")};
      if(!result.has(iface))result.set(iface,new Map()); result.get(iface)!.set(publicKey,runtime);
    }
  }catch{}
  return result;
}

export async function getWireGuardStatus(){
  const state=await load(); const runtimePeers=await getRuntimePeers(); const hints=await getHostRoutingHints();
  return{
    defaultWanInterface:hints.defaultWanInterface??null,
    defaultWanInterface6:hints.defaultWanInterface6??null,
    hostInterfaces:hints.interfaces,
    interfaces:state.interfaces.map(raw=>{
      const i=normalizeInterface(raw); const v4=i.addresses!.find(a=>cidrFamily(a)===4); const v6=i.addresses!.find(a=>cidrFamily(a)===6);
      return{name:i.name,address:v4??i.addresses![0]??"",ipv6Address:v6??null,addresses:i.addresses,listenPort:i.listenPort,mtu:i.mtu,publicKey:i.publicKey,
        accessPolicy:i.accessPolicy??{enabled:false,dockerCidrs:[],lanCidrs:[],internet:false,nat:false,wanInterface:hints.defaultWanInterface,internet6:false,nat66:false,wanInterface6:hints.defaultWanInterface6},
        peers:i.peers.map(p=>({...p,mode:peerMode(p),enabled:peerEnabled(p),remoteNetworks:peerRemoteNetworks(p),serverAllowedIps:computedServerAllowedIps(p),...endpointParts(p),privateKey:undefined,runtime:runtimePeers.get(i.name)?.get(p.publicKey)??emptyPeerRuntime()}))};
    })
  };
}

export async function createWireGuardInterface(input:any){
  const name=String(input.name||"wg0"); validName(name); const state=await load(); if(state.interfaces.some(i=>i.name===name))throw new Error("Interface already exists");
  const ipv4Address=input.address?String(input.address).trim():"";
  const ipv6Enabled=Boolean(input.ipv6Enabled || input.ipv6Address);
  const generatedIpv6=ipv6Enabled ? (input.ipv6Address?String(input.ipv6Address).trim():autoIpv6GatewayFromIpv4(ipv4Address||"10.8.0.1/24")) : "";
  const addresses=uniq([...(ipv4Address?[ipv4Address]:[]),...(generatedIpv6?[generatedIpv6]:[]),...((input.addresses??[]) as any[]).map(String).map(x=>x.trim())]).filter(Boolean);
  if(!addresses.length)throw new Error("At least one IPv4 or IPv6 address is required"); addresses.forEach(validateCidr);
  const keys=await genKeyPair();
  const item:WgInterface={name,address:addresses.find(a=>cidrFamily(a)===4),ipv6Address:addresses.find(a=>cidrFamily(a)===6),addresses,listenPort:Number(input.listenPort||51820),mtu:Number(input.mtu||1420),privateKey:keys.privateKey,publicKey:keys.publicKey,peers:[],accessPolicy:{enabled:false,dockerCidrs:[],lanCidrs:[],internet:false,nat:false,internet6:Boolean(generatedIpv6),nat66:Boolean(generatedIpv6)}};
  await applyInterface(item); state.interfaces.push(item); await save(state); return{name:item.name,publicKey:item.publicKey};
}

export async function updateWireGuardInterface(iface:string,input:any){
  validName(iface);
  const state=await load();
  const item=state.interfaces.find(i=>i.name===iface);
  if(!item) throw new Error("Interface not found");

  // Interface identity/private key are preserved. Renaming requires recreate.
  if(input.name!==undefined && String(input.name)!==iface) throw new Error("WireGuard interface name cannot be changed; recreate the interface to rename it");

  const current=normalizeInterface(item);
  const ipv4Address=input.address!==undefined?String(input.address??"").trim():(addressesForFamily(current,4)[0]??"");
  if(!ipv4Address) throw new Error("IPv4 gateway is required");
  if(validateCidr(ipv4Address)!==4) throw new Error("IPv4 gateway must be an IPv4 CIDR");

  const ipv6Enabled=input.ipv6Enabled!==undefined
    ? Boolean(input.ipv6Enabled)
    : Boolean(input.ipv6Address!==undefined ? input.ipv6Address : current.ipv6Address);
  let ipv6Address="";
  if(ipv6Enabled){
    ipv6Address=String(input.ipv6Address??current.ipv6Address??autoIpv6GatewayFromIpv4(ipv4Address)).trim();
    if(validateCidr(ipv6Address)!==6) throw new Error("IPv6 gateway must be an IPv6 CIDR");
  }

  const listenPort=input.listenPort!==undefined?Number(input.listenPort):item.listenPort;
  if(!Number.isInteger(listenPort)||listenPort<1||listenPort>65535) throw new Error("Listen port must be 1..65535");
  const mtu=input.mtu!==undefined?Number(input.mtu):item.mtu;
  if(!Number.isInteger(mtu)||mtu<576||mtu>9000) throw new Error("MTU must be 576..9000");

  item.address=ipv4Address;
  item.ipv6Address=ipv6Enabled?ipv6Address:undefined;
  item.addresses=uniq([ipv4Address,...(ipv6Enabled?[ipv6Address]:[])]);
  item.listenPort=listenPort;
  item.mtu=mtu;

  if(ipv6Enabled){
    item.peers.forEach((peer,index)=>{
      const clientV6=peer.clientIpv6Address||autoIpv6PeerFromGateway(ipv6Address,index);
      if(clientV6){
        peer.clientIpv6Address=clientV6;
        if(!peer.serverAllowedIps.includes(clientV6))peer.serverAllowedIps.push(clientV6);
        if(peer.clientAllowedIps.includes("0.0.0.0/0")&&!peer.clientAllowedIps.includes("::/0"))peer.clientAllowedIps.push("::/0");
      }
    });
  }else{
    item.peers.forEach(peer=>{
      peer.clientIpv6Address=undefined;
      peer.serverAllowedIps=peer.serverAllowedIps.filter(x=>cidrFamily(x)!==6);
      peer.clientAllowedIps=peer.clientAllowedIps.filter(x=>cidrFamily(x)!==6);
    });
    if(item.accessPolicy){
      item.accessPolicy.internet6=false;
      item.accessPolicy.nat66=false;
      item.accessPolicy.dockerCidrs=item.accessPolicy.dockerCidrs.filter(x=>cidrFamily(x)!==6);
      item.accessPolicy.lanCidrs=item.accessPolicy.lanCidrs.filter(x=>cidrFamily(x)!==6);
    }
  }

  await applyInterface(item);
  await save(state);
  await applyAccessPolicies(state);
  return getWireGuardStatus();
}

export async function configureWireGuardIpv6(iface:string,input:any){
  validName(iface);
  const state=await load();
  const item=state.interfaces.find(i=>i.name===iface);
  if(!item) throw new Error("Interface not found");
  const normalized=normalizeInterface(item);
  const v4=addressesForFamily(normalized,4);
  const enabled=Boolean(input.enabled);

  if(enabled){
    const gateway=String(input.ipv6Address||normalized.addresses?.find(a=>cidrFamily(a)===6)||autoIpv6GatewayFromIpv4(v4[0]||"10.8.0.1/24")).trim();
    if(validateCidr(gateway)!==6) throw new Error("IPv6 gateway must be an IPv6 CIDR");
    item.ipv6Address=gateway;
    item.addresses=uniq([...v4,gateway]);

    item.peers.forEach((peer,index)=>{
      const clientV6=peer.clientIpv6Address||autoIpv6PeerFromGateway(gateway,index);
      if(clientV6){
        peer.clientIpv6Address=clientV6;
        if(!peer.serverAllowedIps.includes(clientV6)) peer.serverAllowedIps.push(clientV6);
        // If this is an IPv4 full-tunnel peer, make it dual-stack automatically.
        if(peer.clientAllowedIps.includes("0.0.0.0/0") && !peer.clientAllowedIps.includes("::/0")) peer.clientAllowedIps.push("::/0");
      }
    });

    item.accessPolicy=item.accessPolicy??{enabled:false,dockerCidrs:[],lanCidrs:[],internet:false,nat:false};
    if(item.accessPolicy.internet){
      item.accessPolicy.internet6=true;
      item.accessPolicy.nat66=true;
    }
  }else{
    item.ipv6Address=undefined;
    item.addresses=v4;
    item.peers.forEach(peer=>{
      peer.clientIpv6Address=undefined;
      peer.serverAllowedIps=peer.serverAllowedIps.filter(x=>cidrFamily(x)!==6);
      peer.clientAllowedIps=peer.clientAllowedIps.filter(x=>cidrFamily(x)!==6);
    });
    if(item.accessPolicy){
      item.accessPolicy.internet6=false;
      item.accessPolicy.nat66=false;
      item.accessPolicy.dockerCidrs=item.accessPolicy.dockerCidrs.filter(x=>cidrFamily(x)!==6);
      item.accessPolicy.lanCidrs=item.accessPolicy.lanCidrs.filter(x=>cidrFamily(x)!==6);
    }
  }

  await applyInterface(item);
  await save(state);
  await applyAccessPolicies(state);
  return getWireGuardStatus();
}

export async function deleteWireGuardInterface(name:string){
  validName(name); const state=await load(); const item=state.interfaces.find(i=>i.name===name); if(!item)throw new Error("Interface is not managed by DRM");
  try{await run("ip",["link","del","dev",name]);}catch{}
  await rm(`${wgDir}/${name}.key`,{force:true}); state.interfaces=state.interfaces.filter(i=>i.name!==name); await save(state); await applyAccessPolicies(state);
}

export async function addWireGuardPeer(iface:string,input:any){
  validName(iface); const state=await load(); const item=state.interfaces.find(i=>i.name===iface); if(!item)throw new Error("Interface not found");
  const keys=input.publicKey?{publicKey:String(input.publicKey),privateKey:undefined}:await genKeyPair();
  const mode=input.mode==="site-to-site"?"site-to-site":"remote-access";
  const enabled=input.enabled!==false;
  const clientAddress=input.clientAddress?String(input.clientAddress).trim():undefined; if(clientAddress)validateCidr(clientAddress);
  const ifaceV6=addressesForFamily(item,6)[0];
  const requestedClientV6=input.clientIpv6Address?String(input.clientIpv6Address).trim():undefined;
  const clientIpv6Address=requestedClientV6 || (ifaceV6 ? autoIpv6PeerFromGateway(ifaceV6,item.peers.length) : undefined); if(clientIpv6Address)validateCidr(clientIpv6Address);
  const remoteNetworks=(input.remoteNetworks||[]).map(String).map((x:string)=>x.trim()).filter(Boolean); remoteNetworks.forEach(validateCidr);
  let serverAllowedIps=(input.serverAllowedIps||[]).map(String).map((x:string)=>x.trim()).filter(Boolean); serverAllowedIps.forEach(validateCidr);
  if(mode==="site-to-site") serverAllowedIps=uniq([clientAddress??"",clientIpv6Address??"",...remoteNetworks]).filter(Boolean);
  else if(clientIpv6Address && !serverAllowedIps.includes(clientIpv6Address)) serverAllowedIps.push(clientIpv6Address);
  const clientAllowedIps=(input.clientAllowedIps||[]).map(String).map((x:string)=>x.trim()).filter(Boolean); clientAllowedIps.forEach(validateCidr);
  const endpointHost=input.endpointHost?String(input.endpointHost).trim():undefined; const endpointPort=input.endpointPort?Number(input.endpointPort):undefined;
  if(endpointPort!==undefined&&(!Number.isInteger(endpointPort)||endpointPort<1||endpointPort>65535))throw new Error("Endpoint port must be 1..65535");
  const peer:Peer={id:randomUUID(),name:String(input.name||"peer"),mode,enabled,publicKey:keys.publicKey,privateKey:keys.privateKey,serverAllowedIps,clientAllowedIps,clientAddress,clientIpv6Address,remoteNetworks,endpoint:input.endpoint?String(input.endpoint):undefined,endpointHost,endpointPort,dns:input.dns?String(input.dns).trim():undefined,persistentKeepalive:Number(input.persistentKeepalive||0)};
  validatePeerOverlap(item,peer); item.peers.push(peer); await applyInterface(item); await save(state); await applyAccessPolicies(state); return{id:peer.id,publicKey:peer.publicKey,clientConfigAvailable:Boolean(peer.privateKey)};
}

export async function updateWireGuardPeer(iface:string,id:string,input:any){
  validName(iface); const state=await load(); const item=state.interfaces.find(i=>i.name===iface); if(!item)throw new Error("Interface not found"); const peer=item.peers.find(p=>p.id===id); if(!peer)throw new Error("Peer not found");
  if(input.publicKey && String(input.publicKey)!==peer.publicKey) throw new Error("Public key cannot be changed in Edit; recreate the peer to change identity");
  const mode=input.mode==="site-to-site"?"site-to-site":input.mode==="remote-access"?"remote-access":peerMode(peer);
  const remoteNetworks=(input.remoteNetworks??peer.remoteNetworks??[]).map(String).map((x:string)=>x.trim()).filter(Boolean); remoteNetworks.forEach(validateCidr);
  const clientAddress=input.clientAddress===null?undefined:input.clientAddress!==undefined?String(input.clientAddress).trim():peer.clientAddress; if(clientAddress)validateCidr(clientAddress);
  const clientIpv6Address=input.clientIpv6Address===null?undefined:input.clientIpv6Address!==undefined?String(input.clientIpv6Address).trim():peer.clientIpv6Address; if(clientIpv6Address)validateCidr(clientIpv6Address);
  let serverAllowedIps=(input.serverAllowedIps??peer.serverAllowedIps??[]).map(String).map((x:string)=>x.trim()).filter(Boolean); serverAllowedIps.forEach(validateCidr);
  if(mode==="site-to-site")serverAllowedIps=uniq([clientAddress??"",clientIpv6Address??"",...remoteNetworks]).filter(Boolean);
  const clientAllowedIps=(input.clientAllowedIps??peer.clientAllowedIps??[]).map(String).map((x:string)=>x.trim()).filter(Boolean);clientAllowedIps.forEach(validateCidr);
  const next:Peer={...peer,name:input.name!==undefined?String(input.name):peer.name,mode,enabled:input.enabled!==undefined?Boolean(input.enabled):peerEnabled(peer),clientAddress,clientIpv6Address,remoteNetworks,serverAllowedIps,clientAllowedIps,endpointHost:input.endpointHost!==undefined?String(input.endpointHost).trim()||undefined:peer.endpointHost,endpointPort:input.endpointPort!==undefined?(input.endpointPort?Number(input.endpointPort):undefined):peer.endpointPort,dns:input.dns!==undefined?(String(input.dns).trim()||undefined):peer.dns,persistentKeepalive:input.persistentKeepalive!==undefined?Number(input.persistentKeepalive||0):peer.persistentKeepalive};
  if(next.endpointPort!==undefined&&(!Number.isInteger(next.endpointPort)||next.endpointPort<1||next.endpointPort>65535))throw new Error("Endpoint port must be 1..65535");
  validatePeerOverlap(item,next,id); const oldRemote=peerRemoteNetworks(peer); await removePeerRoutes(item,oldRemote); Object.assign(peer,next); await applyInterface(item); await save(state); await applyAccessPolicies(state); return getWireGuardStatus();
}

export async function setWireGuardPeerEnabled(iface:string,id:string,enabled:boolean){
  const state=await load(); const item=state.interfaces.find(i=>i.name===iface); if(!item)throw new Error("Interface not found"); const peer=item.peers.find(p=>p.id===id); if(!peer)throw new Error("Peer not found");
  peer.enabled=enabled; if(!enabled){try{await run("wg",["set",iface,"peer",peer.publicKey,"remove"]);}catch{}}
  await applyInterface(item); await save(state); await applyAccessPolicies(state); return getWireGuardStatus();
}

export async function deleteWireGuardPeer(iface:string,id:string){
  const state=await load(); const item=state.interfaces.find(i=>i.name===iface); if(!item)throw new Error("Interface not found"); const peer=item.peers.find(p=>p.id===id); if(!peer)throw new Error("Peer not found");
  try{await run("wg",["set",iface,"peer",peer.publicKey,"remove"]);}catch{}
  await removePeerRoutes(item,peerRemoteNetworks(peer)); item.peers=item.peers.filter(p=>p.id!==id); await syncPeerRoutes(item); await save(state); await applyAccessPolicies(state);
}

export async function getClientConfig(iface:string,id:string){
  const state=await load(); const item=state.interfaces.find(i=>i.name===iface); if(!item)throw new Error("Interface not found"); const peer=item.peers.find(p=>p.id===id); if(!peer)throw new Error("Peer not found");
  if(!peerEnabled(peer))throw new Error("Peer is disabled");
  if(!peer.privateKey)throw new Error("Client private key is not stored for this peer");
  const clientAddresses=uniq([peer.clientAddress??"",peer.clientIpv6Address??""]).filter(Boolean); if(!clientAddresses.length)throw new Error("Client address is missing"); if(!endpointString(peer))throw new Error("Server endpoint is missing");
  const lines=["[Interface]",`PrivateKey = ${peer.privateKey}`,`Address = ${clientAddresses.join(", ")}`];
  if(peer.dns)lines.push(`DNS = ${peer.dns}`);
  const defaultClientRoutes=addressesForFamily(item,6).length?["0.0.0.0/0","::/0"]:["0.0.0.0/0"];
  lines.push("","[Peer]",`PublicKey = ${item.publicKey}`,`Endpoint = ${endpointString(peer)}`,`AllowedIPs = ${(peer.clientAllowedIps.length?peer.clientAllowedIps:defaultClientRoutes).join(", ")}`);
  if(peer.persistentKeepalive>0)lines.push(`PersistentKeepalive = ${peer.persistentKeepalive}`);
  return lines.join("\n")+"\n";
}

export async function getClientConfigQrSvg(iface:string,id:string){
  const config=await getClientConfig(iface,id);
  return QRCode.toString(config,{type:"svg",errorCorrectionLevel:"M",margin:2,width:320});
}
