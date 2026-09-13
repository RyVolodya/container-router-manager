import type { Topology, NatStatus, HostInterfaceManagementStatus } from "./types";

let csrfToken = "";
export function setCsrfToken(token:string){ csrfToken=token; }

type DrmNotificationType="success"|"error"|"info";
function emitNotification(type:DrmNotificationType,message:string,detail?:string){
  window.dispatchEvent(new CustomEvent("drm-notification",{detail:{type,message,detail}}));
}

function mutationSuccessMessage(url:string,method:string){
  if(url==="/api/auth/change-password") return "Password changed";
  if(url.includes("/management/users")){
    if(method==="DELETE") return "User deleted";
    if(url.endsWith("/role")) return "User role updated";
    if(url.endsWith("/reset-password")) return "User password reset";
    if(method==="POST") return "User added";
  }
  if(url==="/api/networks" && method==="POST") return "Docker network created";
  if(url.startsWith("/api/networks/") && method==="DELETE") return "Docker network deleted";
  if(/\/api\/containers\/[^/]+\/networks\/[^/]+\/connect$/.test(url)) return "Network connected to container";
  if(/\/api\/containers\/[^/]+\/networks\/[^/]+\/disconnect$/.test(url)) return "Network disconnected from container";
  if(/\/api\/containers\/[^/]+\/networks\/[^/]+\/ip$/.test(url) && method==="PUT") return "Container IP address updated";
  if(/\/api\/containers\/[^/]+\/network-policy$/.test(url) && method==="PUT") return "Persistent network configuration saved";
  if(/\/api\/containers\/[^/]+\/network-policy$/.test(url) && method==="DELETE") return "Persistent network configuration disabled";
  if(url==="/api/firewall/rules" && method==="POST") return "Firewall rule added";
  if(url.startsWith("/api/firewall/rules/") && method==="DELETE") return "Firewall rule deleted";
  if(url==="/api/firewall/access-rules" && method==="POST") return "Container access rule added";
  if(url==="/api/firewall/access-rules/reorder") return "Container access rule order updated";
  if(url.startsWith("/api/firewall/access-rules/") && method==="PUT") return "Container access rule updated";
  if(url.startsWith("/api/firewall/access-rules/") && method==="DELETE") return "Container access rule deleted";
  if(url==="/api/firewall/host-input-rules" && method==="POST") return "Host INPUT rule added";
  if(url.startsWith("/api/firewall/host-input-rules/") && method==="DELETE") return "Host INPUT rule deleted";
  if(url==="/api/firewall/published-port-rules" && method==="POST") return "Published-port rule added";
  if(url.startsWith("/api/firewall/published-port-rules/") && method==="DELETE") return "Published-port rule deleted";
  if(url==="/api/firewall/apply") return "Firewall changes applied";
  if(url==="/api/firewall/disable") return "Firewall Engine disabled";
  if(url==="/api/firewall/rollback") return "Firewall configuration rolled back";
  if(url==="/api/routing/routes" && method==="POST") return "Route added";
  if(url.startsWith("/api/routing/routes/") && method==="PUT") return "Route updated";
  if(url.startsWith("/api/routing/routes/") && method==="DELETE") return "Route deleted";
  if(url==="/api/routing/ip-forward") return "IPv4 forwarding updated";
  if(url==="/api/routing/ip-forward6") return "IPv6 forwarding updated";
  if(url==="/api/interfaces/apply") return "Interface change applied temporarily";
  if(url==="/api/interfaces/confirm") return "Interface configuration confirmed";
  if(url==="/api/interfaces/rollback") return "Interface configuration rolled back";
  if(url.startsWith("/api/interfaces/vlans/") && method==="DELETE") return "VLAN interface deleted";
  if(url.startsWith("/api/interfaces/") && url.endsWith("/managed") && method==="DELETE") return "Interface removed from DRM management";
  if(url==="/api/nat/rules" && method==="POST") return "NAT rule added";
  if(url.startsWith("/api/nat/rules/") && method==="PUT") return "NAT rule updated";
  if(url.startsWith("/api/nat/rules/") && method==="DELETE") return "NAT rule deleted";
  if(url==="/api/wireguard/interfaces" && method==="POST") return "WireGuard interface created";
  if(/^\/api\/wireguard\/interfaces\/[^/]+$/.test(url) && method==="DELETE") return "WireGuard interface deleted";
  if(/\/wireguard\/interfaces\/[^/]+\/peers$/.test(url) && method==="POST") return "WireGuard peer added";
  if(/\/wireguard\/interfaces\/[^/]+\/peers\/[^/]+$/.test(url) && method==="PUT") return "WireGuard peer updated";
  if(/\/wireguard\/interfaces\/[^/]+\/peers\/[^/]+$/.test(url) && method==="DELETE") return "WireGuard peer deleted";
  if(url.endsWith("/enabled")) return "WireGuard peer state updated";
  if(url.endsWith("/access")) return "WireGuard access policy applied";
  if(url.endsWith("/ipv6")) return "WireGuard IPv6 settings updated";
  return "Configuration updated";
}

async function apiFetch(url:string, init:RequestInit={}) {
  const method=(init.method ?? "GET").toUpperCase();
  const mutation=!["GET","HEAD","OPTIONS"].includes(method);
  const headers=new Headers(init.headers ?? {});
  if(mutation && csrfToken) headers.set("X-CSRF-Token",csrfToken);

  let response:Response;
  try{
    response=await fetch(url,{...init,headers,credentials:"same-origin"});
  }catch(error){
    if(mutation && url!=="/api/auth/login" && url!=="/api/auth/logout"){
      emitNotification("error","Request failed",error instanceof Error?error.message:String(error));
    }
    throw error;
  }

  if(!response.ok){
    const text=await response.text();
    let message=text;
    let code:string|undefined;
    try{const parsed=JSON.parse(text);message=parsed.message??text;code=parsed.error;}catch{}

    // Only a confirmed authentication failure expires the UI session.
    if(response.status===401 && url!=="/api/auth/login"){
      window.dispatchEvent(new Event("drm-auth-expired"));
    }

    if(mutation && url!=="/api/auth/login" && url!=="/api/auth/logout"){
      emitNotification("error","Change failed",message);
    }

    const error=new Error(message) as Error & {status?:number;code?:string};
    error.status=response.status;
    error.code=code;
    throw error;
  }

  let result:any=null;
  if(response.status!==204){
    const type=response.headers.get("content-type") ?? "";
    result=type.includes("application/json") ? await response.json() : await response.text();
  }

  if(mutation && url!=="/api/auth/login" && url!=="/api/auth/logout"){
    emitNotification("success",mutationSuccessMessage(url,method));
  }

  return result;
}

export async function login(username:string,password:string){
  const result=await apiFetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});
  setCsrfToken(result.csrfToken); return result;
}
export async function getMe(){const result=await apiFetch("/api/auth/me");setCsrfToken(result.csrfToken);return result;}
export type UpdateStatus={configured:boolean;currentVersion:string;latestVersion:string|null;updateAvailable:boolean;releaseName:string|null;releaseUrl:string|null;publishedAt:string|null;repository:string|null;error?:string};
export async function getUpdateStatus():Promise<UpdateStatus>{return apiFetch("/api/system/update");}
export async function logout(){await apiFetch("/api/auth/logout",{method:"POST"});setCsrfToken("");}
export async function changePassword(currentPassword:string,newPassword:string){return apiFetch("/api/auth/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({currentPassword,newPassword})});}
export const listManagementUsers=()=>apiFetch("/api/management/users");
export const addManagementUser=(body:any)=>apiFetch("/api/management/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const changeManagementRole=(id:string,role:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}/role`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({role})});
export const resetManagementPassword=(id:string,password:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}/reset-password`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});
export const removeManagementUser=(id:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}`,{method:"DELETE"});

export async function getTopology(signal?: AbortSignal): Promise<Topology> {return apiFetch("/api/topology",{signal});}
export type NetworkSuggestion={pool:string;prefixLength:number;subnet:string;gateway:string;conflicts:string[]};
export type HostNetworkInterface={name:string;kind:string|null;state:string;up:boolean;vlanId:number|null;parent:string|null;managed:boolean};
export const getDockerNetworkParents=():Promise<HostNetworkInterface[]>=>apiFetch("/api/networks/host-interfaces");
export const getManagedVlans=():Promise<HostNetworkInterface[]>=>apiFetch("/api/networks/vlans");
export const createManagedVlan=(parent:string,vlanId:number)=>apiFetch("/api/networks/vlans",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({parent,vlanId})});
export const removeManagedVlan=(name:string)=>apiFetch(`/api/networks/vlans/${encodeURIComponent(name)}`,{method:"DELETE"});
export const suggestDockerNetworkSubnet=(pool:string,prefixLength:number):Promise<NetworkSuggestion>=>apiFetch(`/api/networks/suggest?pool=${encodeURIComponent(pool)}&prefixLength=${prefixLength}`);
export const createDockerNetwork=(body:any)=>apiFetch("/api/networks",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeDockerNetwork=(id:string)=>apiFetch(`/api/networks/${encodeURIComponent(id)}`,{method:"DELETE"});
export type ContainerNetworkIpInfo={networkId:string;networkName:string;subnet:string;gateway:string|null;usedIps:Array<{ip:string;containerId:string;containerName:string}>;nextFreeIp:string|null};
export const getContainerNetworkIpInfo=(containerId:string,networkId:string):Promise<ContainerNetworkIpInfo>=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/networks/${encodeURIComponent(networkId)}/ip-info`);
export const connectContainerNetwork=(containerId:string,networkId:string,body:any)=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/networks/${encodeURIComponent(networkId)}/connect`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const disconnectContainerNetwork=(containerId:string,networkId:string,force=false)=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/networks/${encodeURIComponent(networkId)}/disconnect`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({force})});
export const changeContainerNetworkIp=(containerId:string,networkId:string,body:any)=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/networks/${encodeURIComponent(networkId)}/ip`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export type ContainerNetworkPolicyRuntime={state:"idle"|"waiting"|"applied"|"error";lastCheckedAt:string|null;lastAppliedAt:string|null;lastSeenContainerId:string|null;message:string|null};
export type ContainerNetworkPolicy={id:string;enabled:boolean;identity:{kind:"compose"|"name";key:string;project?:string;service?:string;containerNumber?:string;name?:string};displayName:string;desiredNetworks:Array<{networkName:string;ipv4Address:string|null}>;createdAt:string;updatedAt:string;runtime:ContainerNetworkPolicyRuntime};
export type ContainerNetworkPolicyResponse={supportedIdentity:{kind:"compose"|"name";key:string;project?:string;service?:string;containerNumber?:string;name?:string};policy:ContainerNetworkPolicy|null};
export const getContainerNetworkPolicy=(containerId:string):Promise<ContainerNetworkPolicyResponse>=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/network-policy`);
export const saveContainerNetworkPolicy=(containerId:string):Promise<ContainerNetworkPolicy>=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/network-policy`,{method:"PUT"});
export const removeContainerNetworkPolicy=(containerId:string)=>apiFetch(`/api/containers/${encodeURIComponent(containerId)}/network-policy`,{method:"DELETE"});
export const getFirewallStatus=()=>apiFetch("/api/firewall/status");
export const createFirewallRule=(rule:any)=>apiFetch("/api/firewall/rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeFirewallRule=(id:string)=>apiFetch(`/api/firewall/rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const reorderFirewallRules=(ids:string[])=>apiFetch("/api/firewall/rules/reorder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})});
export const firewallAction=(action:"apply"|"disable"|"rollback")=>apiFetch(`/api/firewall/${action}`,{method:"POST"});
export const createPublishedPortRule=(rule:any)=>apiFetch("/api/firewall/published-port-rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const updatePublishedPortRule=(id:string,rule:any)=>apiFetch(`/api/firewall/published-port-rules/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removePublishedPortRule=(id:string)=>apiFetch(`/api/firewall/published-port-rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const reorderPublishedPortRules=(ids:string[])=>apiFetch("/api/firewall/published-port-rules/reorder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})});
export const getNetworkStats=()=>apiFetch("/api/stats/network");
export const getRoutingStatus=()=>apiFetch("/api/routing/status");
export const setRoutingForward=(enabled:boolean)=>apiFetch("/api/routing/ip-forward",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});
export const setRoutingForward6=(enabled:boolean)=>apiFetch("/api/routing/ip-forward6",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});
export const createRoute=(route:any)=>apiFetch("/api/routing/routes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(route)});
export const updateRoute=(id:string,route:any)=>apiFetch(`/api/routing/routes/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(route)});
export const removeRoute=(id:string)=>apiFetch(`/api/routing/routes/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getVrfStatus=()=>apiFetch("/api/vrf/status");
export const createVrf=(body:any)=>apiFetch("/api/vrf",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const updateVrf=(id:string,body:any)=>apiFetch(`/api/vrf/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeVrf=(id:string)=>apiFetch(`/api/vrf/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getWireGuard=()=>apiFetch("/api/wireguard/status");
export const createWgInterface=(body:any)=>apiFetch("/api/wireguard/interfaces",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const updateWgInterface=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeWgInterface=(name:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}`,{method:"DELETE"});
export const createWgPeer=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeWgPeer=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getWgClientConfig=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}/config`);

export const getWgClientQr=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}/qr`);

export const createHostInputRule=(rule:any)=>apiFetch("/api/firewall/host-input-rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeHostInputRule=(id:string)=>apiFetch(`/api/firewall/host-input-rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const reorderHostInputRules=(ids:string[])=>apiFetch("/api/firewall/host-input-rules/reorder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})});
export const createAccessRule=(rule:any)=>apiFetch("/api/firewall/access-rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const updateAccessRule=(id:string,rule:any)=>apiFetch(`/api/firewall/access-rules/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeAccessRule=(id:string)=>apiFetch(`/api/firewall/access-rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const reorderAccessRules=(ids:string[])=>apiFetch("/api/firewall/access-rules/reorder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})});
export const setWgAccessPolicy=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/access`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});

export const setWgIpv6=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/ipv6`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});

export const updateWgPeer=(name:string,id:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const setWgPeerEnabled=(name:string,id:string,enabled:boolean)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}/enabled`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});

export const getNatStatus=():Promise<NatStatus>=>apiFetch("/api/nat/status");
export const createNatRule=(rule:any)=>apiFetch("/api/nat/rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const updateNatRule=(id:string,rule:any)=>apiFetch(`/api/nat/rules/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeNatRule=(id:string)=>apiFetch(`/api/nat/rules/${encodeURIComponent(id)}`,{method:"DELETE"});

export const getHostInterfacesStatus=():Promise<HostInterfaceManagementStatus>=>apiFetch("/api/interfaces/status");
export const applyHostInterface=(body:any)=>apiFetch("/api/interfaces/apply",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const confirmHostInterface=(token:string)=>apiFetch("/api/interfaces/confirm",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
export const rollbackHostInterface=(token?:string)=>apiFetch("/api/interfaces/rollback",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})});
export const forgetHostInterface=(name:string)=>apiFetch(`/api/interfaces/${encodeURIComponent(name)}/managed`,{method:"DELETE"});

export const deleteHostVlan=(name:string)=>apiFetch(`/api/interfaces/vlans/${encodeURIComponent(name)}`,{method:"DELETE"});
