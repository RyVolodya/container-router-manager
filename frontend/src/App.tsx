import { useEffect, useMemo, useState } from "react";
import {
  Activity, Boxes, Container, GitBranch, LayoutDashboard, Network,
  RefreshCw, Route, Search, Server, Shield, Wifi, CircleDot, Plug, Trash2, Pencil, KeyRound, Waypoints, Plus, UserCog, LogOut, Moon, Sun, Download, QrCode, X, CheckCircle2, AlertTriangle, Info, ChevronLeft, ChevronRight, Cable
} from "lucide-react";
import { Background, Controls, Edge, MarkerType, Node, ReactFlow, useNodesState } from "@xyflow/react";
import { getUpdateStatus, suggestDockerNetworkSubnet, createDockerNetwork, removeDockerNetwork, getDockerNetworkParents, getContainerNetworkIpInfo, connectContainerNetwork, disconnectContainerNetwork, changeContainerNetworkIp, getContainerNetworkPolicy, saveContainerNetworkPolicy, removeContainerNetworkPolicy,  addManagementUser, changeManagementRole, changePassword, createFirewallRule, createHostInputRule, createPublishedPortRule, updatePublishedPortRule, createAccessRule, updateAccessRule, removeAccessRule, reorderAccessRules, firewallAction, getFirewallStatus, getMe, getNetworkStats, getTopology, listManagementUsers, login, logout, removeFirewallRule, reorderFirewallRules, removeHostInputRule, reorderHostInputRules, removeManagementUser, removePublishedPortRule, reorderPublishedPortRules, resetManagementPassword, createRoute, createWgInterface, updateWgInterface, createWgPeer, getRoutingStatus, getWgClientConfig, getWgClientQr, getWireGuard, removeRoute, updateRoute, removeWgInterface, removeWgPeer, setRoutingForward, setRoutingForward6, setWgAccessPolicy, setWgIpv6, updateWgPeer, setWgPeerEnabled, getNatStatus, createNatRule, updateNatRule, removeNatRule, getHostInterfacesStatus, applyHostInterface, confirmHostInterface, rollbackHostInterface, forgetHostInterface, deleteHostVlan, getVrfStatus, createVrf, updateVrf, removeVrf } from "./api";
import type { DockerContainer, DockerNetwork, FirewallStatus, NetworkStatsResponse, RoutingStatus, Topology, WireGuardStatus, NatStatus, NatRule, NatDnatRule, NatOutboundRule, HostInterfaceManagementStatus, VrfStatus, ManagedVrf } from "./types";

type Page = "dashboard" | "networks" | "containers" | "ports" | "topology" | "firewall" | "interfaces" | "routing" | "nat" | "wireguard" | "management";

type AuthUser = {id:string;username:string;role:"administrator"|"operator"|"viewer";mustChangePassword:boolean;createdAt:string;updatedAt:string;lastLoginAt:string|null;disabled:boolean};

const navigation = [
  { id: "dashboard" as Page, label: "Dashboard", icon: LayoutDashboard },
  { id: "networks" as Page, label: "Networks", icon: Network },
  { id: "containers" as Page, label: "Containers", icon: Container },
  { id: "ports" as Page, label: "Ports", icon: Plug },
  { id: "topology" as Page, label: "Topology", icon: GitBranch },
  { id: "firewall" as Page, label: "Firewall", icon: Shield },
  { id: "interfaces" as Page, label: "Interfaces", icon: Cable },
  { id: "routing" as Page, label: "Routing", icon: Waypoints },
  { id: "nat" as Page, label: "NAT", icon: Route },
  { id: "wireguard" as Page, label: "WireGuard", icon: KeyRound },
  { id: "management" as Page, label: "Management", icon: UserCog }
];


type DrmNotification={
  id:string;
  type:"success"|"error"|"info";
  message:string;
  detail?:string;
  actionUrl?:string;
  actionLabel?:string;
};

function NotificationCenter(){
  const [items,setItems]=useState<DrmNotification[]>([]);

  useEffect(()=>{
    const handler=(event:Event)=>{
      const custom=event as CustomEvent<{type:"success"|"error"|"info";message:string;detail?:string;actionUrl?:string;actionLabel?:string}>;
      const detail=custom.detail;
      if(!detail?.message)return;
      const item:DrmNotification={
        id:`${Date.now()}-${Math.random().toString(36).slice(2)}`,
        type:detail.type||"info",
        message:detail.message,
        detail:detail.detail,
        actionUrl:detail.actionUrl,
        actionLabel:detail.actionLabel
      };
      setItems(current=>[item,...current].slice(0,20));
    };
    window.addEventListener("drm-notification",handler);
    return()=>window.removeEventListener("drm-notification",handler);
  },[]);

  if(!items.length)return null;

  return <div className="notification-center" aria-live="polite">
    {items.length>1&&<button className="notification-clear" onClick={()=>setItems([])}>Clear all</button>}
    {items.map(item=>{
      const Icon=item.type==="success"?CheckCircle2:item.type==="error"?AlertTriangle:Info;
      return <div key={item.id} className={`drm-notification ${item.type}`}>
        <Icon size={18}/>
        <div className="notification-copy">
          <strong>{item.message}</strong>
          {item.detail&&<span>{item.detail}</span>}
          {item.actionUrl&&<a className="notification-action" href={item.actionUrl} target="_blank" rel="noreferrer">{item.actionLabel||"Open"}</a>}
        </div>
        <button className="notification-close" onClick={()=>setItems(current=>current.filter(x=>x.id!==item.id))} title="Close"><X size={16}/></button>
      </div>;
    })}
  </div>;
}

function MainApp({auth,onAuthChange,onLogout,theme,onToggleTheme}:{auth:AuthUser;onAuthChange:(u:AuthUser)=>void;onLogout:()=>void;theme:"dark"|"light";onToggleTheme:()=>void}) {
  const [page, setPage] = useState<Page>("dashboard");
  const [data, setData] = useState<Topology | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [firewallStatus, setFirewallStatus] = useState<FirewallStatus | null>(null);
  const [trafficRates, setTrafficRates] = useState<Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}>>({});
  const [sidebarCollapsed,setSidebarCollapsed]=useState(()=>localStorage.getItem("drm-sidebar-collapsed")==="1");
  useEffect(()=>{localStorage.setItem("drm-sidebar-collapsed",sidebarCollapsed?"1":"0")},[sidebarCollapsed]);

  async function refresh() {
    setLoading(true);
    try {
      const [result, fw] = await Promise.all([
        getTopology(),
        getFirewallStatus()
      ]);
      setData(result);
      setFirewallStatus(fw);
      setLastUpdate(new Date());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 10000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let previous: NetworkStatsResponse | null = null;
    async function pollTraffic() {
      try {
        const current = await getNetworkStats() as NetworkStatsResponse;
        if (previous) {
          const prevById = new Map(previous.containers.map(c => [c.id, c]));
          const elapsed = Math.max(0.25,(new Date(current.generatedAt).getTime()-new Date(previous.generatedAt).getTime())/1000);
          const next: Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}> = {};
          for (const c of current.containers) { const prev=prevById.get(c.id); next[c.id]={rxRate:prev?Math.max(0,(c.rxBytes-prev.rxBytes)/elapsed):0,txRate:prev?Math.max(0,(c.txBytes-prev.txBytes)/elapsed):0,rxBytes:c.rxBytes,txBytes:c.txBytes}; }
          setTrafficRates(next);
        }
        previous=current;
      } catch {}
    }
    pollTraffic();
    const timer=window.setInterval(pollTraffic,2000);
    return ()=>window.clearInterval(timer);
  }, []);

  const filteredNetworks = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stable = [...(data?.networks ?? [])].sort((a,b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    if (!q) return stable;
    return stable.filter(n =>
      [n.name, n.driver, ...n.subnets.flatMap(s => [s.subnet ?? "", s.gateway ?? ""])]
        .some(v => v.toLowerCase().includes(q))
    );
  }, [data, query]);

  const filteredContainers = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stable = [...(data?.containers ?? [])].sort((a,b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    if (!q) return stable;
    return stable.filter(c =>
      [
        c.name, c.image, c.state,
        ...c.networks.flatMap(n => [n.networkName, n.ipv4Address ?? ""]),
        ...c.ports.flatMap(p => [
          p.containerPort,
          ...p.published.map(x => `${x.hostIp}:${x.hostPort}`)
        ])
      ].some(v => v.toLowerCase().includes(q))
    );
  }, [data, query]);

  return (
    <div className={sidebarCollapsed?"shell sidebar-collapsed":"shell"}>
      <aside className={sidebarCollapsed?"sidebar collapsed":"sidebar"}>
        <div className="brand">
          <div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div>
          <div className="brand-text"><strong>Container Router</strong><span>Manager</span></div>
          <button className="sidebar-collapse-btn" onClick={()=>setSidebarCollapsed(v=>!v)} title={sidebarCollapsed?"Expand sidebar":"Collapse sidebar"} aria-label={sidebarCollapsed?"Expand sidebar":"Collapse sidebar"}>
            {sidebarCollapsed?<ChevronRight size={18}/>:<ChevronLeft size={18}/>}
          </button>
        </div>

        <nav>
          {navigation.map(item => {
            const Icon = item.icon;
            return (
              <button key={item.id}
                className={page === item.id ? "nav-item active" : "nav-item"}
                onClick={() => { setPage(item.id); setQuery(""); }}>
                <Icon size={22}/><span className="nav-label">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="engine-card">
            <span className={error ? "status-dot bad" : "status-dot"} />
            <div><strong>{error ? "Docker API error" : "Docker Engine"}</strong>
              <span>{error ? "Disconnected" : "Connected"}</span></div>
          </div>
          <button className="theme-toggle" onClick={onToggleTheme} title={theme==="dark"?"Switch to light theme":"Switch to dark theme"}>
            <span className="theme-toggle-icon">{theme==="dark"?<Sun size={15}/>:<Moon size={15}/>}</span>
            <span className="theme-toggle-text">{theme==="dark"?"Light theme":"Dark theme"}</span>
          </button>
          <div className="sidebar-user"><strong>{auth.username}</strong><span>{auth.role}</span><button onClick={onLogout} title="Logout"><LogOut size={14}/></button></div>
          <div className="version">DRM v0.16.1</div>
        </div>
      </aside>

      <main className="main">
        <header>
          <div><span className="eyebrow">INFRASTRUCTURE</span>
            <h1>{navigation.find(n => n.id === page)?.label}</h1></div>
          <div className="header-actions">
            {["networks","containers","ports"].includes(page) && (
              <label className="search"><Search size={16}/>
                <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search..."/></label>
            )}
            <div className="sync">
              <span>{lastUpdate ? `Updated ${lastUpdate.toLocaleTimeString()}` : "Not synced"}</span>
              <button onClick={refresh} disabled={loading}><RefreshCw size={17} className={loading ? "spin" : ""}/></button>
            </div>
          </div>
        </header>

        {error && <div className="error-banner"><Shield size={18}/><div><strong>Cannot reach backend</strong><span>{error}</span></div></div>}

        {page === "dashboard" && <Dashboard data={data} trafficRates={trafficRates}/>}
        {page === "networks" && <Networks networks={filteredNetworks} canManage={auth.role!=="viewer"} onChanged={refresh}/>}
        {page === "containers" && <Containers containers={filteredContainers} networks={data?.networks ?? []} canManage={auth.role!=="viewer"} onChanged={refresh}/>}
        {page === "ports" && <Ports containers={filteredContainers} firewall={firewallStatus} canManage={auth.role!=="viewer"}/>}
        {page === "topology" && <TopologyView data={data} firewall={firewallStatus}/>}
        {page === "firewall" && <FirewallEngine/>}
        {page === "interfaces" && <HostInterfacesPage canManage={auth.role!=="viewer"}/>}
        {page === "routing" && <RoutingPage/>}
        {page === "nat" && <NatPage canManage={auth.role!=="viewer"}/>}
        {page === "wireguard" && <WireGuardPage topology={data}/>}
        {page === "management" && <ManagementPage auth={auth} onAuthChange={onAuthChange}/>}
      </main>
    </div>
  );
}


function LoginScreen({onAuthenticated}:{onAuthenticated:(user:AuthUser)=>void}){
  const [username,setUsername]=useState("admin");
  const [password,setPassword]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);setError("");try{const result=await login(username,password);onAuthenticated(result.user);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <div className="auth-page"><form className="auth-card" onSubmit={submit}>
    <div className="auth-brand"><div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div><div><strong>Container Router Manager</strong><span>Secure management access</span></div></div>
    <h1>Sign in</h1><p>Authenticate to manage Docker networking, firewall, routing and VPN.</p>
    {error&&<div className="auth-error">{error}</div>}
    <label><span>Username</span><input autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} /></label>
    <label><span>Password</span><input autoComplete="current-password" type="password" value={password} onChange={e=>setPassword(e.target.value)} autoFocus /></label>
    <button className="btn primary auth-submit" disabled={busy}>{busy?"Signing in…":"Sign in"}</button>
    <small>Bootstrap credentials: admin / admin. A password change is mandatory after the first login.</small>
  </form></div>;
}

function ForcedPasswordChange({auth,onChanged,onLogout}:{auth:AuthUser;onChanged:(u:AuthUser)=>void;onLogout:()=>void}){
  const [current,setCurrent]=useState("");const [next,setNext]=useState("");const [confirm,setConfirm]=useState("");const [error,setError]=useState("");const [busy,setBusy]=useState(false);
  async function submit(e:React.FormEvent){e.preventDefault();if(next!==confirm){setError("Passwords do not match");return;}setBusy(true);setError("");try{await changePassword(current,next);const me=await getMe();onChanged(me.user);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <div className="auth-page"><form className="auth-card" onSubmit={submit}>
    <div className="auth-brand"><div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div><div><strong>Password change required</strong><span>{auth.username}</span></div></div>
    <h1>Create a new password</h1><p>The bootstrap password cannot be used to access DRM. Use at least 8 characters.</p>
    {error&&<div className="auth-error">{error}</div>}
    <label><span>Current password</span><input type="password" autoComplete="current-password" value={current} onChange={e=>setCurrent(e.target.value)}/></label>
    <label><span>New password</span><input type="password" autoComplete="new-password" minLength={8} value={next} onChange={e=>setNext(e.target.value)}/></label>
    <label><span>Confirm new password</span><input type="password" autoComplete="new-password" minLength={8} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
    <button className="btn primary auth-submit" disabled={busy}>{busy?"Updating…":"Change password"}</button>
    <button type="button" className="auth-link" onClick={onLogout}>Sign out</button>
  </form></div>;
}

function ManagementPage({auth,onAuthChange}:{auth:AuthUser;onAuthChange:(u:AuthUser)=>void}){
  const [current,setCurrent]=useState("");const [next,setNext]=useState("");const [confirm,setConfirm]=useState("");
  const [users,setUsers]=useState<AuthUser[]>([]);const [message,setMessage]=useState("");const [error,setError]=useState("");
  const [newUser,setNewUser]=useState({username:"",password:"",role:"viewer"});
  async function loadUsers(){if(auth.role!=="administrator")return;try{setUsers(await listManagementUsers());}catch(e){setError(e instanceof Error?e.message:String(e));}}
  useEffect(()=>{loadUsers();},[auth.role]);
  async function ownPassword(e:React.FormEvent){e.preventDefault();setError("");setMessage("");if(next!==confirm){setError("Passwords do not match");return;}try{await changePassword(current,next);const me=await getMe();onAuthChange(me.user);setCurrent("");setNext("");setConfirm("");setMessage("Password changed successfully");}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function create(){setError("");try{await addManagementUser(newUser);setNewUser({username:"",password:"",role:"viewer"});await loadUsers();setMessage("User created; password change will be required at first login");}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function role(id:string,role:string){try{await changeManagementRole(id,role);await loadUsers();}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function reset(id:string,username:string){const password=window.prompt(`Temporary password for ${username} (min 8 characters):`);if(!password)return;try{await resetManagementPassword(id,password);await loadUsers();setMessage(`${username} must change password at next login`);}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function remove(id:string,username:string){if(!window.confirm(`Delete user ${username}?`))return;try{await removeManagementUser(id);await loadUsers();}catch(e){setError(e instanceof Error?e.message:String(e));}}
  return <div className="management-stack">
    {error&&<div className="error-banner"><Shield size={18}/><div><strong>Management error</strong><span>{error}</span></div></div>}
    {message&&<div className="management-success">{message}</div>}
    <div className="panel"><PanelTitle title="My account" subtitle={`${auth.username} · ${auth.role}`}/><form className="password-form" onSubmit={ownPassword}>
      <label><span>Current password</span><input type="password" value={current} onChange={e=>setCurrent(e.target.value)}/></label>
      <label><span>New password</span><input type="password" minLength={8} value={next} onChange={e=>setNext(e.target.value)}/></label>
      <label><span>Confirm password</span><input type="password" minLength={8} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
      <button className="btn primary">Change password</button>
    </form></div>
    {auth.role==="administrator"&&<>
      <div className="panel"><PanelTitle title="Add user" subtitle="New accounts must change their temporary password at first login"/><div className="user-builder">
        <label><span>Username</span><input value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})}/></label>
        <label><span>Temporary password</span><input type="password" minLength={8} value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})}/></label>
        <label><span>Role</span><select value={newUser.role} onChange={e=>setNewUser({...newUser,role:e.target.value})}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="administrator">Administrator</option></select></label>
        <button className="btn add-rule" onClick={create}>Add user</button>
      </div></div>
      <div className="table-panel"><div className="users-table-head"><span>User</span><span>Role</span><span>Password</span><span>Last login</span><span>Actions</span></div>
      {users.map(u=><div className="users-table-row" key={u.id}><div><strong>{u.username}</strong><small>{u.username==="admin"?"Built-in administrator":u.id}</small></div>
        <select value={u.role} disabled={u.username==="admin"} onChange={e=>role(u.id,e.target.value)}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="administrator">Administrator</option></select>
        <span className={u.mustChangePassword?"pill warning":"pill green"}>{u.mustChangePassword?"CHANGE REQUIRED":"SET"}</span>
        <span>{u.lastLoginAt?new Date(u.lastLoginAt).toLocaleString():"Never"}</span>
        <div className="user-actions"><button className="btn secondary" onClick={()=>reset(u.id,u.username)}>Reset password</button><button className="icon-danger" disabled={u.username==="admin"} onClick={()=>remove(u.id,u.username)}><Trash2 size={15}/></button></div>
      </div>)}</div>
    </>}
  </div>;
}

function AuthenticatedApp(){
  const [auth,setAuth]=useState<AuthUser|null>(null);const [checking,setChecking]=useState(true);
  const [theme,setTheme]=useState<"dark"|"light">(()=>localStorage.getItem("drm-theme")==="light"?"light":"dark");
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem("drm-theme",theme);},[theme]);
  const toggleTheme=()=>setTheme(current=>current==="dark"?"light":"dark");
  useEffect(()=>{
    getMe().then(r=>setAuth(r.user)).catch(()=>setAuth(null)).finally(()=>setChecking(false));
    const expired=()=>setAuth(null); window.addEventListener("drm-auth-expired",expired);
    return()=>window.removeEventListener("drm-auth-expired",expired);
  },[]);

  useEffect(()=>{
    if(!auth || auth.mustChangePassword)return;
    let cancelled=false;
    getUpdateStatus().then(status=>{
      if(cancelled || !status.updateAvailable || !status.latestVersion || !status.releaseUrl)return;
      window.dispatchEvent(new CustomEvent("drm-notification",{detail:{
        type:"info",
        message:`New DRM version ${status.latestVersion} is available`,
        detail:`You are running v${status.currentVersion}. Open the GitHub release to view changes and download the new version.`,
        actionUrl:status.releaseUrl,
        actionLabel:"View release on GitHub"
      }}));
    }).catch(()=>{ /* Update checks must never interrupt login. */ });
    return()=>{cancelled=true};
  },[auth?.id,auth?.mustChangePassword]);
  async function signOut(){try{await logout();}catch{}setAuth(null);}
  if(checking)return <div className="auth-page"><div className="auth-loading">Loading DRM…</div></div>;
  if(!auth)return <LoginScreen onAuthenticated={setAuth}/>;
  if(auth.mustChangePassword)return <><NotificationCenter/><ForcedPasswordChange auth={auth} onChanged={setAuth} onLogout={signOut}/></>;
  return <><NotificationCenter/><MainApp auth={auth} onAuthChange={setAuth} onLogout={signOut} theme={theme} onToggleTheme={toggleTheme}/></>;
}

function containerAddressSummary(c:DockerContainer){
  const values=c.networks.flatMap(n=>[n.ipv4Address,n.ipv6Address]).filter((x):x is string=>Boolean(x));
  return values.join(" · ") || "No IP";
}
function networkEndpointAddress(ipv4?:string|null,ipv6?:string|null){return [ipv4,ipv6].filter(Boolean).join(" · ")||"—";}

function Dashboard({ data, trafficRates }: { data: Topology | null; trafficRates: Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}> }) {
  const endpoints = data?.networks.reduce((n,x) => n+x.containers.length,0) ?? 0;
  const published = data?.containers.reduce((n,c) =>
    n + c.ports.reduce((m,p) => m + p.published.length,0), 0) ?? 0;
  const stats = [
    {label:"Networks",value:data?.networkCount ?? "—",icon:Network,hint:"Docker networks"},
    {label:"Containers",value:data?.containerCount ?? "—",icon:Boxes,hint:`${data?.runningContainerCount ?? 0} running`},
    {label:"Endpoints",value:endpoints,icon:CircleDot,hint:"Network attachments"},
    {label:"Published ports",value:published,icon:Plug,hint:"Host port mappings"}
  ];
  return <>
    <section className="stats-grid">
      {stats.map(({label,value,icon:Icon,hint}) =>
        <article className="stat-card" key={label}>
          <div className="icon-box"><Icon size={19}/></div><span className="stat-label">{label}</span>
          <strong className="stat-value">{value}</strong><span className="stat-hint">{hint}</span>
        </article>)}
    </section>
    <section className="two-col">
      <div className="panel"><PanelTitle title="Network overview" subtitle="Live Docker Engine data"/>
        <div className="network-list">{[...(data?.networks ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).slice(0,6).map(n=><NetworkRow network={n} key={n.id}/>)}
        {!data?.networks.length && <Empty text="No network data yet"/>}</div>
      </div>
      <div className="panel"><PanelTitle title="Containers & ports" subtitle="Primary address and published services"/>
        <div className="container-list">{[...(data?.containers ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).slice(0,7).map(c=>
          <div className="container-row" key={c.id}>
            <div className="container-icon"><Container size={17}/></div>
            <div className="grow"><strong>{c.name}</strong><span>{portSummary(c)}</span></div>
            <div className="right-meta"><span className={c.state==="running"?"pill green":"pill"}>{c.state}</span>
            <code className="dual-ip-code">{networkEndpointAddress(c.networks[0]?.ipv4Address,c.networks[0]?.ipv6Address)}</code></div>
          </div>)}
        {!data?.containers.length && <Empty text="No container data yet"/>}</div>
      </div>
    </section>
    <section className="panel live-traffic-panel">
      <PanelTitle title="Live container traffic" subtitle="Docker network I/O, refreshed every 2 seconds"/>
      <div className="traffic-table-head"><span>Container</span><span>RX / sec</span><span>TX / sec</span><span>Total RX</span><span>Total TX</span></div>
      {[...(data?.containers ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).map(c=>{ const t=trafficRates[c.id]; return <div className="traffic-table-row" key={c.id}><div className="name-cell"><div className="container-icon"><Activity size={15}/></div><div><strong>{c.name}</strong><span>{containerAddressSummary(c)}</span></div></div><strong className="traffic-rx">{formatRate(t?.rxRate ?? 0)}</strong><strong className="traffic-tx">{formatRate(t?.txRate ?? 0)}</strong><span>{formatBytes(t?.rxBytes ?? 0)}</span><span>{formatBytes(t?.txBytes ?? 0)}</span></div>; })}
      {!data?.containers.length && <Empty text="No container traffic data"/>}
    </section>
  </>;
}

function Networks({networks,canManage,onChanged}:{networks:DockerNetwork[];canManage:boolean;onChanged:()=>Promise<void>}) {
  const [showCreate,setShowCreate]=useState(false); const [busy,setBusy]=useState(false); const [formError,setFormError]=useState("");
  const [driver,setDriver]=useState<"bridge"|"macvlan"|"ipvlan">("bridge"); const [allocation,setAllocation]=useState<"automatic"|"manual">("automatic");
  const [name,setName]=useState(""); const [pool,setPool]=useState("10.0.0.0/8"); const [prefixLength,setPrefixLength]=useState(24);
  const [suggestedSubnet,setSuggestedSubnet]=useState(""); const [suggestedGateway,setSuggestedGateway]=useState(""); const [subnet,setSubnet]=useState(""); const [gateway,setGateway]=useState("");
  const [parents,setParents]=useState<any[]>([]); const [parent,setParent]=useState(""); const [vlanId,setVlanId]=useState(""); const [mode,setMode]=useState("bridge");

  async function refreshInterfaces(){try{const ifs=await getDockerNetworkParents();setParents(ifs);if(!parent&&ifs.length)setParent(ifs.find((x:any)=>x.kind!=="vlan")?.name??ifs[0].name)}catch(e){setFormError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{if(showCreate||canManage)void refreshInterfaces()},[showCreate]);
  async function loadSuggestion(nextPool=pool,nextPrefix=prefixLength){if(allocation!=="automatic"||driver!=="bridge")return;try{setFormError("");const value=await suggestDockerNetworkSubnet(nextPool,nextPrefix);setSuggestedSubnet(value.subnet);setSuggestedGateway(value.gateway)}catch(e){setSuggestedSubnet("");setSuggestedGateway("");setFormError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{if(showCreate&&allocation==="automatic"&&driver==="bridge")void loadSuggestion()},[showCreate,allocation,pool,prefixLength,driver]);
  useEffect(()=>{if(driver!=="bridge"){setAllocation("manual");setMode(driver==="macvlan"?"bridge":"l2")}else setMode("bridge")},[driver]);
  function closeCreate(){setShowCreate(false);setFormError("");setName("");setSubnet("");setGateway("");setVlanId("")}
  async function create(e:React.FormEvent){e.preventDefault();setBusy(true);setFormError("");try{await createDockerNetwork({name,driver,allocation,pool,prefixLength,subnet:allocation==="manual"?subnet:undefined,gateway:allocation==="manual"?gateway:undefined,parent:driver!=="bridge"?parent:undefined,vlanId:driver!=="bridge"&&vlanId.trim()?Number(vlanId):undefined,mode:driver!=="bridge"?mode:undefined});closeCreate();await Promise.all([onChanged(),refreshInterfaces()])}catch(e){setFormError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}
  async function remove(network:DockerNetwork){if(!canManage)return;if(network.containers.length){setFormError(`Network ${network.name} has attached containers and cannot be deleted`);return}if(!window.confirm(`Delete Docker network "${network.name}"?`))return;setBusy(true);setFormError("");try{await removeDockerNetwork(network.id);await Promise.all([onChanged(),refreshInterfaces()])}catch(e){setFormError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}

  const baseParents=parents.filter((x:any)=>x.kind!=="vlan");
  return <>
    <div className="network-page-toolbar"><div><strong>Docker Networks</strong><span>Bridge, macvlan and ipvlan networks with managed 802.1Q VLAN parents.</span></div>{canManage&&<button className="btn primary" onClick={()=>setShowCreate(v=>!v)}><Plus size={16}/>{showCreate?"Close":"Create Network"}</button>}</div>
    {showCreate&&<form className="network-create-panel" onSubmit={create}>
      <div className="network-create-head"><div><strong>Create Docker network</strong><span>Use bridge for routed Docker networks. macvlan/ipvlan attach containers directly to a physical LAN or tagged VLAN.</span></div></div>
      <div className="network-create-grid">
        <label><span>Name</span><input value={name} onChange={e=>setName(e.target.value)} placeholder="vlan100-apps" required/></label>
        <label><span>Driver</span><select value={driver} onChange={e=>setDriver(e.target.value as any)}><option value="bridge">bridge</option><option value="macvlan">macvlan</option><option value="ipvlan">ipvlan</option></select></label>
        {driver!=="bridge"&&<>
          <label><span>Physical parent</span><select value={parent} onChange={e=>setParent(e.target.value)} required><option value="">Select interface</option>{baseParents.map((x:any)=><option key={x.name} value={x.name}>{x.name} · {x.state}</option>)}</select></label>
          <label><span>VLAN ID (optional)</span><input type="number" min="1" max="4094" value={vlanId} onChange={e=>setVlanId(e.target.value)} placeholder="100"/><small>{vlanId?`DRM creates ${parent||"parent"}.${vlanId}`:"Untagged — use parent directly"}</small></label>
          <label><span>{driver} mode</span><select value={mode} onChange={e=>setMode(e.target.value)}>{driver==="macvlan"?<><option value="bridge">bridge</option><option value="vepa">vepa</option><option value="private">private</option><option value="passthru">passthru</option></>:<><option value="l2">l2</option><option value="l3">l3</option><option value="l3s">l3s</option></>}</select></label>
        </>}
        <label><span>IPv4 allocation</span><select value={allocation} disabled={driver!=="bridge"} onChange={e=>setAllocation(e.target.value as any)}><option value="automatic">Automatic</option><option value="manual">Manual</option></select>{driver!=="bridge"&&<small>Physical VLAN/LAN addressing must be entered manually.</small>}</label>
        {allocation==="automatic"&&driver==="bridge"?<>
          <label><span>Private IPv4 pool</span><select value={pool} onChange={e=>setPool(e.target.value)}><option value="10.0.0.0/8">10.0.0.0/8</option><option value="172.16.0.0/12">172.16.0.0/12</option><option value="192.168.0.0/16">192.168.0.0/16</option></select></label>
          <label><span>Subnet size</span><select value={prefixLength} onChange={e=>setPrefixLength(Number(e.target.value))}>{[24,23,22,21,20,25,26,27,28].map(p=><option key={p} value={p}>/{p}</option>)}</select></label>
          <div className="network-suggestion"><span>Next free subnet</span><strong>{suggestedSubnet||"Scanning…"}</strong><small>Gateway {suggestedGateway||"—"}</small></div>
        </>:<><label><span>Subnet</span><input value={subnet} onChange={e=>setSubnet(e.target.value)} placeholder="192.168.100.0/24" required/></label><label><span>Gateway</span><input value={gateway} onChange={e=>setGateway(e.target.value)} placeholder="192.168.100.1"/></label></>}
      </div>
      {driver==="macvlan"&&<div className="network-form-note"><AlertTriangle size={16}/><span>macvlan gives containers their own MAC addresses. Host-to-container traffic on the same macvlan is not available by default unless a host-side macvlan interface is added.</span></div>}
      {formError&&<div className="network-form-error"><AlertTriangle size={16}/><span>{formError}</span></div>}
      <div className="network-create-actions"><button type="button" className="btn secondary" onClick={closeCreate}>Cancel</button><button className="btn primary" disabled={busy||!name.trim()||(driver!=="bridge"&&(!parent||!subnet.trim()))||(allocation==="automatic"&&!suggestedSubnet)}>{busy?"Creating…":"Create Network"}</button></div>
    </form>}
    
    {!showCreate&&formError&&<div className="network-form-error"><AlertTriangle size={16}/><span>{formError}</span></div>}
    <section className="cards">{networks.map(network=><article className="network-card" key={network.id}><div className="network-card-head"><div className="network-symbol"><Network size={20}/></div><div className="grow"><strong>{network.name}</strong><span>{network.id.slice(0,12)}</span></div><span className="pill blue">{network.driver}</span>{canManage&&!['bridge','host','none'].includes(network.name)&&!network.ingress&&<button className="network-delete-btn" disabled={busy||network.containers.length>0} onClick={()=>remove(network)} title={network.containers.length?'Disconnect containers before deleting':'Delete network'}><Trash2 size={15}/></button>}</div><div className="network-details"><Metric label="Subnets" value={network.subnets.map(x=>x.subnet).filter(Boolean).join(' · ')||'—'}/><Metric label="Gateways" value={network.subnets.map(x=>x.gateway).filter(Boolean).join(' · ')||'—'}/><Metric label="Containers" value={String(network.containers.length)}/><Metric label="Scope" value={network.scope}/>{network.parent&&<Metric label="Parent" value={network.parent}/>} {network.vlanId&&<Metric label="VLAN" value={String(network.vlanId)}/>}</div><div className="endpoint-block"><span className="section-label">ATTACHED ENDPOINTS</span>{network.containers.length?network.containers.map(e=><div className="endpoint" key={e.id}><span className="status-dot"/><strong>{e.name}</strong><code>{networkEndpointAddress(e.ipv4Address,e.ipv6Address)}</code></div>):<span className="muted">No attached containers</span>}</div></article>)}{!networks.length&&<Empty text="No matching networks"/>}</section>
  </>;
}

function Containers({containers,networks,canManage,onChanged}:{containers:DockerContainer[];networks:DockerNetwork[];canManage:boolean;onChanged:()=>Promise<void>}) {
  const [selected,setSelected]=useState<DockerContainer|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [connectNetworkId,setConnectNetworkId]=useState("");
  const [allocation,setAllocation]=useState<"automatic"|"manual">("automatic");
  const [manualIp,setManualIp]=useState("");
  const [ipInfo,setIpInfo]=useState<Awaited<ReturnType<typeof getContainerNetworkIpInfo>>|null>(null);
  const [editNetworkId,setEditNetworkId]=useState("");
  const [editAllocation,setEditAllocation]=useState<"automatic"|"manual">("manual");
  const [editIp,setEditIp]=useState("");
  const [showCreate,setShowCreate]=useState(false);
  const [newNetworkName,setNewNetworkName]=useState("");
  const [newPool,setNewPool]=useState("10.0.0.0/8");
  const [newPrefix,setNewPrefix]=useState(24);
  const [newSuggestion,setNewSuggestion]=useState<{subnet:string;gateway:string}|null>(null);
  const [persistentEnabled,setPersistentEnabled]=useState(false);
  const [policyIdentity,setPolicyIdentity]=useState<{kind:"compose"|"name";project?:string;service?:string;containerNumber?:string;name?:string}|null>(null);
  const [policyRuntime,setPolicyRuntime]=useState<{state:string;message:string|null;lastAppliedAt:string|null}|null>(null);
  const [policyLoading,setPolicyLoading]=useState(false);

  const attachedIds=new Set(selected?.networks.map(n=>n.networkId).filter(Boolean) as string[] ?? []);
  const availableNetworks=networks.filter(n=>n.driver==="bridge"&&!attachedIds.has(n.id)&&n.subnets.some(x=>x.subnet&&!x.subnet.includes(":")));

  async function selectContainer(c:DockerContainer){
    setSelected(c);setError("");setConnectNetworkId("");setManualIp("");setIpInfo(null);setEditNetworkId("");setEditIp("");setShowCreate(false);
    setPolicyLoading(true);setPolicyRuntime(null);
    try{
      const info=await getContainerNetworkPolicy(c.id);
      setPersistentEnabled(Boolean(info.policy?.enabled));
      setPolicyIdentity(info.supportedIdentity);
      setPolicyRuntime(info.policy?.runtime??null);
    }catch(e){
      setPersistentEnabled(false);setPolicyIdentity(null);setError(e instanceof Error?e.message:String(e));
    }finally{setPolicyLoading(false);}
  }

  async function refreshPersistentSnapshot(containerId:string){
    if(!persistentEnabled)return;
    const policy=await saveContainerNetworkPolicy(containerId);
    setPolicyRuntime(policy.runtime);
  }

  async function togglePersistent(enabled:boolean){
    if(!selected||busy)return;
    setBusy(true);setError("");
    try{
      if(enabled){
        const policy=await saveContainerNetworkPolicy(selected.id);
        setPersistentEnabled(true);setPolicyIdentity(policy.identity);setPolicyRuntime(policy.runtime);
      }else{
        await removeContainerNetworkPolicy(selected.id);
        setPersistentEnabled(false);setPolicyRuntime(null);
      }
    }catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function loadIpInfo(networkId:string){
    setConnectNetworkId(networkId);setManualIp("");setIpInfo(null);setError("");
    if(!selected||!networkId)return;
    try{setIpInfo(await getContainerNetworkIpInfo(selected.id,networkId));}
    catch(e){setError(e instanceof Error?e.message:String(e));}
  }

  useEffect(()=>{
    if(!showCreate)return;
    let cancelled=false;
    suggestDockerNetworkSubnet(newPool,newPrefix).then(v=>{if(!cancelled)setNewSuggestion({subnet:v.subnet,gateway:v.gateway});}).catch(e=>{if(!cancelled)setError(e instanceof Error?e.message:String(e));});
    return()=>{cancelled=true};
  },[showCreate,newPool,newPrefix]);

  async function connect(){
    if(!selected||!connectNetworkId)return;
    setBusy(true);setError("");
    try{
      await connectContainerNetwork(selected.id,connectNetworkId,{allocation,ipv4Address:allocation==="manual"?manualIp:undefined});
      await refreshPersistentSnapshot(selected.id);
      await onChanged();
      const fresh=(await getTopology()).containers.find(c=>c.id===selected.id); if(fresh)setSelected(fresh);
      setConnectNetworkId("");setManualIp("");setIpInfo(null);
    }catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function disconnect(networkId:string,networkName:string){
    if(!selected)return;
    const last=selected.networks.length<=1;
    const warning=last?`This is the last network attached to ${selected.name}. Disconnect it anyway?`:`Disconnect ${selected.name} from ${networkName}?`;
    if(!window.confirm(warning))return;
    setBusy(true);setError("");
    try{
      await disconnectContainerNetwork(selected.id,networkId,false);
      await refreshPersistentSnapshot(selected.id);
      await onChanged();
      const fresh=(await getTopology()).containers.find(c=>c.id===selected.id); if(fresh)setSelected(fresh); else setSelected(null);
    }catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  function beginEdit(n:DockerContainer["networks"][number]){
    if(!n.networkId)return;
    setEditNetworkId(n.networkId);setEditAllocation("manual");setEditIp(n.ipv4Address||"");setError("");
  }

  async function applyIp(){
    if(!selected||!editNetworkId)return;
    setBusy(true);setError("");
    try{
      await changeContainerNetworkIp(selected.id,editNetworkId,{allocation:editAllocation,ipv4Address:editAllocation==="manual"?editIp:undefined});
      await refreshPersistentSnapshot(selected.id);
      await onChanged();
      const fresh=(await getTopology()).containers.find(c=>c.id===selected.id); if(fresh)setSelected(fresh);
      setEditNetworkId("");setEditIp("");
    }catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function createAndSelectNetwork(e:React.FormEvent){
    e.preventDefault();
    if(!selected||!newSuggestion)return;
    setBusy(true);setError("");
    try{
      const created:any=await createDockerNetwork({name:newNetworkName,driver:"bridge",allocation:"automatic",pool:newPool,prefixLength:newPrefix});
      await onChanged();
      setShowCreate(false);setNewNetworkName("");
      if(created?.id){await loadIpInfo(created.id);}
    }catch(e){setError(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  return <>
    <div className="table-panel">
      <div className="table-head ports-aware dual-stack-containers"><span>Container</span><span>Image</span><span>Network</span><span>IPv4</span><span>IPv6</span><span>Ports</span><span>Status</span></div>
      {containers.map(c=><div className={`table-row ports-aware dual-stack-containers ${canManage?"container-manage-row":""}`} key={c.id} onClick={()=>canManage&&selectContainer(c)} title={canManage?"Manage container networks":undefined}>
        <div className="name-cell"><div className="container-icon"><Container size={16}/></div>
          <div><strong>{c.name}</strong><span>{c.id.slice(0,12)}</span></div></div>
        <span className="truncate">{c.image}</span>
        <span>{c.networks.length?c.networks.map(n=>n.networkName).join(" · "):"—"}</span>
        <code>{c.networks.length?c.networks.map(n=>n.ipv4Address||"—").join(" · "):"—"}</code>
        <code className="ipv6-value">{c.networks.length?c.networks.map(n=>n.ipv6Address||"—").join(" · "):"—"}</code>
        <div className="port-mini">{c.ports.length ? c.ports.slice(0,3).map(p=><span key={p.containerPort}>{p.containerPort}</span>) : <span>—</span>}</div>
        <span><span className={c.state==="running"?"pill green":"pill"}>{c.state}</span></span>
      </div>)}
      {!containers.length && <Empty text="No matching containers"/>}
    </div>

    {selected&&<div className="container-network-modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setSelected(null)}}>
      <div className="container-network-modal">
        <div className="container-network-modal-head">
          <div><strong>Manage Networks · {selected.name}</strong><span>{selected.id.slice(0,12)}</span></div>
          <button className="notification-close" onClick={()=>setSelected(null)}><X size={17}/></button>
        </div>

        <div className="container-persistent-policy">
          <div className="container-persistent-copy">
            <div><strong>Persistent Network Assignment</strong>{persistentEnabled&&<span className="pill green">ACTIVE</span>}</div>
            <span>Remember this container's network names and IPv4 addresses and restore them after Docker Compose recreates the container.</span>
            {policyIdentity&&<small>{policyIdentity.kind==="compose"?`Compose identity: ${policyIdentity.project} / ${policyIdentity.service}${policyIdentity.containerNumber?` #${policyIdentity.containerNumber}`:""}`:`Container identity: ${policyIdentity.name} (name-based fallback)`}</small>}
            {persistentEnabled&&policyRuntime?.message&&<small className={`policy-runtime ${policyRuntime.state}`}>{policyRuntime.message}{policyRuntime.lastAppliedAt?` · ${new Date(policyRuntime.lastAppliedAt).toLocaleString()}`:""}</small>}
          </div>
          <label className="persistent-switch"><input type="checkbox" checked={persistentEnabled} disabled={busy||policyLoading} onChange={e=>togglePersistent(e.target.checked)}/><span>{policyLoading?"Loading…":persistentEnabled?"Persistent":"Temporary"}</span></label>
        </div>

        <section className="container-network-section">
          <div className="container-network-section-title"><strong>Connected Networks</strong><span>Change IPv4 or disconnect an existing endpoint.</span></div>
          {selected.networks.length?selected.networks.map(n=><div className="container-network-item" key={n.networkId||n.networkName}>
            <div className="container-network-main"><div className="network-symbol small"><Network size={16}/></div><div><strong>{n.networkName}</strong><span>{n.ipv4Address||"No IPv4"}{n.gateway?` · gateway ${n.gateway}`:""}</span>{n.ipv6Address&&<small>{n.ipv6Address}</small>}</div></div>
            <div className="container-network-actions">
              {n.networkId&&<button className="btn secondary small" disabled={busy} onClick={()=>beginEdit(n)}>Change IP</button>}
              {n.networkId&&<button className="btn small danger-soft" disabled={busy} onClick={()=>disconnect(n.networkId!,n.networkName)}>Disconnect</button>}
            </div>
            {editNetworkId===n.networkId&&<div className="container-ip-editor">
              <label><span>IPv4 allocation</span><select value={editAllocation} onChange={e=>setEditAllocation(e.target.value as "automatic"|"manual")}><option value="automatic">Automatic free IP</option><option value="manual">Manual</option></select></label>
              {editAllocation==="manual"&&<label><span>IPv4 address</span><input value={editIp} onChange={e=>setEditIp(e.target.value)} placeholder="10.0.0.10"/></label>}
              <div className="container-ip-editor-actions"><button className="btn secondary small" onClick={()=>setEditNetworkId("")} disabled={busy}>Cancel</button><button className="btn primary small" onClick={applyIp} disabled={busy||(editAllocation==="manual"&&!editIp.trim())}>{busy?"Applying…":"Apply IP"}</button></div>
              <small className="field-hint">Changing IP briefly disconnects this endpoint. DRM attempts rollback if reconnect fails.</small>
            </div>}
          </div>):<div className="empty-inline">No connected networks</div>}
        </section>

        <section className="container-network-section">
          <div className="container-network-section-title"><strong>Connect Network</strong><span>Attach this running container without recreating it. Persistent mode automatically updates the saved assignment.</span></div>
          <div className="container-connect-grid">
            <label><span>Docker Network</span><select value={connectNetworkId} onChange={e=>loadIpInfo(e.target.value)}><option value="">Select network…</option>{availableNetworks.map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.find(x=>x.subnet&&!x.subnet.includes(":"))?.subnet}</option>)}</select></label>
            <label><span>IPv4 allocation</span><select value={allocation} onChange={e=>setAllocation(e.target.value as "automatic"|"manual")}><option value="automatic">Automatic free IP</option><option value="manual">Manual</option></select></label>
            {allocation==="manual"&&<label><span>IPv4 address</span><input value={manualIp} onChange={e=>setManualIp(e.target.value)} placeholder={ipInfo?.nextFreeIp||"10.0.0.10"}/></label>}
          </div>
          {ipInfo&&<div className="container-ip-info"><span>Subnet <strong>{ipInfo.subnet}</strong></span><span>Gateway <strong>{ipInfo.gateway||"—"}</strong></span><span>Next free <strong>{ipInfo.nextFreeIp||"No free IP"}</strong></span><span>Used <strong>{ipInfo.usedIps.length}</strong></span></div>}
          <div className="container-connect-actions"><button className="btn secondary" onClick={()=>setShowCreate(v=>!v)}><Plus size={15}/>{showCreate?"Close Create Network":"Create New Network"}</button><button className="btn primary" disabled={busy||!connectNetworkId||(allocation==="manual"&&!manualIp.trim())||!ipInfo?.nextFreeIp&&allocation==="automatic"} onClick={connect}>{busy?"Connecting…":"Connect Network"}</button></div>

          {showCreate&&<form className="container-create-network" onSubmit={createAndSelectNetwork}>
            <strong>Create bridge network</strong>
            <div className="container-create-network-grid">
              <label><span>Name</span><input value={newNetworkName} onChange={e=>setNewNetworkName(e.target.value)} placeholder="app-network" required/></label>
              <label><span>Private pool</span><select value={newPool} onChange={e=>setNewPool(e.target.value)}><option value="10.0.0.0/8">10.0.0.0/8</option><option value="172.16.0.0/12">172.16.0.0/12</option><option value="192.168.0.0/16">192.168.0.0/16</option></select></label>
              <label><span>Subnet size</span><select value={newPrefix} onChange={e=>setNewPrefix(Number(e.target.value))}>{[24,23,22,21,20,25,26,27,28].map(v=><option key={v} value={v}>/{v}</option>)}</select></label>
            </div>
            {newSuggestion&&<div className="container-new-network-preview"><span>Subnet <strong>{newSuggestion.subnet}</strong></span><span>Gateway <strong>{newSuggestion.gateway}</strong></span></div>}
            <div className="container-create-network-actions"><button className="btn primary" disabled={busy||!newNetworkName.trim()||!newSuggestion}>{busy?"Creating…":"Create & Select"}</button></div>
          </form>}
        </section>

        {error&&<div className="network-form-error"><AlertTriangle size={16}/><span>{error}</span></div>}
      </div>
    </div>}
  </>;
}

function Ports({containers,firewall,canManage}:{containers:DockerContainer[];firewall:FirewallStatus|null;canManage:boolean}) {
  const rows = containers.flatMap(c => c.ports.map(p => ({c,p})));
  const [natStatus,setNatStatus]=useState<NatStatus|null>(null);
  const [editing,setEditing]=useState<{container:DockerContainer;port:DockerContainer["ports"][number];rule:NatDnatRule|null}|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [form,setForm]=useState({wan:"",externalIp:"0.0.0.0",externalPort:"",internalPort:"",sourceCidr:"0.0.0.0/0",networkName:"",createFirewallRule:true,description:""});

  async function loadNat(){
    try{const next=await getNatStatus();setNatStatus(next);setError("")}
    catch(e){setError(e instanceof Error?e.message:String(e))}
  }
  useEffect(()=>{void loadNat();const t=window.setInterval(loadNat,5000);return()=>window.clearInterval(t)},[]);

  function publishedRuleState(c:DockerContainer, p:DockerContainer["ports"][number]) {
    const rules=firewall?.config.publishedPortRules ?? [];
    const matching=p.published.flatMap(binding => rules.filter(r => r.enabled && r.containerId===c.id && r.protocol===p.protocol && r.publishedPort===binding.hostPort && r.containerPort===p.port && (r.hostIp===binding.hostIp || (!r.hostIp && !binding.hostIp))));
    const blocks=matching.filter(r=>r.action==="DROP" || r.action==="REJECT"); const accepts=matching.filter(r=>r.action==="ACCEPT");
    const anyDst=(r:any)=>!r.destinationCidr || r.destinationCidr==="0.0.0.0/0" || r.destinationCidr==="::/0";
    const wanLabel=(r:any)=>r.interfaceName&&r.interfaceName!=="*"?` on ${r.interfaceName}`:"";
    if(blocks.some(r=>(r.sourceCidr==="0.0.0.0/0"||r.sourceCidr==="::/0")&&anyDst(r))) return {state:"blocked" as const,detail:`Blocked${wanLabel(blocks[0])}`};
    if(blocks.length) return {state:"restricted" as const,detail:`Blocked: ${blocks.map(r=>`${r.sourceCidr}${wanLabel(r)}`).join(", ")}`};
    if(accepts.some(r=>(r.sourceCidr==="0.0.0.0/0"||r.sourceCidr==="::/0")&&anyDst(r))) return {state:"allowed" as const,detail:`Explicit allow${wanLabel(accepts[0])}`};
    if(accepts.length) return {state:"restricted" as const,detail:`Allowed: ${accepts.map(r=>`${r.sourceCidr}${wanLabel(r)}`).join(", ")}`};
    return {state:"open" as const,detail:"No firewall rule"};
  }

  function matchingDnat(c:DockerContainer,p:DockerContainer["ports"][number]){
    const rules=(natStatus?.config.rules??[]).filter((r):r is NatDnatRule=>r.type==="dnat");
    return rules.find(r=>{
      if(r.protocol!==p.protocol||r.internalPort!==Number(p.port))return false;
      const d=r.destination;
      if(d.kind!=="container")return false;
      return d.refId===c.id || d.refName===c.name || d.label===c.name;
    })??null;
  }

  function openEdit(c:DockerContainer,p:DockerContainer["ports"][number]){
    const rule=matchingDnat(c,p);
    const published=p.published[0];
    const wan=rule?.inInterface||natStatus?.defaultWanInterface||natStatus?.hostInterfaces[0]?.name||"";
    setEditing({container:c,port:p,rule});
    setForm({
      wan,
      externalIp:rule?.externalIp??"0.0.0.0",
      externalPort:String(rule?.externalPort??published?.hostPort??p.port),
      internalPort:String(rule?.internalPort??p.port),
      sourceCidr:rule?.sourceCidr??"0.0.0.0/0",
      networkName:rule?.destination.kind==="container"?(rule.destination.networkName??""):"",
      createFirewallRule:rule?.createFirewallRule??true,
      description:rule?.description??`Port mapping for ${c.name}`
    });
    setError("");
  }

  async function savePortMapping(){
    if(!editing)return;
    setBusy(true);setError("");
    try{
      const ref=natStatus?.containerRefs.find(x=>x.id===editing.container.id||x.name===editing.container.name);
      const body={
        type:"dnat",
        inInterface:form.wan,
        externalIp:form.externalIp||"0.0.0.0",
        protocol:editing.port.protocol,
        externalPort:Number(form.externalPort),
        sourceCidr:form.sourceCidr||"0.0.0.0/0",
        destination:{kind:"container",refId:ref?.id??editing.container.id,refName:ref?.name??editing.container.name,label:ref?.name??editing.container.name,networkName:form.networkName||null},
        internalPort:Number(form.internalPort),
        createFirewallRule:form.createFirewallRule,
        description:form.description,
        enabled:true
      };
      if(editing.rule)await updateNatRule(editing.rule.id,body);else await createNatRule(body);
      await loadNat();setEditing(null);
    }catch(e){setError(e instanceof Error?e.message:String(e))}
    finally{setBusy(false)}
  }

  async function removePortMapping(){
    if(!editing?.rule)return;
    if(!window.confirm(`Delete DRM port mapping for ${editing.container.name}? The original Docker published port, if any, is not changed.`))return;
    setBusy(true);setError("");
    try{await removeNatRule(editing.rule.id);await loadNat();setEditing(null)}
    catch(e){setError(e instanceof Error?e.message:String(e))}
    finally{setBusy(false)}
  }

  return <>
    {error&&<div className="error-banner"><AlertTriangle size={18}/><div><strong>Ports / NAT error</strong><span>{error}</span></div></div>}
    <div className="table-panel">
      <div className="port-table-head port-table-head-edit"><span>Container</span><span>Container IP</span><span>Internal port</span><span>Published / DRM mapping</span><span>Firewall</span><span>Action</span></div>

      {rows.map(({c,p},i)=>{
        const policy=publishedRuleState(c,p);
        const state=policy.state;
        const portClass=state==="blocked" ? "port-number blocked" : state==="allowed" ? "port-number allowed" : state==="restricted" ? "port-number restricted" : "port-number open";
        const dnat=matchingDnat(c,p);

        return <div className="port-table-row port-table-row-edit" key={`${c.id}-${p.containerPort}-${i}`}>
          <div className="name-cell">
            <div className="container-icon"><Plug size={15}/></div>
            <div><strong>{c.name}</strong><span>{c.image}</span></div>
          </div>
          <code className="dual-ip-code">{networkEndpointAddress(c.networks[0]?.ipv4Address,c.networks[0]?.ipv6Address)}</code>
          <code className={portClass}>{p.containerPort}/{p.protocol}</code>
          <div className="published-list">
            {dnat&&<code className="port-number allowed">DRM {dnat.inInterface} · {dnat.externalIp==="0.0.0.0"?"*":dnat.externalIp}:{dnat.externalPort} → {dnat.internalPort}</code>}
            {p.published.length ? p.published.map((x,j)=><code className={portClass} key={j}>Docker {formatHostIp(x.hostIp)}:{x.hostPort} → {p.containerPort}</code>) : !dnat&&<span className="pill">not published</span>}
          </div>
          <div className="port-firewall-state"><span className={state==="blocked" ? "pill danger" : state==="allowed" ? "pill green" : state==="restricted" ? "pill warning" : "pill blue"}>{state==="blocked" ? "BLOCKED" : state==="allowed" ? "ALLOW" : state==="restricted" ? "RESTRICTED" : "NO RULE"}</span><small>{policy.detail}</small></div>
          <div className="port-edit-actions">{canManage&&<button className="btn secondary" onClick={()=>openEdit(c,p)}>{dnat?"Edit":"Map port"}</button>}</div>
        </div>;
      })}
      {!rows.length && <Empty text="No exposed or published ports"/>}
    </div>

    {editing&&<div className="port-mapping-overlay" onMouseDown={e=>{if(e.target===e.currentTarget)setEditing(null)}}>
      <div className="port-mapping-dialog">
        <div className="port-mapping-head"><div><strong>Edit Port Mapping</strong><span>{editing.container.name} · {editing.port.port}/{editing.port.protocol}</span></div><button className="notification-close" onClick={()=>setEditing(null)}><X size={17}/></button></div>
        <div className="port-mapping-grid">
          <label><span>WAN interface</span><select value={form.wan} onChange={e=>setForm({...form,wan:e.target.value})}>{(natStatus?.hostInterfaces??[]).map(i=><option key={i.name} value={i.name}>{i.name} · {i.addresses.join(", ")||"no IPv4"}</option>)}</select></label>
          <label><span>External IP</span><select value={form.externalIp} onChange={e=>setForm({...form,externalIp:e.target.value})}><option value="0.0.0.0">Any IP on selected WAN</option>{(natStatus?.hostInterfaces.find(i=>i.name===form.wan)?.ips??[]).map(ip=><option key={ip}>{ip}</option>)}</select></label>
          <label><span>External port</span><input type="number" min="1" max="65535" value={form.externalPort} onChange={e=>setForm({...form,externalPort:e.target.value.replace(/\D/g,"")})}/></label>
          <label><span>Internal port</span><input type="number" min="1" max="65535" value={form.internalPort} onChange={e=>setForm({...form,internalPort:e.target.value.replace(/\D/g,"")})}/></label>
          <label><span>Allowed source</span><input value={form.sourceCidr} onChange={e=>setForm({...form,sourceCidr:e.target.value})}/></label>
          <label><span>Container network</span><select value={form.networkName} onChange={e=>setForm({...form,networkName:e.target.value})}><option value="">Follow current IPv4</option>{(natStatus?.containerRefs.find(c=>c.id===editing.container.id||c.name===editing.container.name)?.networks??[]).filter(n=>n.ipv4Address).map(n=><option key={n.networkName} value={n.networkName}>{n.networkName} · {n.ipv4Address}</option>)}</select></label>
          <label className="nat-check"><input type="checkbox" checked={form.createFirewallRule} onChange={e=>setForm({...form,createFirewallRule:e.target.checked})}/><span>Create/update linked Firewall ACCEPT</span></label>
          <label className="port-map-description"><span>Description</span><input value={form.description} onChange={e=>setForm({...form,description:e.target.value})}/></label>
        </div>
        <div className="network-form-note"><Info size={16}/><span>This is a DRM DNAT Port Mapping. It does not recreate the container or remove the original Docker published port. Delete the DRM mapping to return to the original Docker mapping.</span></div>
        <div className="port-mapping-actions">{editing.rule&&<button className="btn secondary danger-soft" disabled={busy} onClick={removePortMapping}>Remove mapping</button>}<div className="grow"/><button className="btn secondary" disabled={busy} onClick={()=>setEditing(null)}>Cancel</button><button className="btn primary" disabled={busy||!form.wan||!form.externalPort||!form.internalPort} onClick={savePortMapping}>{busy?"Saving…":editing.rule?"Save changes":"Create mapping"}</button></div>
      </div>
    </div>}
  </>;
}
function FirewallEngine() {
  const [status,setStatus]=useState<FirewallStatus|null>(null);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [source,setSource]=useState("");
  const [destination,setDestination]=useState("");
  const [family,setFamily]=useState<4|6|"both">("both");
  const [protocol,setProtocol]=useState<"all"|"tcp"|"udp"|"icmp"|"icmpv6">("all");
  const [port,setPort]=useState("");
  const [action,setAction]=useState<"ACCEPT"|"DROP"|"REJECT">("ACCEPT");
  const [description,setDescription]=useState("");
  const [publishedKey,setPublishedKey]=useState("");
  const [publishedFamily,setPublishedFamily]=useState<4|6>(4);
  const [publishedInterface,setPublishedInterface]=useState("*");
  const [publishedSource,setPublishedSource]=useState("0.0.0.0/0");
  const [publishedSourceNegate,setPublishedSourceNegate]=useState(false);
  const [publishedDestination,setPublishedDestination]=useState("0.0.0.0/0");
  const [publishedDestinationType,setPublishedDestinationType]=useState<"any"|"docker-network"|"custom">("any");
  const [publishedDestinationNetwork,setPublishedDestinationNetwork]=useState("");
  const [publishedAction,setPublishedAction]=useState<"DROP"|"REJECT"|"ACCEPT">("DROP");
  const [publishedDescription,setPublishedDescription]=useState("");
  const [hostPortKey,setHostPortKey]=useState("");
  const [hostInterface,setHostInterface]=useState("*");
  const [hostFamily,setHostFamily]=useState<4|6|"both">(4);
  const [hostSource,setHostSource]=useState("0.0.0.0/0");
  const [hostSourceNegate,setHostSourceNegate]=useState(false);
  const [hostProtocol,setHostProtocol]=useState<"all"|"tcp"|"udp"|"icmp"|"icmpv6">("tcp");
  const [hostPort,setHostPort]=useState("");
  const [hostAction,setHostAction]=useState<"ACCEPT"|"DROP"|"REJECT">("DROP");
  const [hostDescription,setHostDescription]=useState("");
  const [accessFamily,setAccessFamily]=useState<4|6>(4);
  const [accessSourceType,setAccessSourceType]=useState<"custom"|"docker-network"|"container"|"wireguard">("wireguard");
  const [accessSourceKey,setAccessSourceKey]=useState("");
  const [accessSourceCustom,setAccessSourceCustom]=useState("");
  const [accessSourceNegate,setAccessSourceNegate]=useState(false);
  const [accessDestinationType,setAccessDestinationType]=useState<"custom"|"docker-network"|"container"|"wireguard">("container");
  const [accessDestinationKey,setAccessDestinationKey]=useState("");
  const [accessDestinationCustom,setAccessDestinationCustom]=useState("");
  const [accessProtocol,setAccessProtocol]=useState<"all"|"tcp"|"udp"|"icmp"|"icmpv6">("all");
  const [accessPort,setAccessPort]=useState("");
  const [accessAction,setAccessAction]=useState<"ACCEPT"|"DROP"|"REJECT">("DROP");
  const [accessDescription,setAccessDescription]=useState("");
  const [editingAccessId,setEditingAccessId]=useState<string|null>(null);
  const [fwOwnerFilter,setFwOwnerFilter]=useState<"All"|"DRM"|"Docker"|"System-External">("All");
  const [fwFamilyFilter,setFwFamilyFilter]=useState<"All"|"IPv4"|"IPv6">("All");
  const [fwChainFilter,setFwChainFilter]=useState("All");
  const [fwSearch,setFwSearch]=useState("");


  async function load() {
    try { setStatus(await getFirewallStatus()); setMessage(""); }
    catch(e){ setMessage(e instanceof Error ? e.message : String(e)); }
  }

  useEffect(()=>{ load(); const timer=window.setInterval(load,10000); return()=>window.clearInterval(timer); },[]);

  const networks=status?.networkRefs ?? [];
  const byId=new Map(networks.map(n=>[n.id,n]));
  const publishedDestinationNetworks=networks.flatMap(n=>n.subnets
    .filter(c=>publishedFamily===6?c.includes(":"):c.includes("."))
    .map(c=>({key:`${n.id}|${c}`,name:n.name,cidr:c})));

  async function addRule() {
    if(!source || !destination){setMessage("Select source and destination networks");return;}
    setBusy(true);
    try{
      await createFirewallRule({
        family,
        sourceNetworkId:source,
        destinationNetworkId:destination,
        protocol,
        destinationPort:port ? Number(port) : null,
        action,
        description
      });
      setDescription(""); setPort(""); await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function remove(id:string) {
    setBusy(true);
    try{await removeFirewallRule(id);await load();}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function doAction(which:"apply"|"disable"|"rollback"){
    setBusy(true);
    try{setStatus(await firewallAction(which));setMessage("");}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  const publishedRefs=status?.publishedPortRefs ?? [];
  const selectedPublished=publishedRefs.find((x)=>
    `${x.containerId}|${x.hostIp}|${x.publishedPort}|${x.protocol}|${x.containerPort}`===publishedKey
  );

  async function addPublishedRule(){
    if(!selectedPublished){setMessage("Select a published Docker port");return;}
    setBusy(true);
    try{
      await createPublishedPortRule({
        ...selectedPublished,
        family:publishedFamily,
        interfaceName:publishedInterface,
        sourceCidr:publishedSource || (publishedFamily===6 ? "::/0" : "0.0.0.0/0"),
        sourceNegate:publishedSourceNegate,
        destinationCidr:publishedDestination || (publishedFamily===6 ? "::/0" : "0.0.0.0/0"),
        action:publishedAction,
        description:publishedDescription
      });
      setPublishedDescription("");
      await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function removePublished(id:string){
    setBusy(true);try{await removePublishedPortRule(id);await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}
  }
  const selectedHostPort=(status?.hostPortRefs??[]).find(x=>`${x.protocol}|${x.listenAddress}|${x.port}`===hostPortKey);
  function chooseHostPort(key:string){setHostPortKey(key);const r=(status?.hostPortRefs??[]).find(x=>`${x.protocol}|${x.listenAddress}|${x.port}`===key);if(r){setHostProtocol(r.protocol);setHostPort(String(r.port));}}
  async function addHostRule(){setBusy(true);try{await createHostInputRule({family:hostFamily,interfaceName:hostInterface,localAddress:selectedHostPort&&!["0.0.0.0","*","::"].includes(selectedHostPort.listenAddress)?selectedHostPort.listenAddress:null,protocol:hostProtocol,destinationPort:["tcp","udp"].includes(hostProtocol)&&hostPort?Number(hostPort):null,sourceCidr:hostSource,sourceNegate:hostSourceNegate,action:hostAction,description:hostDescription});setHostDescription("");await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function removeHostRule(id:string){setBusy(true);try{await removeHostInputRule(id);await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}

  const accessNetworkOptions=(status?.networkRefs??[]).filter(n=>n.subnets.some(c=>accessFamily===6?c.includes(":"):c.includes(".")));
  const accessContainerOptions=(status?.containerRefs??[]).filter(c=>c.addresses.some(a=>a.family===accessFamily));
  const accessWireGuardOptions=(status?.wireguardRefs??[]).filter(w=>w.family===accessFamily);

  function selectorFrom(type:"custom"|"docker-network"|"container"|"wireguard",key:string,custom:string){
    if(type==="custom")return {type,value:custom.trim(),label:custom.trim()};
    if(type==="docker-network"){
      const ref=(status?.networkRefs??[]).find(n=>n.id===key);
      return {type,refId:key,refName:ref?.name||null,label:ref?.name||key};
    }
    if(type==="container"){
      const ref=(status?.containerRefs??[]).find(c=>c.id===key);
      return {
        type,refId:key,refName:ref?.name||null,label:ref?.name||key,
        composeProject:ref?.composeProject??null,
        composeService:ref?.composeService??null,
        composeContainerNumber:ref?.composeContainerNumber??null
      };
    }
    const ref=(status?.wireguardRefs??[]).find(w=>w.id===key);return {type,refId:key,value:ref?.cidr||"",label:ref?`${ref.name} · ${ref.cidr}`:key};
  }
  function accessSelectorReady(type:string,key:string,custom:string){return type==="custom"?Boolean(custom.trim()):Boolean(key);}

  async function saveAccessRule(){
    if(!accessSelectorReady(accessSourceType,accessSourceKey,accessSourceCustom)||!accessSelectorReady(accessDestinationType,accessDestinationKey,accessDestinationCustom)){setMessage("Select source and destination");return;}
    const payload={
      family:accessFamily,
      source:selectorFrom(accessSourceType,accessSourceKey,accessSourceCustom),
      sourceNegate:accessSourceType==="custom"?accessSourceNegate:false,
      destination:selectorFrom(accessDestinationType,accessDestinationKey,accessDestinationCustom),
      protocol:accessProtocol,
      destinationPort:["tcp","udp"].includes(accessProtocol)&&accessPort?Number(accessPort):null,
      action:accessAction,
      description:accessDescription
    };
    setBusy(true);
    try{
      if(editingAccessId)await updateAccessRule(editingAccessId,payload);else await createAccessRule(payload);
      setEditingAccessId(null);setAccessDescription("");setAccessPort("");await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }
  function editAccessRule(rule:any){
    setEditingAccessId(rule.id);setAccessFamily(rule.family===6?6:4);
    setAccessSourceType(rule.source.type);setAccessSourceKey(rule.source.refId||"");setAccessSourceCustom(rule.source.type==="custom"?(rule.source.value||""):"");setAccessSourceNegate(Boolean(rule.sourceNegate));
    setAccessDestinationType(rule.destination.type);setAccessDestinationKey(rule.destination.refId||"");setAccessDestinationCustom(rule.destination.type==="custom"?(rule.destination.value||""):"");
    setAccessProtocol(rule.protocol);setAccessPort(rule.destinationPort?String(rule.destinationPort):"");setAccessAction(rule.action);setAccessDescription(rule.description||"");
  }
  async function toggleAccessRule(rule:any){setBusy(true);try{await updateAccessRule(rule.id,{enabled:!rule.enabled});await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function deleteAccessRule(id:string){setBusy(true);try{await removeAccessRule(id);if(editingAccessId===id)setEditingAccessId(null);await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function moveAccessRule(id:string,direction:-1|1){
    const rules=[...(status?.config.accessRules??[])];const index=rules.findIndex(r=>r.id===id);const target=index+direction;if(index<0||target<0||target>=rules.length)return;
    [rules[index],rules[target]]=[rules[target],rules[index]];
    setBusy(true);try{await reorderAccessRules(rules.map(r=>r.id));await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}
  }
  async function moveManagedRule(kind:"network"|"published"|"input",id:string,direction:-1|1){
    const rules:Array<{id:string}>=kind==="network"?[...(status?.config.rules??[])]:kind==="published"?[...(status?.config.publishedPortRules??[])]:[...(status?.config.hostInputRules??[])];
    const index=rules.findIndex(r=>r.id===id),target=index+direction;if(index<0||target<0||target>=rules.length)return;
    [rules[index],rules[target]]=[rules[target],rules[index]];
    setBusy(true);
    try{
      const ids=rules.map(r=>r.id);
      if(kind==="network")await reorderFirewallRules(ids);
      else if(kind==="published")await reorderPublishedPortRules(ids);
      else await reorderHostInputRules(ids);
      await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }
  function selectorLabel(sel:any){
    if(sel.type==="custom")return sel.value||"—";
    return sel.label||sel.value||sel.refId||"—";
  }
  function ruleCounter(kind:"network"|"published"|"input"|"access",id:string){
    return status?.ruleCounters?.[`${kind}:${id}`] ?? {packets:0,bytes:0};
  }
  function counterView(counter:{packets:number;bytes:number}){
    return <div className="fw-rule-counter"><strong>{counter.packets.toLocaleString()}</strong><small>pkts · {formatBytes(counter.bytes)}</small></div>;
  }

  const allFirewallRules=status?.allFirewallRules??[];
  const firewallChains=Array.from(new Set(allFirewallRules.map(r=>r.chain))).sort();
  const visibleFirewallRules=allFirewallRules.filter(rule=>{
    if(fwOwnerFilter!=="All"&&rule.owner!==fwOwnerFilter)return false;
    if(fwFamilyFilter==="IPv4"&&rule.family!==4)return false;
    if(fwFamilyFilter==="IPv6"&&rule.family!==6)return false;
    if(fwChainFilter!=="All"&&rule.chain!==fwChainFilter)return false;
    const q=fwSearch.trim().toLowerCase();
    if(!q)return true;
    return [rule.chain,rule.protocol,rule.source,rule.destination,rule.inInterface,rule.outInterface,rule.sourcePort,rule.destinationPort,rule.target,rule.state,rule.comment,rule.owner,rule.raw].filter(Boolean).join(" ").toLowerCase().includes(q);
  });

  return <div className="firewall-stack">
    <div className="panel firewall-global">
      <div className="firewall-global-left">
        <div className="engine-line">
          <div>
            <span className="stat-label">Firewall Engine</span>
            <strong className="firewall-state">{status?.config.enabled ? "Enabled" : "Disabled"}</strong>
            <span className="stat-hint">{status?.engine ?? "—"} · {status?.managedChain ?? "—"}</span>
          </div>

          <button
            className={status?.config.enabled ? "engine-toggle on" : "engine-toggle"}
            disabled={busy || !status}
            onClick={()=>doAction(status?.config.enabled ? "disable" : "apply")}
            title={status?.config.enabled ? "Disable Firewall Engine" : "Enable Firewall Engine"}
          >
            <span className="toggle-knob"></span>
            <span className="toggle-label">{status?.config.enabled ? "ON" : "OFF"}</span>
          </button>
        </div>

        <div className="engine-meta">
          <span className={status?.pendingChanges ? "change-state pending" : "change-state applied"}>
            {status?.pendingChanges ? "Pending changes" : "Applied"}
          </span>
          <span className="last-applied">
            Last applied: {status?.lastAppliedAt ? new Date(status.lastAppliedAt).toLocaleString() : "Never"}
          </span>
          <span className="runtime-jump">
            DOCKER-USER jump: {status?.runtime.jumpPresent ? "active" : "inactive"}
          </span>
        </div>
      </div>

      <div className="firewall-global-actions">
        <button className="btn secondary" disabled={busy} onClick={()=>doAction("rollback")}>Rollback</button>
        <button className="btn primary" disabled={busy || !status?.pendingChanges} onClick={()=>doAction("apply")}>Apply changes</button>
      </div>
    </div>

    {message && <div className="error-banner"><Shield size={18}/><div><strong>Firewall error</strong><span>{message}</span></div></div>}

    <div className="panel">
      <div className="firewall-titlebar"><PanelTitle title="Host / INPUT" subtitle="Control services listening on the Docker host, including WAN-facing ports"/></div>
      <div className="host-input-builder">
        <label><span>Detected host port</span><select value={hostPortKey} onChange={e=>chooseHostPort(e.target.value)}><option value="">Custom / select listening port</option>{(status?.hostPortRefs??[]).map((x,i)=><option key={`${x.protocol}-${x.listenAddress}-${x.port}-${i}`} value={`${x.protocol}|${x.listenAddress}|${x.port}`}>{x.listenAddress}:{x.port}/{x.protocol}</option>)}</select></label>
        <label><span>Interface</span><select value={hostInterface} onChange={e=>setHostInterface(e.target.value)}><option value="*">Any interface</option>{(status?.hostInterfaces??[]).map(x=><option key={x.name} value={x.name}>{x.name}{x.name===status?.defaultWanInterface?" · WAN":""}</option>)}</select></label>
        <label><span>Address family</span><select value={hostFamily} onChange={e=>{const v=e.target.value;setHostFamily(v==="both"?"both":Number(v) as 4|6);setHostSource(v==="6"?"::/0":"0.0.0.0/0");}}><option value="4">IPv4</option><option value="6">IPv6</option><option value="both">Both</option></select></label>
        <label><span>Source CIDR</span><input value={hostSource} onChange={e=>setHostSource(e.target.value)} placeholder={hostFamily===6?"::/0":"0.0.0.0/0"}/></label><label className="fw-except-check"><span>Source match</span><div><input type="checkbox" checked={hostSourceNegate} onChange={e=>setHostSourceNegate(e.target.checked)}/><strong>! Except this CIDR</strong></div></label>
        <label><span>Protocol</span><select value={hostProtocol} onChange={e=>setHostProtocol(e.target.value as any)}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option><option value="all">ANY</option></select></label>
        <label><span>Port</span><input disabled={!["tcp","udp"].includes(hostProtocol)} value={hostPort} onChange={e=>setHostPort(e.target.value.replace(/\D/g,""))}/></label>
        <label><span>Action</span><select value={hostAction} onChange={e=>setHostAction(e.target.value as any)}><option value="ACCEPT">ACCEPT</option><option value="DROP">DROP</option><option value="REJECT">REJECT</option></select></label>
        <label><span>Description</span><input value={hostDescription} onChange={e=>setHostDescription(e.target.value)} placeholder="Optional"/></label>
        <button className="btn add-rule" disabled={busy} onClick={addHostRule}>Add rule</button>
      </div>
      <div className="host-input-list">{(status?.config.hostInputRules??[]).map((rule,index)=><div className="host-input-row" key={rule.id}><div className="fw-order"><strong>#{index+1}</strong><button disabled={busy||index===0} onClick={()=>moveManagedRule("input",rule.id,-1)}>↑</button><button disabled={busy||index===(status?.config.hostInputRules.length??1)-1} onClick={()=>moveManagedRule("input",rule.id,1)}>↓</button></div><div><strong>{rule.interfaceName==="*"?"ANY":rule.interfaceName}</strong><small>{rule.localAddress||"any host IP"}</small></div><code>{rule.family===6?"IPv6":rule.family==="both"?"Dual":"IPv4"} · {rule.protocol.toUpperCase()} {rule.destinationPort??"ANY"}</code><code>{rule.sourceNegate?"! ":""}{rule.sourceCidr}</code><span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>{counterView(ruleCounter("input",rule.id))}<span className="truncate">{rule.description||"—"}</span><button className="icon-danger" onClick={()=>removeHostRule(rule.id)}><Trash2 size={15}/></button></div>)}{!status?.config.hostInputRules?.length&&<div className="muted published-empty">No host INPUT rules configured</div>}</div>
    </div>

    <div className="panel">
      <div className="firewall-titlebar">
        <PanelTitle title="Inbound / Published Ports" subtitle="Control access from outside to Docker host published ports"/>
      </div>

      <div className="session-policy-note">
        <Shield size={15}/>
        <div>
          <strong>Existing sessions are terminated on Apply</strong>
          <span>For DROP/REJECT, DRM deletes matching conntrack sessions for this published port.</span>
        </div>
      </div>

      <div className="published-rule-builder">
        <label><span>Published Docker port</span>
          <select value={publishedKey} onChange={e=>setPublishedKey(e.target.value)}>
            <option value="">Select published port</option>
            {publishedRefs.map((x,i)=>{
              const key=`${x.containerId}|${x.hostIp}|${x.publishedPort}|${x.protocol}|${x.containerPort}`;
              return <option key={`${key}-${i}`} value={key}>
                {x.hostIp}:{x.publishedPort}/{x.protocol} → {x.containerName}:{x.containerPort}
              </option>;
            })}
          </select>
        </label>
        <label><span>WAN interface</span><select value={publishedInterface} onChange={e=>setPublishedInterface(e.target.value)}><option value="*">Any interface</option>{(status?.hostInterfaces??[]).map(x=><option key={x.name} value={x.name}>{x.name}{x.name===status?.defaultWanInterface?" · default WAN":""}</option>)}</select></label>
        <label><span>Address family</span><select value={publishedFamily} onChange={e=>{const v=Number(e.target.value) as 4|6;setPublishedFamily(v);const any=v===6?"::/0":"0.0.0.0/0";setPublishedSource(any);setPublishedDestination(any);setPublishedDestinationType("any");setPublishedDestinationNetwork("");}}><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
        <label><span>Source CIDR</span>
          <input value={publishedSource} onChange={e=>setPublishedSource(e.target.value)} placeholder={publishedFamily===6?"::/0":"0.0.0.0/0"}/>
        </label><label className="fw-except-check"><span>Source match</span><div><input type="checkbox" checked={publishedSourceNegate} onChange={e=>setPublishedSourceNegate(e.target.checked)}/><strong>! Except this CIDR</strong></div></label>
        <label><span>Destination type</span>
          <select value={publishedDestinationType} onChange={e=>{
            const type=e.target.value as "any"|"docker-network"|"custom";
            setPublishedDestinationType(type);
            setPublishedDestinationNetwork("");
            if(type==="any") setPublishedDestination(publishedFamily===6?"::/0":"0.0.0.0/0");
            if(type==="custom") setPublishedDestination("");
          }}>
            <option value="any">Any</option>
            <option value="docker-network">Docker Network</option>
            <option value="custom">Custom CIDR</option>
          </select>
        </label>
        {publishedDestinationType==="docker-network"&&<label><span>Destination Docker network</span>
          <select value={publishedDestinationNetwork} onChange={e=>{
            setPublishedDestinationNetwork(e.target.value);
            const ref=publishedDestinationNetworks.find(x=>x.key===e.target.value);
            setPublishedDestination(ref?.cidr||"");
          }}>
            <option value="">Select Docker network</option>
            {publishedDestinationNetworks.map(x=><option key={x.key} value={x.key}>{x.name} · {x.cidr}</option>)}
          </select>
        </label>}
        {publishedDestinationType==="custom"&&<label><span>Destination CIDR</span>
          <input value={publishedDestination} onChange={e=>setPublishedDestination(e.target.value)} placeholder={publishedFamily===6?"fd20:20::/64":"172.20.0.0/16"}/>
        </label>}
        <label><span>Action</span>
          <select value={publishedAction} onChange={e=>setPublishedAction(e.target.value as any)}>
            <option value="DROP">DROP</option><option value="REJECT">REJECT</option><option value="ACCEPT">ACCEPT</option>
          </select>
        </label>
        <label><span>Description</span>
          <input value={publishedDescription} onChange={e=>setPublishedDescription(e.target.value)} placeholder="Optional"/>
        </label>
        <button className="btn add-rule" disabled={busy} onClick={addPublishedRule}>Add rule</button>
      </div>

      <div className="published-policy-list">
        {(status?.config.publishedPortRules ?? []).map((rule,index)=>
          <div className="published-policy-row" key={rule.id}>
            <div className="fw-order"><strong>#{index+1}</strong><button disabled={busy||index===0} onClick={()=>moveManagedRule("published",rule.id,-1)}>↑</button><button disabled={busy||index===(status?.config.publishedPortRules.length??1)-1} onClick={()=>moveManagedRule("published",rule.id,1)}>↓</button></div>
            <div><strong>{rule.family===6?"IPv6":"IPv4"} · {(rule.interfaceName&&rule.interfaceName!=="*")?rule.interfaceName:"ANY WAN"} · {rule.hostIp}:{rule.publishedPort}/{rule.protocol}</strong>
              <small>→ {rule.containerName}:{rule.containerPort}</small></div>
            <div className="published-cidrs"><code>{rule.sourceNegate?"! ":""}{rule.sourceCidr}</code><small>→ {rule.destinationCidr || (rule.family===6?"::/0":"0.0.0.0/0")}</small></div>
            <span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>
            {counterView(ruleCounter("published",rule.id))}
            <span className="truncate">{rule.description || "—"}</span>
            <button className="icon-danger" disabled={busy} onClick={()=>removePublished(rule.id)} title="Delete rule"><Trash2 size={15}/></button>
          </div>
        )}
        {!status?.config.publishedPortRules?.length && <div className="muted published-empty">No published-port firewall rules configured</div>}
      </div>
    </div>

    <div className="panel access-firewall-panel">
      <div className="firewall-titlebar">
        <PanelTitle title="Container Access / Forwarding" subtitle="Dynamic Docker-aware rules follow current container IPs, Compose recreation and Docker network subnets"/>
      </div>
      <div className="session-policy-note"><Shield size={15}/><div><strong>First match wins · Docker references are dynamic</strong><span>After Apply, DRM automatically refreshes active rules when a selected container IP or Docker network changes. New or edited definitions remain draft until Apply changes.</span></div></div>

      <div className="access-rule-builder">
        <label><span>Family</span><select value={accessFamily} onChange={e=>{const f=Number(e.target.value) as 4|6;setAccessFamily(f);setAccessSourceKey("");setAccessDestinationKey("");setAccessSourceCustom("");setAccessDestinationCustom("");}}><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
        <label><span>Source type</span><select value={accessSourceType} onChange={e=>{setAccessSourceType(e.target.value as any);setAccessSourceKey("");}}><option value="wireguard">WireGuard network</option><option value="container">Container</option><option value="docker-network">Docker network</option><option value="custom">Custom IP / CIDR</option></select></label>
        <label className="access-selector-field"><span>Source</span>
          {accessSourceType==="custom"?<input value={accessSourceCustom} onChange={e=>setAccessSourceCustom(e.target.value)} placeholder={accessFamily===6?"fd42:8::2/128":"10.8.0.2/32"}/>:
           <select value={accessSourceKey} onChange={e=>setAccessSourceKey(e.target.value)}><option value="">Select source</option>
             {accessSourceType==="wireguard"&&accessWireGuardOptions.map(x=><option key={x.id} value={x.id}>{x.kind==="tunnel"?"Tunnel":x.kind==="peer"?"Peer":"Remote network"} · {x.name} · {x.cidr}</option>)}
             {accessSourceType==="container"&&accessContainerOptions.map(x=><option key={x.id} value={x.id}>{x.name} · {x.addresses.filter(a=>a.family===accessFamily).map(a=>a.address).join(", ")}</option>)}
             {accessSourceType==="docker-network"&&accessNetworkOptions.map(x=><option key={x.id} value={x.id}>{x.name} · {x.subnets.filter(c=>accessFamily===6?c.includes(":"):c.includes(".")).join(", ")}</option>)}
           </select>}
        </label>
        {accessSourceType==="custom"&&<label className="fw-except-check"><span>Source match</span><div><input type="checkbox" checked={accessSourceNegate} onChange={e=>setAccessSourceNegate(e.target.checked)}/><strong>! Except this CIDR</strong></div><small>Invert only the custom source CIDR</small></label>}
        <label><span>Destination type</span><select value={accessDestinationType} onChange={e=>{setAccessDestinationType(e.target.value as any);setAccessDestinationKey("");}}><option value="container">Container</option><option value="docker-network">Docker network</option><option value="wireguard">WireGuard network</option><option value="custom">Custom IP / CIDR</option></select></label>
        <label className="access-selector-field"><span>Destination</span>
          {accessDestinationType==="custom"?<input value={accessDestinationCustom} onChange={e=>setAccessDestinationCustom(e.target.value)} placeholder={accessFamily===6?"fd20:20::2/128":"172.20.0.2/32"}/>:
           <select value={accessDestinationKey} onChange={e=>setAccessDestinationKey(e.target.value)}><option value="">Select destination</option>
             {accessDestinationType==="wireguard"&&accessWireGuardOptions.map(x=><option key={x.id} value={x.id}>{x.kind==="tunnel"?"Tunnel":x.kind==="peer"?"Peer":"Remote network"} · {x.name} · {x.cidr}</option>)}
             {accessDestinationType==="container"&&accessContainerOptions.map(x=><option key={x.id} value={x.id}>{x.name} · {x.addresses.filter(a=>a.family===accessFamily).map(a=>a.address).join(", ")}</option>)}
             {accessDestinationType==="docker-network"&&accessNetworkOptions.map(x=><option key={x.id} value={x.id}>{x.name} · {x.subnets.filter(c=>accessFamily===6?c.includes(":"):c.includes(".")).join(", ")}</option>)}
           </select>}
        </label>
        <label><span>Protocol</span><select value={accessProtocol} onChange={e=>setAccessProtocol(e.target.value as any)}><option value="all">ANY</option><option value="tcp">TCP</option><option value="udp">UDP</option>{accessFamily===4?<option value="icmp">ICMP</option>:<option value="icmpv6">ICMPv6</option>}</select></label>
        <label><span>Port</span><input disabled={!["tcp","udp"].includes(accessProtocol)} value={accessPort} onChange={e=>setAccessPort(e.target.value.replace(/\D/g,""))} placeholder={["tcp","udp"].includes(accessProtocol)?"1-65535":"—"}/></label>
        <label><span>Action</span><select value={accessAction} onChange={e=>setAccessAction(e.target.value as any)}><option value="DROP">DROP</option><option value="REJECT">REJECT</option><option value="ACCEPT">ACCEPT</option></select></label>
        <label><span>Description</span><input value={accessDescription} onChange={e=>setAccessDescription(e.target.value)} placeholder="Optional"/></label>
        <button className="btn add-rule" disabled={busy} onClick={saveAccessRule}>{editingAccessId?"Save rule":"Add rule"}</button>
        {editingAccessId&&<button className="btn secondary" disabled={busy} onClick={()=>setEditingAccessId(null)}>Cancel</button>}
      </div>

      <div className="access-rule-list">
        {(status?.config.accessRules??[]).map((rule,index)=>{
          const counter=ruleCounter("access",rule.id);
          return <div className={`access-rule-row ${!rule.enabled?"disabled":""}`} key={rule.id}>
            <div className="access-order"><strong>{index+1}</strong><button disabled={busy||index===0} onClick={()=>moveAccessRule(rule.id,-1)}>↑</button><button disabled={busy||index===(status?.config.accessRules.length??1)-1} onClick={()=>moveAccessRule(rule.id,1)}>↓</button></div>
            <div><span className="access-family">{rule.family===6?"IPv6":"IPv4"}</span><strong>{rule.sourceNegate?"! ":""}{selectorLabel(rule.source)}</strong><small>{rule.source.type}</small></div>
            <div className="access-arrow">→</div>
            <div><strong>{selectorLabel(rule.destination)}</strong><small>{rule.destination.type}</small></div>
            <div className="access-live-resolution">
              {status?.accessRuleResolution?.[rule.id]?.resolved
                ? <><span className="pill green">LIVE</span><small>{(status.accessRuleResolution[rule.id].source??[]).join(", ")||"—"} → {(status.accessRuleResolution[rule.id].destination??[]).join(", ")||"—"}</small></>
                : <><span className="pill warning">WAITING</span><small>{status?.accessRuleResolution?.[rule.id]?.message||"Waiting for Docker object"}</small></>}
            </div>
            <code>{rule.protocol.toUpperCase()} {rule.destinationPort??"ANY"}</code>
            <span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>
            <div className="access-counter"><strong>{counter.packets.toLocaleString()}</strong><small>pkts · {formatBytes(counter.bytes)}</small></div>
            <span className="truncate">{rule.description||"—"}</span>
            <div className="access-actions"><button className="btn secondary" onClick={()=>editAccessRule(rule)}>Edit</button><button className="btn secondary" onClick={()=>toggleAccessRule(rule)}>{rule.enabled?"Disable":"Enable"}</button><button className="icon-danger" onClick={()=>deleteAccessRule(rule.id)}><Trash2 size={15}/></button></div>
          </div>;
        })}
        {!status?.config.accessRules?.length&&<div className="muted published-empty">No container access rules configured</div>}
      </div>
    </div>

    <div className="panel">
      <div className="firewall-titlebar">
        <PanelTitle title="Create policy" subtitle="Rules are saved as draft; use Apply changes in the Firewall Engine panel"/>
      </div>

      <div className="rule-builder">
        <label><span>Address family</span><select value={family} onChange={e=>setFamily(e.target.value==="both"?"both":Number(e.target.value) as 4|6)}><option value="both">IPv4 + IPv6</option><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
        <label><span>Source network</span><select value={source} onChange={e=>setSource(e.target.value)}>
          <option value="">Select network</option>{networks.map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.join(", ")}</option>)}
        </select></label>
        <label><span>Destination network</span><select value={destination} onChange={e=>setDestination(e.target.value)}>
          <option value="">Select network</option>{networks.map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.join(", ")}</option>)}
        </select></label>
        <label><span>Protocol</span><select value={protocol} onChange={e=>setProtocol(e.target.value as any)}>
          <option value="all">ANY</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option>
        </select></label>
        <label><span>Destination port</span><input disabled={!["tcp","udp"].includes(protocol)} value={port}
          onChange={e=>setPort(e.target.value.replace(/\D/g,""))} placeholder={["tcp","udp"].includes(protocol)?"1-65535":"—"}/></label>
        <label><span>Action</span><select value={action} onChange={e=>setAction(e.target.value as any)}>
          <option value="ACCEPT">ACCEPT</option><option value="DROP">DROP</option><option value="REJECT">REJECT</option>
        </select></label>
        <label className="description-field"><span>Description</span><input value={description} onChange={e=>setDescription(e.target.value)} placeholder="Optional"/></label>
        <button className="btn add-rule" disabled={busy} onClick={addRule}>Add rule</button>
      </div>
    </div>

    <div className="table-panel">
      <div className="fw-table-head"><span>#</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Port</span><span>Action</span><span>Hits / Traffic</span><span>Description</span><span></span></div>
      {(status?.config.rules ?? []).map((rule,index)=><div className="fw-table-row" key={rule.id}>
        <div className="fw-order"><strong>#{index+1}</strong><button disabled={busy||index===0} onClick={()=>moveManagedRule("network",rule.id,-1)}>↑</button><button disabled={busy||index===(status?.config.rules.length??1)-1} onClick={()=>moveManagedRule("network",rule.id,1)}>↓</button></div>
        <div><strong>{byId.get(rule.sourceNetworkId)?.name ?? "Missing network"}</strong><small>{byId.get(rule.sourceNetworkId)?.subnets.join(", ")}</small></div>
        <div><strong>{byId.get(rule.destinationNetworkId)?.name ?? "Missing network"}</strong><small>{byId.get(rule.destinationNetworkId)?.subnets.join(", ")}</small></div>
        <code>{rule.protocol.toUpperCase()}</code><code>{rule.destinationPort ?? "ANY"}</code>
        <span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>
        {counterView(ruleCounter("network",rule.id))}
        <span className="truncate">{rule.description || "—"}</span>
        <button className="icon-danger" disabled={busy} onClick={()=>remove(rule.id)} title="Delete rule"><Trash2 size={15}/></button>
      </div>)}
      {!status?.config.rules.length && <Empty text="No firewall rules configured"/>}
    </div>

    <div className="panel all-firewall-panel">
      <PanelTitle title="All Firewall Rules" subtitle="Live read-only view of the host IPv4 and IPv6 filter tables, including DRM, Docker and external/system rules"/>
      <div className="all-firewall-toolbar">
        <label><span>Owner</span><select value={fwOwnerFilter} onChange={e=>setFwOwnerFilter(e.target.value as any)}><option>All</option><option>DRM</option><option>Docker</option><option>System-External</option></select></label>
        <label><span>Family</span><select value={fwFamilyFilter} onChange={e=>setFwFamilyFilter(e.target.value as any)}><option>All</option><option>IPv4</option><option>IPv6</option></select></label>
        <label><span>Chain</span><select value={fwChainFilter} onChange={e=>setFwChainFilter(e.target.value)}><option>All</option>{firewallChains.map(chain=><option key={chain}>{chain}</option>)}</select></label>
        <label className="all-firewall-search"><span>Search</span><input value={fwSearch} onChange={e=>setFwSearch(e.target.value)} placeholder="IP, port, target, interface, state…"/></label>
        <div className="all-firewall-count"><span>Shown</span><strong>{visibleFirewallRules.length} / {allFirewallRules.length}</strong></div>
      </div>
      <div className="all-firewall-table-wrap">
        <table className="all-firewall-table">
          <thead><tr><th>Owner</th><th>Family</th><th>Chain</th><th>#</th><th>Packets</th><th>Bytes</th><th>Protocol</th><th>Source</th><th>Destination</th><th>In</th><th>Out</th><th>Ports / State</th><th>Target</th></tr></thead>
          <tbody>{visibleFirewallRules.length===0?<tr><td colSpan={13}><div className="empty-state">No firewall rules match the current filters</div></td></tr>:visibleFirewallRules.map(rule=>{
            const details=[
              rule.sourcePort?`sport ${rule.sourcePort}`:"",
              rule.destinationPort?`dport ${rule.destinationPort}`:"",
              rule.state?`state ${rule.state}`:""
            ].filter(Boolean).join(" · ")||"—";
            const ownerClass=rule.owner==="DRM"?"green":rule.owner==="Docker"?"blue":"warning";
            const targetClass=rule.target==="ACCEPT"?"green":rule.target==="DROP"?"danger":rule.target==="REJECT"?"warning":"";
            return <tr key={rule.id}>
              <td><span className={`pill ${ownerClass}`}>{rule.owner}</span></td>
              <td><span className={`pill ${rule.family===4?"blue":""}`}>{rule.family===4?"IPv4":"IPv6"}</span></td>
              <td><code>{rule.chain}</code></td><td>{rule.position}</td>
              <td>{rule.packets.toLocaleString()}</td><td>{formatBytes(rule.bytes)}</td>
              <td>{rule.protocol.toUpperCase()}</td><td><code>{rule.source}</code></td><td><code>{rule.destination}</code></td>
              <td>{rule.inInterface??"—"}</td><td>{rule.outInterface??"—"}</td><td><code>{details}</code></td>
              <td><span className={`pill ${targetClass}`}>{rule.target||"—"}</span></td>
            </tr>
          })}</tbody>
        </table>
      </div>
      <div className="session-policy-note"><Shield size={15}/><div><strong>Read-only system view</strong><span>DRM, Docker and system/external filter rules are shown exactly as installed on the host. Docker and external rules are diagnostic only and cannot be edited from this table.</span></div></div>
    </div>

    <div className="panel runtime-panel">
      <PanelTitle title="DRM Runtime Rules" subtitle="Raw rules currently installed in the DRM managed IPv4 chain"/>
      <pre>{status?.runtime.installedRules.length ? status.runtime.installedRules.join("\\n") : "No DRM runtime rules installed."}</pre>
    </div>
  </div>;
}




function NatPage({canManage}:{canManage:boolean}){
  const [status,setStatus]=useState<NatStatus|null>(null);
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [editingOut,setEditingOut]=useState<string|null>(null);
  const [editingDnat,setEditingDnat]=useState<string|null>(null);
  const [natOwnerFilter,setNatOwnerFilter]=useState<"All"|"DRM"|"Docker"|"System-External">("All");
  const [natChainFilter,setNatChainFilter]=useState("All");
  const [natSearch,setNatSearch]=useState("");
  const [outForm,setOutForm]=useState({type:"masquerade" as "masquerade"|"snat",sourceType:"docker-network" as "docker-network"|"custom",sourceKey:"",sourceCidr:"10.0.0.0/24",outInterface:"",toSourceIp:"",policyRoute:true,description:""});
  const [dnatForm,setDnatForm]=useState({inInterface:"",externalIp:"0.0.0.0",protocol:"tcp" as "tcp"|"udp",externalPort:"8080",sourceCidr:"0.0.0.0/0",destinationKind:"container" as "container"|"ip",containerId:"",networkName:"",destinationIp:"",internalPort:"80",createFirewallRule:true,description:""});

  async function load(){
    try{
      const next=await getNatStatus();setStatus(next);setError("");
      setOutForm(current=>({...current,outInterface:current.outInterface||next.defaultWanInterface||next.hostInterfaces[0]?.name||"",sourceKey:current.sourceKey||next.networkRefs[0]?.id||""}));
      setDnatForm(current=>({...current,inInterface:current.inInterface||next.defaultWanInterface||next.hostInterfaces[0]?.name||"",containerId:current.containerId||next.containerRefs[0]?.id||""}));
    }catch(e){setError(e instanceof Error?e.message:String(e));}
  }
  useEffect(()=>{load();const timer=window.setInterval(load,5000);return()=>window.clearInterval(timer)},[]);

  const selectedOutInterface=status?.hostInterfaces.find(x=>x.name===outForm.outInterface);
  const selectedDnatInterface=status?.hostInterfaces.find(x=>x.name===dnatForm.inInterface);
  const selectedContainer=status?.containerRefs.find(x=>x.id===dnatForm.containerId);

  async function saveOutbound(){
    setBusy(true);setError("");
    try{
      const network=status?.networkRefs.find(n=>n.id===outForm.sourceKey);
      const source=outForm.sourceType==="custom"
        ? {type:"custom",value:outForm.sourceCidr,label:outForm.sourceCidr}
        : {type:"docker-network",refId:network?.id??outForm.sourceKey,refName:network?.name??null,label:network?.name??outForm.sourceKey};
      const body={type:outForm.type,source,outInterface:outForm.outInterface,toSourceIp:outForm.type==="snat"?outForm.toSourceIp:null,policyRoute:outForm.policyRoute,description:outForm.description,enabled:true};
      if(editingOut)await updateNatRule(editingOut,body);else await createNatRule(body);
      setEditingOut(null);setOutForm(f=>({...f,type:"masquerade",toSourceIp:"",description:""}));await load();
    }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false)}
  }

  async function saveDnat(){
    setBusy(true);setError("");
    try{
      const container=status?.containerRefs.find(c=>c.id===dnatForm.containerId);
      const destination=dnatForm.destinationKind==="ip"
        ? {kind:"ip",ip:dnatForm.destinationIp}
        : {kind:"container",refId:container?.id??dnatForm.containerId,refName:container?.name??null,label:container?.name??dnatForm.containerId,networkName:dnatForm.networkName||null};
      const body={type:"dnat",inInterface:dnatForm.inInterface,externalIp:dnatForm.externalIp||"0.0.0.0",protocol:dnatForm.protocol,externalPort:Number(dnatForm.externalPort),sourceCidr:dnatForm.sourceCidr,destination,internalPort:Number(dnatForm.internalPort),createFirewallRule:dnatForm.createFirewallRule,description:dnatForm.description,enabled:true};
      if(editingDnat)await updateNatRule(editingDnat,body);else await createNatRule(body);
      setEditingDnat(null);setDnatForm(f=>({...f,externalPort:"8080",internalPort:"80",description:""}));await load();
    }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false)}
  }

  function editOutbound(rule:NatOutboundRule){
    setEditingOut(rule.id);setEditingDnat(null);
    setOutForm({type:rule.type,sourceType:rule.source.type==="docker-network"?"docker-network":"custom",sourceKey:rule.source.refId??"",sourceCidr:rule.source.value??"",outInterface:rule.outInterface,toSourceIp:rule.toSourceIp??"",policyRoute:rule.policyRoute!==false,description:rule.description??""});
  }
  function editDnat(rule:NatDnatRule){
    setEditingDnat(rule.id);setEditingOut(null);
    setDnatForm({inInterface:rule.inInterface,externalIp:rule.externalIp,protocol:rule.protocol,externalPort:String(rule.externalPort),sourceCidr:rule.sourceCidr,destinationKind:rule.destination.kind,containerId:rule.destination.kind==="container"?rule.destination.refId:"",networkName:rule.destination.kind==="container"?(rule.destination.networkName??""):"",destinationIp:rule.destination.kind==="ip"?rule.destination.ip:"",internalPort:String(rule.internalPort),createFirewallRule:rule.createFirewallRule,description:rule.description??""});
  }
  async function toggle(rule:NatRule){try{await updateNatRule(rule.id,{enabled:!rule.enabled});await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  async function remove(rule:NatRule){if(!window.confirm(`Delete NAT rule ${rule.description||rule.id}?`))return;try{await removeNatRule(rule.id);if(editingOut===rule.id)setEditingOut(null);if(editingDnat===rule.id)setEditingDnat(null);await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}

  const outbound=(status?.config.rules??[]).filter((r):r is NatOutboundRule=>r.type!=="dnat");
  const dnat=(status?.config.rules??[]).filter((r):r is NatDnatRule=>r.type==="dnat");
  const allNatRules=status?.allNatRules??[];
  const natChains=Array.from(new Set(allNatRules.map(r=>r.chain))).sort();
  const visibleNatRules=allNatRules.filter(rule=>{
    if(natOwnerFilter!=="All"&&rule.owner!==natOwnerFilter)return false;
    if(natChainFilter!=="All"&&rule.chain!==natChainFilter)return false;
    const q=natSearch.trim().toLowerCase();
    if(!q)return true;
    return [rule.chain,rule.protocol,rule.source,rule.destination,rule.inInterface,rule.outInterface,rule.target,rule.sourcePort,rule.destinationPort,rule.toDestination,rule.toSource,rule.owner,rule.raw].filter(Boolean).join(" ").toLowerCase().includes(q);
  });
  const fmtBytes=(value:number)=>value>=1024*1024*1024?`${(value/1024/1024/1024).toFixed(1)} GB`:value>=1024*1024?`${(value/1024/1024).toFixed(1)} MB`:value>=1024?`${(value/1024).toFixed(1)} KB`:`${value} B`;
  return <div className="nat-stack">
    {error&&<div className="error-banner"><AlertTriangle size={18}/><div><strong>NAT error</strong><span>{error}</span></div></div>}
    <div className="panel nat-overview">
      <PanelTitle title="NAT Engine" subtitle="Managed IPv4 MASQUERADE, SNAT and DNAT with dynamic Docker container resolution"/>
      <div className="nat-summary">
        <div><span>PREROUTING</span><strong className={status?.engine.preChainPresent?"good-text":"warn-text"}>{status?.engine.preChainPresent?"ACTIVE":"NOT INSTALLED"}</strong></div>
        <div><span>POSTROUTING</span><strong className={status?.engine.postChainPresent?"good-text":"warn-text"}>{status?.engine.postChainPresent?"ACTIVE":"NOT INSTALLED"}</strong></div>
        <div><span>Default WAN</span><strong>{status?.defaultWanInterface??"—"}</strong></div>
        <div><span>Dynamic sync</span><strong>{status?.dynamic.intervalMs?`${status.dynamic.intervalMs/1000}s`:"—"}</strong></div>
      </div>
      {status?.dynamic.lastError&&<div className="network-form-error">{status.dynamic.lastError}</div>}
    </div>

    <div className="panel">
      <PanelTitle title="Outbound NAT" subtitle="Choose which Docker/private source networks leave through each WAN"/>
      {canManage&&<div className="nat-builder">
        <label><span>Mode</span><select value={outForm.type} onChange={e=>setOutForm({...outForm,type:e.target.value as any})}><option value="masquerade">MASQUERADE</option><option value="snat">SNAT</option></select></label>
        <label><span>Source type</span><select value={outForm.sourceType} onChange={e=>setOutForm({...outForm,sourceType:e.target.value as any})}><option value="docker-network">Docker Network</option><option value="custom">Custom CIDR</option></select></label>
        {outForm.sourceType==="docker-network"?<label><span>Source network</span><select value={outForm.sourceKey} onChange={e=>setOutForm({...outForm,sourceKey:e.target.value})}>{(status?.networkRefs??[]).map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.join(", ")||"no subnet"}</option>)}</select></label>:<label><span>Source CIDR</span><input value={outForm.sourceCidr} onChange={e=>setOutForm({...outForm,sourceCidr:e.target.value})} placeholder="10.0.0.0/24"/></label>}
        <label><span>WAN interface</span><select value={outForm.outInterface} onChange={e=>setOutForm({...outForm,outInterface:e.target.value,toSourceIp:""})}>{(status?.hostInterfaces??[]).map(i=><option key={i.name} value={i.name}>{i.name} · {i.addresses.join(", ")||"no IPv4"}</option>)}</select></label>
        {outForm.type==="snat"&&<label><span>Source IP</span><select value={outForm.toSourceIp} onChange={e=>setOutForm({...outForm,toSourceIp:e.target.value})}><option value="">Select IP…</option>{(selectedOutInterface?.ips??[]).map(ip=><option key={ip}>{ip}</option>)}</select></label>}
        <label className="nat-check"><input type="checkbox" checked={outForm.policyRoute} onChange={e=>setOutForm({...outForm,policyRoute:e.target.checked})}/><span>Route this source through selected WAN</span></label>
        <label className="nat-description"><span>Description</span><input value={outForm.description} onChange={e=>setOutForm({...outForm,description:e.target.value})} placeholder="Office containers via ISP-1"/></label>
        <div className="nat-form-actions"><button className="btn primary" disabled={busy||!outForm.outInterface} onClick={saveOutbound}>{editingOut?"Save changes":"Add outbound rule"}</button>{editingOut&&<button className="btn secondary" onClick={()=>setEditingOut(null)}>Cancel</button>}</div>
      </div>}
      <div className="nat-rule-list">{outbound.length===0?<div className="empty-state">No outbound NAT rules</div>:outbound.map(rule=>{
        const rt=status?.runtime[rule.id];return <div className="nat-rule-row" key={rule.id}>
          <span className={`pill ${rule.enabled?"green":"warning"}`}>{rule.type.toUpperCase()}</span>
          <div><strong>{rule.source.label||rule.source.refName||rule.source.value||"Source"} → {rule.outInterface}</strong><small>{rule.type==="snat"?`SNAT ${rule.toSourceIp}`:"MASQUERADE"} · {rt?.source.join(", ")||"waiting"}{rule.policyRoute?` · policy table ${rule.routeTable}`:""}</small></div>
          <span className={`pill ${rt?.resolved?"green":"warning"}`}>{rt?.resolved?"LIVE":"WAITING"}</span>
          {canManage&&<div className="nat-actions"><button className="btn secondary" onClick={()=>editOutbound(rule)}>Edit</button><button className="btn secondary" onClick={()=>toggle(rule)}>{rule.enabled?"Disable":"Enable"}</button><button className="icon-danger" onClick={()=>remove(rule)}><Trash2 size={15}/></button></div>}
        </div>})}</div>
    </div>

    <div className="panel">
      <PanelTitle title="Port Forwarding / Container Port Mapping" subtitle="DNAT external WAN ports to an IP or a Docker container; external and internal ports are independently editable"/>
      {canManage&&<div className="nat-builder dnat-builder">
        <label><span>WAN interface</span><select value={dnatForm.inInterface} onChange={e=>setDnatForm({...dnatForm,inInterface:e.target.value,externalIp:"0.0.0.0"})}>{(status?.hostInterfaces??[]).map(i=><option key={i.name} value={i.name}>{i.name} · {i.addresses.join(", ")||"no IPv4"}</option>)}</select></label>
        <label><span>External IP</span><select value={dnatForm.externalIp} onChange={e=>setDnatForm({...dnatForm,externalIp:e.target.value})}><option value="0.0.0.0">Any IP on interface</option>{(selectedDnatInterface?.ips??[]).map(ip=><option key={ip}>{ip}</option>)}</select></label>
        <label><span>Protocol</span><select value={dnatForm.protocol} onChange={e=>setDnatForm({...dnatForm,protocol:e.target.value as any})}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        <label><span>External port</span><input type="number" min="1" max="65535" value={dnatForm.externalPort} onChange={e=>setDnatForm({...dnatForm,externalPort:e.target.value})}/></label>
        <label><span>Allowed source</span><input value={dnatForm.sourceCidr} onChange={e=>setDnatForm({...dnatForm,sourceCidr:e.target.value})} placeholder="0.0.0.0/0"/></label>
        <label><span>Destination</span><select value={dnatForm.destinationKind} onChange={e=>setDnatForm({...dnatForm,destinationKind:e.target.value as any})}><option value="container">Docker Container</option><option value="ip">IP address</option></select></label>
        {dnatForm.destinationKind==="container"?<>
          <label><span>Container</span><select value={dnatForm.containerId} onChange={e=>setDnatForm({...dnatForm,containerId:e.target.value,networkName:""})}>{(status?.containerRefs??[]).map(c=><option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
          <label><span>Container network</span><select value={dnatForm.networkName} onChange={e=>setDnatForm({...dnatForm,networkName:e.target.value})}><option value="">Follow current IPv4</option>{(selectedContainer?.networks??[]).filter(n=>n.ipv4Address).map(n=><option key={n.networkName} value={n.networkName}>{n.networkName} · {n.ipv4Address}</option>)}</select></label>
        </>:<label><span>Destination IP</span><input value={dnatForm.destinationIp} onChange={e=>setDnatForm({...dnatForm,destinationIp:e.target.value})} placeholder="192.168.1.100"/></label>}
        <label><span>Internal port</span><input type="number" min="1" max="65535" value={dnatForm.internalPort} onChange={e=>setDnatForm({...dnatForm,internalPort:e.target.value})}/></label>
        <label className="nat-check"><input type="checkbox" checked={dnatForm.createFirewallRule} onChange={e=>setDnatForm({...dnatForm,createFirewallRule:e.target.checked})}/><span>Create/update matching Firewall ACCEPT rule</span></label>
        <label className="nat-description"><span>Description</span><input value={dnatForm.description} onChange={e=>setDnatForm({...dnatForm,description:e.target.value})} placeholder="Public syslog web UI"/></label>
        <div className="nat-form-actions"><button className="btn primary" disabled={busy||!dnatForm.inInterface} onClick={saveDnat}>{editingDnat?"Save port mapping":"Add port forward"}</button>{editingDnat&&<button className="btn secondary" onClick={()=>setEditingDnat(null)}>Cancel</button>}</div>
      </div>}
      <div className="nat-rule-list">{dnat.length===0?<div className="empty-state">No DNAT / Container Port Mapping rules</div>:dnat.map(rule=>{
        const rt=status?.runtime[rule.id];const dest=rule.destination.kind==="container"?(rule.destination.label||rule.destination.refName||"container"):rule.destination.ip;return <div className="nat-rule-row dnat-row" key={rule.id}>
          <span className={`pill ${rule.enabled?"blue":"warning"}`}>DNAT</span>
          <div><strong>{rule.inInterface} · {rule.externalIp==="0.0.0.0"?"*":rule.externalIp}:{rule.externalPort}/{rule.protocol.toUpperCase()} → {dest}:{rule.internalPort}</strong><small>{rule.sourceCidr} · {rt?.destination[0]??"destination unavailable"}{rule.createFirewallRule?" · Firewall linked":""}</small></div>
          <span className={`pill ${rt?.resolved?"green":"warning"}`}>{rt?.resolved?"LIVE":"WAITING"}</span>
          {canManage&&<div className="nat-actions"><button className="btn secondary" onClick={()=>editDnat(rule)}>Edit ports</button><button className="btn secondary" onClick={()=>toggle(rule)}>{rule.enabled?"Disable":"Enable"}</button><button className="icon-danger" onClick={()=>remove(rule)}><Trash2 size={15}/></button></div>}
        </div>})}</div>
    </div>
    <div className="panel all-nat-panel">
      <PanelTitle title="All NAT Rules" subtitle="Live read-only view of the host IPv4 NAT table, including DRM, Docker and external/system rules"/>
      <div className="all-nat-toolbar">
        <label><span>Owner</span><select value={natOwnerFilter} onChange={e=>setNatOwnerFilter(e.target.value as any)}><option>All</option><option>DRM</option><option>Docker</option><option>System-External</option></select></label>
        <label><span>Chain</span><select value={natChainFilter} onChange={e=>setNatChainFilter(e.target.value)}><option>All</option>{natChains.map(chain=><option key={chain}>{chain}</option>)}</select></label>
        <label className="all-nat-search"><span>Search</span><input value={natSearch} onChange={e=>setNatSearch(e.target.value)} placeholder="IP, port, target, interface…"/></label>
        <div className="all-nat-count"><span>Shown</span><strong>{visibleNatRules.length} / {allNatRules.length}</strong></div>
      </div>
      <div className="all-nat-table-wrap">
        <table className="all-nat-table">
          <thead><tr><th>Owner</th><th>Chain</th><th>#</th><th>Packets</th><th>Bytes</th><th>Protocol</th><th>Source</th><th>Destination</th><th>In</th><th>Out</th><th>Ports / Translation</th><th>Target</th></tr></thead>
          <tbody>{visibleNatRules.length===0?<tr><td colSpan={12}><div className="empty-state">No NAT rules match the current filters</div></td></tr>:visibleNatRules.map(rule=>{
            const ports=[
              rule.sourcePort?`sport ${rule.sourcePort}`:"",
              rule.destinationPort?`dport ${rule.destinationPort}`:"",
              rule.toDestination?`→ ${rule.toDestination}`:"",
              rule.toSource?`SNAT ${rule.toSource}`:""
            ].filter(Boolean).join(" · ")||"—";
            const ownerClass=rule.owner==="DRM"?"green":rule.owner==="Docker"?"blue":"warning";
            return <tr key={rule.id}>
              <td><span className={`pill ${ownerClass}`}>{rule.owner}</span></td>
              <td><code>{rule.chain}</code></td><td>{rule.position}</td><td>{rule.packets.toLocaleString()}</td><td>{fmtBytes(rule.bytes)}</td>
              <td>{rule.protocol.toUpperCase()}</td><td><code>{rule.source}</code></td><td><code>{rule.destination}</code></td>
              <td>{rule.inInterface??"—"}</td><td>{rule.outInterface??"—"}</td><td><code>{ports}</code></td><td><strong>{rule.target||"—"}</strong></td>
            </tr>
          })}</tbody>
        </table>
      </div>
      <div className="session-policy-note"><Shield size={15}/><div><strong>Read-only system view</strong><span>Docker and System-External rules are displayed for diagnostics only. Edit or remove DRM-owned rules from Outbound NAT or Port Forwarding above.</span></div></div>
    </div>
    <div className="session-policy-note"><Shield size={15}/><div><strong>NAT and Firewall remain separate policy layers</strong><span>DNAT changes the destination. The optional linked Firewall rule permits the forwarded traffic. Disable that option if you want to manage Firewall access manually.</span></div></div>
  </div>
}


function HostInterfacesPage({canManage}:{canManage:boolean}){
  const [status,setStatus]=useState<HostInterfaceManagementStatus|null>(null),[error,setError]=useState(""),[busy,setBusy]=useState(false);
  const [kind,setKind]=useState<"physical"|"vlan">("physical"),[name,setName]=useState(""),[parent,setParent]=useState(""),[vlanId,setVlanId]=useState("100");
  const [mode,setMode]=useState<"dhcp"|"static">("static"),[address,setAddress]=useState(""),[gateway,setGateway]=useState(""),[metric,setMetric]=useState("100"),[addDefaultRoute,setAddDefaultRoute]=useState(true),[now,setNow]=useState(Date.now());
  async function load(){try{const next=await getHostInterfacesStatus();setStatus(next);setError("");const p=next.interfaces.filter(i=>i.kind==="physical");setName(v=>v||p[0]?.name||"");setParent(v=>v||p[0]?.name||"")}catch(e){setError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{load();const t=window.setInterval(load,3000),c=window.setInterval(()=>setNow(Date.now()),1000);return()=>{window.clearInterval(t);window.clearInterval(c)}},[]);
  const physical=status?.interfaces.filter(i=>i.kind==="physical")??[],pending=status?.pending??null,secondsLeft=pending?Math.max(0,Math.ceil((new Date(pending.expiresAt).getTime()-now)/1000)):0;
  function edit(i:any){setKind(i.kind==="vlan"?"vlan":"physical");if(i.kind==="vlan"){setParent(i.parent||"");setVlanId(String(i.vlanId||100))}else setName(i.name);const c=i.managedConfig;if(c){setMode(c.mode);setAddress(c.address||"");setGateway(c.gateway||"");setMetric(c.metric==null?"100":String(c.metric));setAddDefaultRoute(c.addDefaultRoute!==false)}else{setMode("static");setAddress(i.ipv4[0]||"");setGateway(i.defaultRoutes[0]?.gateway||"");setMetric(String(i.defaultRoutes[0]?.metric??100));setAddDefaultRoute(Boolean(i.defaultRoutes.length))}}
  async function apply(){setBusy(true);setError("");try{const body=kind==="vlan"?{name:`${parent}.${vlanId}`,vlan:{parent,vlanId:Number(vlanId)},mode,address:mode==="static"?address:null,gateway:mode==="static"?gateway:null,metric:metric?Number(metric):null,addDefaultRoute:mode==="dhcp"?addDefaultRoute:Boolean(gateway)}:{name,mode,address:mode==="static"?address:null,gateway:mode==="static"?gateway:null,metric:metric?Number(metric):null,addDefaultRoute:mode==="dhcp"?addDefaultRoute:Boolean(gateway)};await applyHostInterface(body);await load()}catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}
  async function confirm(){if(!pending)return;setBusy(true);try{await confirmHostInterface(pending.token);await load()}catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}
  async function rollback(){if(!pending)return;setBusy(true);try{await rollbackHostInterface(pending.token);await load()}catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}}
  async function removeVlanInterface(i:any){
    if(i.kind!=="vlan"||!i.managedVlan)return;
    if(!window.confirm(`Delete VLAN interface ${i.name}? This removes the Linux VLAN and its DRM persistent interface configuration.`))return;
    setBusy(true);setError("");
    try{await deleteHostVlan(i.name);await load()}
    catch(e){setError(e instanceof Error?e.message:String(e))}
    finally{setBusy(false)}
  }
  return <div className="interface-stack">
    {error&&<div className="error-banner"><AlertTriangle size={18}/><div><strong>Interface management error</strong><span>{error}</span></div></div>}
    {pending&&<div className="interface-pending-banner"><AlertTriangle size={20}/><div><strong>Confirm network access — {secondsLeft}s remaining</strong><span>{pending.interfaceName} is using the new configuration. If not confirmed, DRM restores the previous IPv4 addresses/default route automatically.</span></div>{canManage&&<div className="interface-pending-actions"><button className="btn primary" disabled={busy} onClick={confirm}>Confirm configuration</button><button className="btn secondary" disabled={busy} onClick={rollback}>Rollback now</button></div>}</div>}
    <div className="panel"><PanelTitle title="Host Interface Management" subtitle="Physical and 802.1Q VLAN IPv4 interfaces with DHCP/static configuration and safe rollback"/><div className="interface-summary-grid"><div><span>Physical</span><strong>{status?.interfaces.filter(i=>i.kind==="physical").length??0}</strong></div><div><span>VLAN</span><strong>{status?.interfaces.filter(i=>i.kind==="vlan").length??0}</strong></div><div><span>DRM managed</span><strong>{status?.managed.length??0}</strong></div><div><span>Rollback timer</span><strong>{status?`${Math.round(status.rollbackMs/1000)}s`:"—"}</strong></div></div></div>
    {canManage&&<div className="panel"><PanelTitle title="Configure interface" subtitle="Apply is temporary first; confirm after verifying DRM is still reachable."/><div className="interface-builder">
      <label><span>Interface type</span><select value={kind} onChange={e=>setKind(e.target.value as any)}><option value="physical">Physical interface</option><option value="vlan">802.1Q VLAN</option></select></label>
      {kind==="physical"?<label><span>Interface</span><select value={name} onChange={e=>{setName(e.target.value);const i=status?.interfaces.find(x=>x.name===e.target.value);if(i)edit(i)}}>{physical.map(i=><option key={i.name} value={i.name}>{i.name} · {i.state} · {i.ipv4.join(", ")||"no IPv4"}</option>)}</select></label>:<><label><span>Parent interface</span><select value={parent} onChange={e=>setParent(e.target.value)}>{physical.map(i=><option key={i.name} value={i.name}>{i.name} · {i.state}</option>)}</select></label><label><span>VLAN ID</span><input type="number" min="1" max="4094" value={vlanId} onChange={e=>setVlanId(e.target.value.replace(/\D/g,""))}/></label></>}
      <label><span>IPv4 mode</span><div className="family-switch"><button type="button" className={mode==="static"?"family-option active":"family-option"} onClick={()=>setMode("static")}>Static</button><button type="button" className={mode==="dhcp"?"family-option active":"family-option"} onClick={()=>setMode("dhcp")}>DHCP</button></div></label>
      {mode==="static"&&<><label><span>IPv4 address / prefix</span><input value={address} onChange={e=>setAddress(e.target.value)} placeholder="192.168.10.2/24"/></label><label><span>Default gateway</span><input value={gateway} onChange={e=>setGateway(e.target.value)} placeholder="192.168.10.1"/></label></>}{mode==="dhcp"&&<label className="interface-default-route-check"><span>DHCP routing</span><div className="wg-ipv6-check"><input type="checkbox" checked={addDefaultRoute} onChange={e=>setAddDefaultRoute(e.target.checked)}/><strong>Add default route</strong></div></label>}
      <label><span>Route metric</span><input value={metric} onChange={e=>setMetric(e.target.value.replace(/\D/g,""))} placeholder="100"/></label><div className="interface-apply-actions"><button className="btn primary" disabled={busy||Boolean(pending)||(kind==="physical"?!name:!parent||!vlanId)||(mode==="static"&&!address)} onClick={apply}>Apply & start rollback timer</button></div>
    </div><div className="session-policy-note"><Shield size={15}/><div><strong>Safe Apply</strong><span>The new configuration becomes persistent only after Confirm. If access is lost, the previous address/default route return automatically.</span></div></div></div>}
    <div className="panel"><PanelTitle title="Host interfaces" subtitle="Docker bridge/veth and WireGuard interfaces are excluded from direct address management"/><div className="host-interface-list">{(status?.interfaces??[]).map(i=><div className="host-interface-row" key={i.name}>
      <div className="host-interface-main"><div className="host-interface-name"><strong>{i.name}</strong><span className={`pill ${i.up?"green":"warning"}`}>{i.state}</span>{i.kind==="vlan"&&<span className="pill blue">VLAN {i.vlanId}</span>}{i.managedConfig&&<span className="pill green">DRM MANAGED</span>}</div><small>{i.mac||"no MAC"} · MTU {i.mtu??"—"}{i.parent?` · parent ${i.parent}`:""}</small></div>
      <div><span className="interface-cell-label">IPv4</span><code>{i.ipv4.join(", ")||"—"}</code></div><div><span className="interface-cell-label">Default route</span><code>{i.defaultRoutes.map((r:any)=>`${r.gateway||"direct"}${r.metric!=null?` metric ${r.metric}`:""}`).join(", ")||"—"}</code></div><div><span className="interface-cell-label">Mode</span><strong>{i.managedConfig?.mode?.toUpperCase()||"SYSTEM"}</strong></div>
      {canManage&&<div className="host-interface-actions"><button className="btn secondary" disabled={Boolean(pending)||busy} onClick={()=>edit(i)}>Configure</button>{i.managedConfig&&<button className="btn secondary" disabled={Boolean(pending)||busy} onClick={async()=>{if(window.confirm(`Stop DRM from restoring ${i.name} after restart? Current runtime addressing is left unchanged.`)){await forgetHostInterface(i.name);await load()}}}>Forget</button>}{i.kind==="vlan"&&i.managedVlan&&<button className="icon-danger" disabled={Boolean(pending)||busy} onClick={()=>removeVlanInterface(i)} title="Delete VLAN interface"><Trash2 size={15}/></button>}</div>}
    </div>)}{!status?.interfaces.length&&<Empty text="No manageable physical/VLAN interfaces detected"/>}</div></div>
  </div>
}

function RoutingPage(){
  const [status,setStatus]=useState<RoutingStatus|null>(null),[vrfs,setVrfs]=useState<VrfStatus|null>(null),[error,setError]=useState('');
  const [family,setFamily]=useState<4|6>(4),[destination,setDestination]=useState(''),[gateway,setGateway]=useState(''),[dev,setDev]=useState(''),[metric,setMetric]=useState('100'),[routeVrf,setRouteVrf]=useState('');
  const [editingId,setEditingId]=useState<string|null>(null),[vrfName,setVrfName]=useState('vrf-wan1'),[vrfTable,setVrfTable]=useState('29001'),[vrfIfaces,setVrfIfaces]=useState<string[]>([]),[vrfDescription,setVrfDescription]=useState(''),[editingVrf,setEditingVrf]=useState<string|null>(null);
  async function load(){try{const [r,v]=await Promise.all([getRoutingStatus(),getVrfStatus()]);setStatus(r);setVrfs(v);setError('')}catch(e){setError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{load();const t=window.setInterval(load,5000);return()=>window.clearInterval(t)},[]);
  const vrfCandidates=(status?.links??[]).filter((x:any)=>x.ifname&&x.ifname!=='lo'&&!x.ifname.startsWith('docker')&&!x.ifname.startsWith('br-')&&!x.ifname.startsWith('veth')&&x.linkinfo?.info_kind!=='vrf');
  function clearForm(){setEditingId(null);setDestination('');setGateway('');setDev('');setMetric('100');setRouteVrf('')}
  function editRoute(r:any){setEditingId(r.id);setFamily(r.family);setDestination(r.destination);setGateway(r.gateway||'');setDev(r.dev||'');setMetric(r.metric==null?'':String(r.metric));setRouteVrf(r.table?String(r.table):'')}
  async function save(){try{const table=routeVrf?Number(routeVrf):null,body={family,destination,gateway:gateway||null,dev:dev||null,metric:metric?Number(metric):null,table};if(editingId)await updateRoute(editingId,body);else await createRoute(body);clearForm();await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  function editVrf(v:ManagedVrf){setEditingVrf(v.id);setVrfName(v.name);setVrfTable(String(v.table));setVrfIfaces(v.interfaces);setVrfDescription(v.description||'')}
  function clearVrf(){setEditingVrf(null);setVrfName('vrf-wan1');setVrfTable(String(Math.min(29999,29001+(vrfs?.config.vrfs.length??0))));setVrfIfaces([]);setVrfDescription('')}
  async function saveVrf(){try{const body={name:vrfName,table:Number(vrfTable),interfaces:vrfIfaces,description:vrfDescription,enabled:true};if(editingVrf)await updateVrf(editingVrf,body);else await createVrf(body);clearVrf();await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  return <div className="firewall-stack">
    {error&&<div className="error-banner"><Route size={18}/><div><strong>Routing error</strong><span>{error}</span></div></div>}
    <div className="routing-forward-grid"><div className="panel routing-status"><div><PanelTitle title="IPv4 forwarding" subtitle="Host forwarding for IPv4 VPN, Docker, VLAN and LAN"/></div><button className={status?.ipForward?'engine-toggle on':'engine-toggle'} onClick={async()=>{await setRoutingForward(!status?.ipForward);await load()}}><span className="toggle-knob"/><span className="toggle-label">{status?.ipForward?'ON':'OFF'}</span></button></div><div className="panel routing-status"><div><PanelTitle title="IPv6 forwarding" subtitle="Host forwarding for WireGuard and Docker IPv6 networks"/></div><button className={status?.ipForward6?'engine-toggle on':'engine-toggle'} onClick={async()=>{await setRoutingForward6(!status?.ipForward6);await load()}}><span className="toggle-knob"/><span className="toggle-label">{status?.ipForward6?'ON':'OFF'}</span></button></div></div>
    <div className="panel vrf-panel"><PanelTitle title="VRF / Multi-WAN" subtitle="Create isolated Linux routing tables and bind WAN/VLAN interfaces to them"/><div className="vrf-builder"><label><span>Name</span><input value={vrfName} onChange={e=>setVrfName(e.target.value)} placeholder="vrf-wan1"/></label><label><span>Routing table</span><input value={vrfTable} onChange={e=>setVrfTable(e.target.value.replace(/\D/g,''))}/></label><label className="vrf-ifaces"><span>Interfaces</span><div className="vrf-interface-list">{vrfCandidates.map((x:any)=><label key={x.ifname}><input type="checkbox" checked={vrfIfaces.includes(x.ifname)} onChange={e=>setVrfIfaces(e.target.checked?[...vrfIfaces,x.ifname]:vrfIfaces.filter(n=>n!==x.ifname))}/><strong>{x.ifname}</strong><small>{x.operstate||''}</small></label>)}</div></label><label><span>Description</span><input value={vrfDescription} onChange={e=>setVrfDescription(e.target.value)} placeholder="ISP-1 routing domain"/></label><div className="nat-form-actions"><button className="btn primary" onClick={saveVrf}>{editingVrf?'Save VRF':'Create VRF'}</button>{editingVrf&&<button className="btn secondary" onClick={clearVrf}>Cancel</button>}</div></div>
      <div className="vrf-list">{(vrfs?.config.vrfs??[]).map(v=>{const rt=vrfs?.runtime.find(x=>x.name===v.name);return <div className="vrf-row" key={v.id}><span className={`pill ${rt?'green':'warning'}`}>{rt?'LIVE':'WAITING'}</span><div><strong>{v.name}</strong><small>table {v.table} · {v.interfaces.join(', ')||'no interfaces'}</small></div><span>{v.description||'—'}</span><div className="nat-actions"><button className="btn secondary" onClick={()=>editVrf(v)}>Edit</button><button className="btn secondary" onClick={async()=>{await updateVrf(v.id,{enabled:!v.enabled});await load()}}>{v.enabled?'Disable':'Enable'}</button><button className="icon-danger" onClick={async()=>{if(window.confirm(`Delete VRF ${v.name}?`)){await removeVrf(v.id);await load()}}}><Trash2 size={15}/></button></div></div>})}{!vrfs?.config.vrfs.length&&<Empty text="No DRM managed VRFs"/>}</div>
    </div>
    <div className="panel"><PanelTitle title={editingId?'Edit static route':'Add static route'} subtitle="Routes can be installed in main or a DRM VRF routing table"/><div className="route-builder route-builder-dual"><label><span>Family</span><div className="family-switch"><button type="button" className={family===4?'family-option active':'family-option'} onClick={()=>setFamily(4)}>IPv4</button><button type="button" className={family===6?'family-option active ipv6':'family-option'} onClick={()=>setFamily(6)}>IPv6</button></div></label><label><span>VRF table</span><select value={routeVrf} onChange={e=>setRouteVrf(e.target.value)}><option value="">main</option>{(vrfs?.config.vrfs??[]).filter(v=>v.enabled).map(v=><option key={v.id} value={v.table}>{v.name} · table {v.table}</option>)}</select></label><label><span>Destination</span><input value={destination} onChange={e=>setDestination(e.target.value)} placeholder={family===4?'0.0.0.0/0':'::/0'}/></label><label><span>Gateway</span><input value={gateway} onChange={e=>setGateway(e.target.value)}/></label><label><span>Interface</span><input value={dev} onChange={e=>setDev(e.target.value)} placeholder="vlan100 / eth0"/></label><label><span>Metric</span><input value={metric} onChange={e=>setMetric(e.target.value.replace(/\D/g,''))}/></label><button className="btn primary" onClick={save}>{editingId?'Save route':'Add route'}</button>{editingId&&<button className="btn secondary" onClick={clearForm}>Cancel</button>}</div></div>
    <div className="table-panel"><div className="route-table-head route-table-dual"><span>Family</span><span>Destination</span><span>Gateway</span><span>Interface</span><span>Protocol</span><span>Metric</span></div>{(status?.routes??[]).map((r:any,i)=><div className="route-table-row route-table-dual" key={`${r.family}-${i}`}><span className={r.family===6?'pill ipv6-pill':'pill blue'}>IPv{r.family}</span><code>{r.dst||'default'}</code><code>{r.gateway||'direct'}</code><span>{r.dev||'—'}</span><span>{r.protocol||r.type||'kernel'}</span><span>{r.metric??'—'}</span></div>)}</div>
    <div className="panel"><PanelTitle title="DRM managed routes" subtitle="VRF routes show their dedicated table"/>{(status?.managedRoutes??[]).map(r=><div className="managed-route managed-route-dual" key={r.id}><span className={r.family===6?'pill ipv6-pill':'pill blue'}>IPv{r.family}</span><code>{r.destination}</code><span>{r.table?`table ${r.table} · `:''}via {r.gateway||'direct'} dev {r.dev||'auto'} metric {r.metric??'—'}</span><div className="managed-route-actions"><button className="btn secondary small" onClick={()=>editRoute(r)}>Edit</button><button className="icon-danger" onClick={async()=>{await removeRoute(r.id);await load()}}><Trash2 size={15}/></button></div></div>)}{!status?.managedRoutes.length&&<Empty text="No DRM managed routes"/>}</div>
  </div>
}

function autoWgIpv6Gateway(ipv4Cidr:string){
  const ip=ipv4Cidr.split('/')[0];
  const o=ip.split('.').map(Number);
  if(o.length!==4 || o.some(x=>!Number.isInteger(x)||x<0||x>255)) return 'fd42:8::1/64';
  const a=o[1].toString(16), b=o[2].toString(16);
  return b==='0'?`fd42:${a}::1/64`:`fd42:${a}:${b}::1/64`;
}
function autoWgIpv6Client(gateway:string,peerIndex=0){
  const base=gateway.split('/')[0];
  const host=Math.max(2,peerIndex+2).toString(16);
  if(base.endsWith('::1')) return `${base.slice(0,-1)}${host}/128`;
  const pos=base.lastIndexOf(':');
  return pos>=0?`${base.slice(0,pos+1)}${host}/128`:'fd42:8::2/128';
}
function wgIpv4ToUint(ip:string){
  const parts=ip.split('.').map(Number);
  if(parts.length!==4||parts.some(x=>!Number.isInteger(x)||x<0||x>255))return null;
  return (((parts[0]<<24)>>>0)+((parts[1]<<16)>>>0)+((parts[2]<<8)>>>0)+parts[3])>>>0;
}
function wgUintToIpv4(value:number){return [value>>>24,(value>>>16)&255,(value>>>8)&255,value&255].join('.')}
function autoWgIpv4Client(gatewayCidr:string,peers:Array<{clientAddress?:string|null}>){
  const [gatewayIp,prefixRaw]=gatewayCidr.trim().split('/');
  const gateway=wgIpv4ToUint(gatewayIp),prefix=Number(prefixRaw??24);
  if(gateway===null||!Number.isInteger(prefix)||prefix<0||prefix>30)return '';
  const mask=prefix===0?0:((0xffffffff<<(32-prefix))>>>0),network=(gateway&mask)>>>0,broadcast=(network|(~mask>>>0))>>>0;
  const used=new Set<number>([gateway]);
  for(const peer of peers){const ip=wgIpv4ToUint(String(peer.clientAddress??'').split('/')[0]);if(ip!==null)used.add(ip)}
  for(let value=(network+1)>>>0;value<broadcast;value=(value+1)>>>0){if(!used.has(value))return `${wgUintToIpv4(value)}/32`;if(value===0xffffffff)break}
  return '';
}

function WireGuardPage({topology}:{topology:Topology|null}){
  const [status,setStatus]=useState<WireGuardStatus|null>(null);
  const [error,setError]=useState('');
  const [name,setName]=useState('wg0');
  const [address,setAddress]=useState('10.8.0.1/24');
  const [ipv6Enabled,setIpv6Enabled]=useState(false);
  const [ipv6Address,setIpv6Address]=useState('');
  const [listenPort,setListenPort]=useState('51820');
  const [interfaceMtu,setInterfaceMtu]=useState('1420');
  const [editingInterfaceName,setEditingInterfaceName]=useState('');
  const [selected,setSelected]=useState('');
  const [peerName,setPeerName]=useState('Laptop');
  const [clientAddress,setClientAddress]=useState('10.8.0.2/32');
  const [clientIpv6Address,setClientIpv6Address]=useState('');
  const [endpointHost,setEndpointHost]=useState(()=>window.location.hostname);
  const [endpointPort,setEndpointPort]=useState('');
  const [endpointHostTouched,setEndpointHostTouched]=useState(false);
  const [endpointPortTouched,setEndpointPortTouched]=useState(false);
  const [serverAllowed,setServerAllowed]=useState('10.8.0.2/32');
  const [peerMode,setPeerMode]=useState<"remote-access"|"site-to-site">("remote-access");
  const [remoteNetworks,setRemoteNetworks]=useState('');
  const [editingPeerId,setEditingPeerId]=useState('');
  const [showCreateInterface,setShowCreateInterface]=useState(false);
  const [showPeerAccess,setShowPeerAccess]=useState(false);

  const [clientAllowed,setClientAllowed]=useState('');
  const [dns,setDns]=useState('');
  const [keepalive,setKeepalive]=useState('25');
  const [config,setConfig]=useState('');
  const [configName,setConfigName]=useState('wireguard-client');
  const [qrSvg,setQrSvg]=useState('');
  const [accessDockerCidrs,setAccessDockerCidrs]=useState<string[]>([]);
  const [accessLanCidrs,setAccessLanCidrs]=useState('');
  const [accessInternet,setAccessInternet]=useState(false);
  const [accessNat,setAccessNat]=useState(true);
  const [accessWan,setAccessWan]=useState('');
  const [accessEnabled,setAccessEnabled]=useState(false);
  const [accessInternet6,setAccessInternet6]=useState(false);
  const [accessNat66,setAccessNat66]=useState(false);
  const [accessWan6,setAccessWan6]=useState('');
  const [selectedIpv6Gateway,setSelectedIpv6Gateway]=useState('');


  async function load(){
    try{
      const x=await getWireGuard();
      setStatus(x);
      setSelected(prev=>{
        if(prev && x.interfaces?.some((i:any)=>i.name===prev)) return prev;
        const saved=localStorage.getItem("drm-wireguard-selected-interface") || "";
        if(saved && x.interfaces?.some((i:any)=>i.name===saved)) return saved;
        return x.interfaces?.[0]?.name || "";
      });
      setError('');
    }catch(e){setError(e instanceof Error?e.message:String(e))}
  }
  useEffect(()=>{load();const t=window.setInterval(load,2000);return()=>window.clearInterval(t)},[]);
  useEffect(()=>{if(selected)localStorage.setItem("drm-wireguard-selected-interface",selected)},[selected]);
  const dockerRoutes=(topology?.networks??[]).flatMap(n=>n.subnets.map(s=>s.subnet).filter(Boolean) as string[]);
  useEffect(()=>{
    if(ipv6Enabled) setIpv6Address(prev=>prev||autoWgIpv6Gateway(address));
    else setIpv6Address('');
  },[ipv6Enabled]);
  useEffect(()=>{
    if(ipv6Enabled) setIpv6Address(autoWgIpv6Gateway(address));
  },[address]);
  const iface=status?.interfaces.find(i=>i.name===selected);
  useEffect(()=>{if(!iface)return;const p=iface.accessPolicy;setAccessEnabled(Boolean(p?.enabled));setAccessDockerCidrs(p?.dockerCidrs??[]);setAccessLanCidrs((p?.lanCidrs??[]).join(', '));setAccessInternet(Boolean(p?.internet));setAccessNat(Boolean(p?.nat));setAccessWan(p?.wanInterface||status?.defaultWanInterface||'');setAccessInternet6(Boolean(p?.internet6));setAccessNat66(Boolean(p?.nat66));setAccessWan6(p?.wanInterface6||status?.defaultWanInterface6||status?.defaultWanInterface||'');},[selected,iface?.name]);
  useEffect(()=>{if(iface)setSelectedIpv6Gateway(iface.ipv6Address||autoWgIpv6Gateway(iface.address||'10.8.0.1/24'));},[iface?.name,iface?.ipv6Address,iface?.address]);
  useEffect(()=>{
    if(!iface||editingPeerId)return;
    const nextV4=autoWgIpv4Client(iface.address||'10.8.0.1/24',iface.peers);
    if(nextV4){
      setClientAddress(nextV4);
      const ipv6Allowed=serverAllowed.split(',').map(x=>x.trim()).filter(x=>x&&x.includes(':'));
      setServerAllowed([nextV4,...ipv6Allowed].join(', '));
    }
  },[iface?.name,iface?.address,iface?.peers.length,editingPeerId]);
  useEffect(()=>{
    if(!iface)return;
    if(iface.ipv6Address){
      const nextV6=autoWgIpv6Client(iface.ipv6Address,iface.peers.length);
      setClientIpv6Address(nextV6);
      const currentServer=serverAllowed.split(',').map(x=>x.trim()).filter(Boolean).filter(x=>!x.includes(':'));
      setServerAllowed([...currentServer,nextV6].join(', '));
      if(!clientAllowed.trim()) setClientAllowed('0.0.0.0/0, ::/0');
    }else{
      setClientIpv6Address('');
      setServerAllowed(prev=>prev.split(',').map(x=>x.trim()).filter(x=>x&&!x.includes(':')).join(', '));
    }
  },[iface?.name,iface?.ipv6Address,iface?.peers.length]);


  useEffect(()=>{
    if(!endpointHostTouched) setEndpointHost(window.location.hostname);
    if(iface && !endpointPortTouched) setEndpointPort(String(iface.listenPort));
  },[iface?.name,iface?.listenPort,endpointHostTouched,endpointPortTouched]);

  function openAddInterface(){
    setEditingInterfaceName('');
    setName('wg0');
    setAddress('10.8.0.1/24');
    setIpv6Enabled(false);
    setIpv6Address('');
    setListenPort('51820');
    setInterfaceMtu('1420');
    setShowCreateInterface(true);
  }
  function openEditInterface(i:any){
    setEditingInterfaceName(i.name);
    setName(i.name);
    setAddress(i.address||'10.8.0.1/24');
    setIpv6Enabled(Boolean(i.ipv6Address));
    setIpv6Address(i.ipv6Address||autoWgIpv6Gateway(i.address||'10.8.0.1/24'));
    setListenPort(String(i.listenPort||51820));
    setInterfaceMtu(String(i.mtu||1420));
    setShowCreateInterface(true);
  }
  function closeInterfaceForm(){
    setShowCreateInterface(false);
    setEditingInterfaceName('');
  }
  async function createIface(){
    try{
      const body={name,address:address.trim()||undefined,ipv6Enabled,ipv6Address:ipv6Enabled?(ipv6Address.trim()||autoWgIpv6Gateway(address)):undefined,listenPort:Number(listenPort),mtu:Number(interfaceMtu||1420)};
      if(editingInterfaceName) await updateWgInterface(editingInterfaceName,body);
      else await createWgInterface(body);
      closeInterfaceForm();
      await load();
    }catch(e){setError(e instanceof Error?e.message:String(e))}
  }
  async function addPeer(){try{
    await createWgPeer(selected,{name:peerName,mode:peerMode,clientAddress:clientAddress.trim()||undefined,clientIpv6Address:clientIpv6Address.trim()||undefined,remoteNetworks:remoteNetworks.split(',').map(x=>x.trim()).filter(Boolean),endpointHost:endpointHost.trim(),endpointPort:Number(endpointPort),serverAllowedIps:serverAllowed.split(',').map(x=>x.trim()).filter(Boolean),clientAllowedIps:clientAllowed.split(',').map(x=>x.trim()).filter(Boolean),dns:dns.trim()||undefined,persistentKeepalive:Number(keepalive||0)});
    setQrSvg('');setConfig('');await load();
  }catch(e){setError(e instanceof Error?e.message:String(e))}}

  function openNewPeer(){
    if(!iface)return;
    setEditingPeerId('');setPeerName('Laptop');setPeerMode('remote-access');setRemoteNetworks('');
    const nextV4=autoWgIpv4Client(iface.address||'10.8.0.1/24',iface.peers);setClientAddress(nextV4);
    const nextV6=iface.ipv6Address?autoWgIpv6Client(iface.ipv6Address,iface.peers.length):'';setClientIpv6Address(nextV6);
    setServerAllowed([nextV4,nextV6].filter(Boolean).join(', '));
    setShowPeerAccess(true);
  }
  function editPeer(peer:any){
    setShowPeerAccess(true);
    setEditingPeerId(peer.id);setPeerName(peer.name);setPeerMode(peer.mode||'remote-access');setClientAddress(peer.clientAddress||'');setClientIpv6Address(peer.clientIpv6Address||'');setRemoteNetworks((peer.remoteNetworks||[]).join(', '));setServerAllowed((peer.serverAllowedIps||[]).join(', '));setClientAllowed((peer.clientAllowedIps||[]).join(', '));setEndpointHost(peer.endpointHost||'');setEndpointPort(peer.endpointPort?String(peer.endpointPort):'');setDns(peer.dns||'');setKeepalive(String(peer.persistentKeepalive||0));
  }
  function cancelEdit(){setEditingPeerId('');setPeerName('Laptop');setPeerMode('remote-access');setRemoteNetworks('');}
  async function savePeer(){if(!editingPeerId)return;try{await updateWgPeer(selected,editingPeerId,{name:peerName,mode:peerMode,clientAddress:clientAddress.trim()||null,clientIpv6Address:clientIpv6Address.trim()||null,remoteNetworks:remoteNetworks.split(',').map(x=>x.trim()).filter(Boolean),serverAllowedIps:serverAllowed.split(',').map(x=>x.trim()).filter(Boolean),clientAllowedIps:clientAllowed.split(',').map(x=>x.trim()).filter(Boolean),endpointHost:endpointHost.trim(),endpointPort:endpointPort?Number(endpointPort):null,dns:dns.trim(),persistentKeepalive:Number(keepalive||0)});setEditingPeerId('');await load();}catch(e){setError(e instanceof Error?e.message:String(e))}}
  async function togglePeer(peer:any){try{await setWgPeerEnabled(selected,peer.id,!peer.enabled);await load();}catch(e){setError(e instanceof Error?e.message:String(e))}}

  async function openConfig(peer:{id:string;name:string}){
    try{setConfig(await getWgClientConfig(selected,peer.id));setConfigName(peer.name||'wireguard-client');setQrSvg('')}
    catch(e){setError(e instanceof Error?e.message:String(e))}
  }
  function downloadConfig(){
    if(!config)return;
    const blob=new Blob([config],{type:'text/plain;charset=utf-8'});
    const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`${configName.replace(/[^a-zA-Z0-9_.-]+/g,'-')}.conf`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  }
  async function showQr(peer:{id:string;name:string}){
    try{setConfig(await getWgClientConfig(selected,peer.id));setConfigName(peer.name||'wireguard-client');setQrSvg(await getWgClientQr(selected,peer.id))}
    catch(e){setError(e instanceof Error?e.message:String(e))}
  }

  async function toggleSelectedIpv6(enabled:boolean){if(!iface)return;try{await setWgIpv6(iface.name,{enabled,ipv6Address:enabled?(selectedIpv6Gateway||autoWgIpv6Gateway(iface.address)):undefined});if(enabled){setAccessInternet6(accessInternet);if(accessInternet)setAccessNat66(true);setClientAllowed(prev=>prev.includes('0.0.0.0/0')&&!prev.includes('::/0')?`${prev}, ::/0`:prev)}await load();}catch(e){setError(e instanceof Error?e.message:String(e))}}

  async function saveAccessPolicy(){if(!iface)return;try{await setWgAccessPolicy(iface.name,{enabled:accessEnabled,dockerCidrs:accessDockerCidrs,lanCidrs:accessLanCidrs.split(',').map(x=>x.trim()).filter(Boolean),internet:accessInternet,nat:accessInternet&&accessNat,wanInterface:accessWan||status?.defaultWanInterface||undefined,internet6:accessInternet6,nat66:accessInternet6&&accessNat66,wanInterface6:accessWan6||status?.defaultWanInterface6||status?.defaultWanInterface||undefined});await load();}catch(e){setError(e instanceof Error?e.message:String(e))}}

  async function deleteInterface(ifaceName:string){
    if(!window.confirm(`Delete WireGuard interface ${ifaceName}?\n\nAll DRM-managed peers for this interface will also be removed.`)) return;
    try{
      await removeWgInterface(ifaceName);
      setConfig('');
      setQrSvg('');
      localStorage.removeItem("drm-wireguard-selected-interface");
      setSelected('');
      await load();
    }catch(e){setError(e instanceof Error?e.message:String(e))}
  }

  return <div className="firewall-stack">
    {error&&<div className="error-banner"><KeyRound size={18}/><div><strong>WireGuard error</strong><span>{error}</span></div></div>}
    {showCreateInterface&&<div className="panel wg-create-interface-panel"><div className="wg-panel-action-head"><PanelTitle title={editingInterfaceName?"Edit WireGuard interface":"Create WireGuard interface"} subtitle="Native Linux WireGuard with optional IPv6 dual-stack"/><button className="btn secondary" onClick={closeInterfaceForm}>Close</button></div><div className="route-builder wg-interface-builder wg-interface-builder-dual"><label><span>Name</span><input disabled={Boolean(editingInterfaceName)} value={name} onChange={e=>setName(e.target.value)}/></label><label><span>IPv4 gateway</span><input value={address} onChange={e=>setAddress(e.target.value)} placeholder="10.8.0.1/24"/></label><label className="wg-ipv6-toggle"><span>IPv6</span><div className="wg-ipv6-check"><input type="checkbox" checked={ipv6Enabled} onChange={e=>setIpv6Enabled(e.target.checked)}/><strong>Enable IPv6</strong></div></label>{ipv6Enabled&&<label><span>IPv6 gateway</span><input value={ipv6Address} onChange={e=>setIpv6Address(e.target.value)} placeholder="fd42:8::1/64"/></label>}<label><span>Listen port</span><input value={listenPort} onChange={e=>setListenPort(e.target.value.replace(/\D/g,''))}/></label><label><span>MTU</span><input value={interfaceMtu} onChange={e=>setInterfaceMtu(e.target.value.replace(/\D/g,''))} placeholder="1420"/></label><button className="btn primary" onClick={createIface}>{editingInterfaceName?"Save interface":"Create interface"}</button></div></div>}
    <div className="wg-layout"><div className="panel"><PanelTitle title="Interfaces" subtitle="Configured by DRM"/>{(status?.interfaces??[]).map(i=>
      <div className={selected===i.name?'wg-interface-card active':'wg-interface-card'} key={i.name}>
        <button className="wg-interface-select" onClick={()=>{setSelected(i.name);setEndpointPortTouched(false);setConfig('');setQrSvg('')}}>
          <div><strong>{i.name}</strong><span>{[i.address,i.ipv6Address].filter(Boolean).join(' · ')} · UDP {i.listenPort}</span></div><code>{i.peers.length} peers</code>
        </button>
        <button className="wg-interface-edit" title={`Edit ${i.name}`} onClick={()=>openEditInterface(i)}><Pencil size={15}/></button>
        <button className="wg-interface-delete" title={`Delete ${i.name}`} onClick={()=>deleteInterface(i.name)}><Trash2 size={15}/></button>
      </div>
    )}{!status?.interfaces.length&&<Empty text="No WireGuard interfaces"/>}<button className="btn primary wg-add-interface-bottom" onClick={openAddInterface}><Plus size={15}/> Add WireGuard interface</button></div>
    <div className="panel"><div className="wg-panel-action-head"><PanelTitle title={iface?`${iface.name} peers`:'Peers'} subtitle={iface?`Public key: ${iface.publicKey}`:'Select an interface'}/>{iface&&<button className="btn primary" onClick={openNewPeer}>Add peer and Routing & Access Policy</button>}</div>{iface&&<>
      <div className="wg-peer-list-top">
        <div className="wg-section-heading"><div><strong>Configured peers</strong><span>{iface.peers.length} peer{iface.peers.length===1?"":"s"} on {iface.name}</span></div></div>
        {iface.peers.length===0&&<Empty text="No peers configured on this interface"/>}
{iface.peers.map(peer=>{
        const rt=peer.runtime;
        return <div className="wg-peer-row wg-peer-runtime-row" key={peer.id}>
          <div className="wg-peer-main">
            <div className="wg-peer-title">
              <strong>{peer.name}</strong>
              <span className={`wg-peer-mode ${peer.mode==="site-to-site"?"site":"remote"}`}>{peer.mode==="site-to-site"?"SITE-TO-SITE":"REMOTE"}</span>
              <span className={`wg-status ${peer.enabled?rt.status:"disabled"}`}>{peer.enabled?(rt.status==="active"?"ACTIVE":rt.status==="idle"?"IDLE":"NEVER"):"DISABLED"}</span>
            </div>
            <span>{[peer.clientAddress,peer.clientIpv6Address].filter(Boolean).join(' · ')||'—'} · server AllowedIPs {peer.serverAllowedIps.join(', ')}</span>
            {peer.mode==="site-to-site"&&<small>Remote networks: {peer.remoteNetworks?.join(', ')||'—'}</small>}
            {peer.dns&&<small>DNS: {peer.dns}</small>}
            <div className="wg-runtime-grid">
              <div><small>Remote endpoint</small><code>{rt.endpoint||"—"}</code></div>
              <div><small>Remote IP</small><code>{rt.remoteIp||"—"}</code></div>
              <div><small>Latest handshake</small><code>{formatHandshakeAge(rt.handshakeAgeSeconds,rt.status)}</code></div>
              <div><small>Transfer</small><code>↓ {formatBytes(rt.rxBytes)} · ↑ {formatBytes(rt.txBytes)}</code></div>
            </div>
          </div>
          <div className="wg-peer-actions"><button className="btn secondary" onClick={()=>editPeer(peer)}>Edit</button><button className="btn secondary" onClick={()=>togglePeer(peer)}>{peer.enabled?'Disable':'Enable'}</button><button className="btn secondary" disabled={!peer.enabled} onClick={()=>openConfig(peer)}>Client config</button><button className="btn secondary" disabled={!peer.enabled} onClick={()=>showQr(peer)}><QrCode size={14}/> QR</button><button className="icon-danger" onClick={async()=>{await removeWgPeer(iface.name,peer.id);await load()}}><Trash2 size={15}/></button></div>
        </div>
      })}
      </div>

      {showPeerAccess&&<><div className="wg-settings-toggle-head"><strong>Peer & Routing settings</strong><button className="btn secondary" onClick={()=>{setShowPeerAccess(false);cancelEdit()}}>Close</button></div><div className="wg-settings-grid">
        <div className="wg-settings-card">
          <div className="wg-section-heading"><div><strong>{editingPeerId?"Edit peer":"Add peer"}</strong><span>Tunnel identity, endpoint and client routing</span></div></div>
          <div className="wg-peer-builder wg-peer-builder-v2">
        <label><span>Peer type</span><select value={peerMode} onChange={e=>setPeerMode(e.target.value as any)}><option value="remote-access">Remote Access</option><option value="site-to-site">Site-to-Site</option></select></label>
        <label><span>Name</span><input value={peerName} onChange={e=>setPeerName(e.target.value)}/></label>
        <label><span>Client address</span><input value={clientAddress} onChange={e=>setClientAddress(e.target.value)}/></label>
        {iface.ipv6Address&&<label><span>Client IPv6 address</span><input value={clientIpv6Address} onChange={e=>{setClientIpv6Address(e.target.value);const v4=serverAllowed.split(',').map(x=>x.trim()).filter(x=>x&&!x.includes(':'));setServerAllowed([...v4,e.target.value].filter(Boolean).join(', '))}} placeholder="fd42:8::2/128"/><small className="field-hint">Next address is generated automatically.</small></label>}
        {peerMode==="site-to-site"&&<label><span>Remote networks</span><input value={remoteNetworks} onChange={e=>setRemoteNetworks(e.target.value)} placeholder="192.168.50.0/24, fd50::/64"/><small className="field-hint">DRM adds these to Server AllowedIPs, routes them via this peer and includes them in Docker access policy.</small></label>}
        <label><span>Endpoint address</span><input value={endpointHost} onChange={e=>{setEndpointHostTouched(true);setEndpointHost(e.target.value)}} placeholder="vpn.example.com"/></label>
        <label><span>Endpoint port</span><input value={endpointPort} onChange={e=>{setEndpointPortTouched(true);setEndpointPort(e.target.value.replace(/\D/g,''))}} placeholder={String(iface.listenPort)}/></label>
        <label><span>DNS</span><input value={dns} onChange={e=>setDns(e.target.value)} placeholder="1.1.1.1, 8.8.8.8"/></label>
        <label><span>Server AllowedIPs</span><input disabled={peerMode==="site-to-site"} value={peerMode==="site-to-site"?[clientAddress,clientIpv6Address,remoteNetworks].filter(Boolean).join(', '):serverAllowed} onChange={e=>setServerAllowed(e.target.value)} placeholder="10.8.0.2/32, fd42:8::2/128"/><small className="field-hint">{peerMode==="site-to-site"?'Generated from tunnel addresses + Remote Networks.':'Cryptokey routing / inbound source validation.'}</small></label>
        <label><span>Client routes</span><input value={clientAllowed} onChange={e=>setClientAllowed(e.target.value)} placeholder="172.20.0.0/16, fd00:20::/64, 192.168.150.0/24"/></label>
        <label><span>Keepalive</span><input value={keepalive} onChange={e=>setKeepalive(e.target.value.replace(/\D/g,''))}/></label>
        {editingPeerId?<><button className="btn primary" onClick={savePeer}>Save peer</button><button className="btn secondary" onClick={cancelEdit}>Cancel</button></>:<button className="btn primary" onClick={addPeer}>Add peer</button>}
      </div>
          <div className="wg-presets"><span>Client route presets:</span><button onClick={()=>setClientAllowed(dockerRoutes.join(', '))}>Docker networks</button><button onClick={()=>setClientAllowed('0.0.0.0/0')}>IPv4 full tunnel</button>{iface.ipv6Address&&<button onClick={()=>setClientAllowed('0.0.0.0/0, ::/0')}>Dual-stack full tunnel</button>}<button onClick={()=>setClientAllowed('')}>Clear</button></div>
        </div>

        <div className="wg-settings-card">
      <div className="wg-access-panel">
        <div className="wg-access-head"><div><strong>Routing & Access Policy</strong><span>Allow this WireGuard network to selected Docker/LAN networks and optionally the Internet.</span></div><label className="wg-access-toggle"><input type="checkbox" checked={accessEnabled} onChange={e=>setAccessEnabled(e.target.checked)}/> Enabled</label></div>
        <div className="wg-access-grid">
          <div className="wg-access-section"><span className="section-label">DOCKER NETWORKS · IPv4 / IPv6</span>{(topology?.networks??[]).filter(n=>n.driver==="bridge").map(n=>{const cidrs=n.subnets.map(x=>x.subnet).filter((x):x is string=>Boolean(x));if(!cidrs.length)return null;const checked=cidrs.every(c=>accessDockerCidrs.includes(c));return <label className="wg-network-check" key={n.id}><input type="checkbox" checked={checked} onChange={e=>setAccessDockerCidrs(prev=>e.target.checked?[...new Set([...prev,...cidrs])]:prev.filter(c=>!cidrs.includes(c)))}/><span><strong>{n.name}</strong><small>{cidrs.map(c=>`${c.includes(':')?'IPv6':'IPv4'} ${c}`).join(" · ")}</small></span></label>})}</div>
          <div className="wg-access-section"><label><span>LAN / custom CIDRs · IPv4 / IPv6</span><input value={accessLanCidrs} onChange={e=>setAccessLanCidrs(e.target.value)} placeholder="192.168.150.0/24, fd42:150::/64"/></label><span className="section-label">IPv4 INTERNET</span><label className="wg-network-check"><input type="checkbox" checked={accessInternet} onChange={e=>{setAccessInternet(e.target.checked);if(e.target.checked&&iface?.ipv6Address){setAccessInternet6(true);setAccessNat66(true)}}}/><span><strong>IPv4 Internet access</strong><small>Forward 0.0.0.0/0 traffic to WAN</small></span></label><label className="wg-network-check"><input type="checkbox" disabled={!accessInternet} checked={accessNat} onChange={e=>setAccessNat(e.target.checked)}/><span><strong>IPv4 NAT / MASQUERADE</strong><small>Usually required when upstream has no route to the VPN subnet</small></span></label><label><span>IPv4 WAN interface</span><select value={accessWan} onChange={e=>setAccessWan(e.target.value)}><option value="">Select WAN</option>{(status?.hostInterfaces??[]).map(x=><option key={x} value={x}>{x}{x===status?.defaultWanInterface?" · default IPv4":""}</option>)}</select></label><span className="section-label">IPv6 INTERNET {iface.ipv6Address?"· ENABLED":"· DISABLED"}</span><label className="wg-network-check"><input type="checkbox" disabled={!iface.ipv6Address} checked={Boolean(iface.ipv6Address)&&accessInternet6} onChange={e=>{setAccessInternet6(e.target.checked);if(e.target.checked)setAccessNat66(true)}}/><span><strong>IPv6 Internet access</strong><small>Forward ::/0 traffic to IPv6 WAN</small></span></label><label className="wg-network-check"><input type="checkbox" disabled={!accessInternet6} checked={accessNat66} onChange={e=>setAccessNat66(e.target.checked)}/><span><strong>NAT66 / MASQUERADE</strong><small>Optional. Prefer routed IPv6 when upstream routing is available.</small></span></label><label><span>IPv6 WAN interface</span><select value={accessWan6} onChange={e=>setAccessWan6(e.target.value)}><option value="">Select IPv6 WAN</option>{(status?.hostInterfaces??[]).map(x=><option key={x} value={x}>{x}{x===status?.defaultWanInterface6?" · default IPv6":""}</option>)}</select></label></div>
        </div>
        <div className="wg-access-footer"><span>Client AllowedIPs must include selected networks. Use <code>0.0.0.0/0</code> for IPv4 full tunnel and <code>::/0</code> for IPv6.</span><button className="btn primary" onClick={saveAccessPolicy}>Apply access policy</button></div>
      </div>
        </div>
      </div></>}

</>}</div></div>
    {config&&<div className="panel"><div className="wg-panel-action-head"><PanelTitle title="Generated client configuration" subtitle="Private key is sensitive; download and QR are available only to Operator/Administrator"/><button className="btn secondary" onClick={()=>{setConfig('');setQrSvg('')}}>Close</button></div><pre className="wg-config">{config}</pre><div className="wg-config-actions"><button className="btn secondary" onClick={()=>navigator.clipboard.writeText(config)}>Copy config</button><button className="btn primary" onClick={downloadConfig}><Download size={14}/> Download .conf</button>{qrSvg&&<button className="btn secondary" onClick={()=>setQrSvg('')}>Hide QR</button>}</div>{qrSvg&&<div className="wg-qr"><div dangerouslySetInnerHTML={{__html:qrSvg}}/><span>Scan with the WireGuard mobile app</span></div>}</div>}
  </div>
}

const topologyStorageKey="drm-topology-positions-v1";
function loadTopologyPositions():Record<string,{x:number;y:number}>{try{return JSON.parse(localStorage.getItem(topologyStorageKey)||"{}");}catch{return {};}}
function saveTopologyPosition(id:string,position:{x:number;y:number}){const p=loadTopologyPositions();p[id]=position;localStorage.setItem(topologyStorageKey,JSON.stringify(p));}

function TopologyView({data,firewall}:{data:Topology|null;firewall:FirewallStatus|null}) {
  const [mode,setMode]=useState<"current"|"routing">(()=>localStorage.getItem("drm-topology-mode")==="routing"?"routing":"current");
  const [routingStatus,setRoutingStatus]=useState<RoutingStatus|null>(null);
  const [natStatus,setNatStatus]=useState<NatStatus|null>(null);
  const [interfacesStatus,setInterfacesStatus]=useState<HostInterfaceManagementStatus|null>(null);
  const [wireguardStatus,setWireguardStatus]=useState<WireGuardStatus|null>(null);
  const [mapError,setMapError]=useState("");

  const currentBuilt=useMemo(()=>buildFlow(data,firewall),[data,firewall]);
  const routingBuilt=useMemo(
    ()=>buildRoutingMap(data,firewall,routingStatus,natStatus,interfacesStatus,wireguardStatus),
    [data,firewall,routingStatus,natStatus,interfacesStatus,wireguardStatus]
  );
  const built=mode==="current"?currentBuilt:routingBuilt;
  const [nodes,setNodes,onNodesChange]=useNodesState(built.nodes);
  const [topologyUnlocked,setTopologyUnlocked]=useState(()=>localStorage.getItem("drm-topology-unlocked")==="1");

  async function loadRoutingMap(){
    try{
      const [routing,nat,interfaces,wireguard]=await Promise.all([
        getRoutingStatus(),getNatStatus(),getHostInterfacesStatus(),getWireGuard()
      ]);
      setRoutingStatus(routing);setNatStatus(nat);setInterfacesStatus(interfaces);setWireguardStatus(wireguard);setMapError("");
    }catch(e){setMapError(e instanceof Error?e.message:String(e))}
  }

  useEffect(()=>{localStorage.setItem("drm-topology-mode",mode);if(mode==="routing")void loadRoutingMap()},[mode]);
  useEffect(()=>{
    if(mode!=="routing")return;
    const timer=window.setInterval(loadRoutingMap,10000);
    return()=>window.clearInterval(timer);
  },[mode]);

  useEffect(()=>{
    const current=new Map(nodes.map(n=>[n.id,n]));
    setNodes(built.nodes.map(n=>current.get(n.id)?{...n,position:current.get(n.id)!.position}:n));
  },[built.nodes,mode]);
  useEffect(()=>{localStorage.setItem("drm-topology-unlocked",topologyUnlocked?"1":"0")},[topologyUnlocked]);

  return <div className="topology-shell">
    <div className="topology-toolbar topology-toolbar-dual">
      <div>
        <strong>{mode==="current"?"Live network topology":"Interactive routing map"}</strong>
        <span>{mode==="current"
          ?"Existing Docker topology is unchanged. Switch to Routing map for host interfaces, VLANs, routes, NAT and Firewall paths."
          :"Physical/VLAN interfaces → Docker networks → containers, plus WAN, routing, NAT, WireGuard and Firewall relationships."}</span>
      </div>
      <div className="topology-mode-switch" role="group" aria-label="Topology mode">
        <button className={mode==="current"?"active":""} onClick={()=>setMode("current")}><GitBranch size={15}/>Current topology</button>
        <button className={mode==="routing"?"active":""} onClick={()=>setMode("routing")}><Waypoints size={15}/>Routing map</button>
      </div>
      <details className="topology-legend-details">
        <summary>Legend</summary>
        <div className="legend topology-legend">
          {mode==="current"?<>
            <span><i className="legend-network"/> Network</span>
            <span><i className="legend-container"/> Container</span>
            <span><i className="legend-port"/> Published port</span>
            <span><i className="legend-allow"/> Allowed path</span>
            <span><i className="legend-block"/> Blocked path</span>
          </>:<>
            <span><i className="legend-interface"/> Interface / VLAN</span>
            <span><i className="legend-network"/> Docker network</span>
            <span><i className="legend-container"/> Container</span>
            <span><i className="legend-route"/> Route</span>
            <span><i className="legend-nat"/> NAT</span>
            <span><i className="legend-allow"/> Firewall allow</span>
            <span><i className="legend-block"/> Firewall drop</span>
          </>}
        </div>
      </details>
    </div>
    {mode==="routing"&&mapError&&<div className="error-banner"><AlertTriangle size={18}/><div><strong>Routing map data error</strong><span>{mapError}</span></div></div>}
    <div className="flow">
      <ReactFlow
        nodes={nodes}
        edges={built.edges}
        onNodesChange={onNodesChange}
        onNodeDragStop={(_e,node)=>saveTopologyPosition(node.id,node.position)}
        fitView
        minZoom={0.08}
        maxZoom={1.8}
        nodesDraggable={topologyUnlocked}
        nodesConnectable={false}
        elementsSelectable={true}
        panOnDrag={true}
        selectionOnDrag={false}
        zoomOnDoubleClick={false}
      >
        <Background gap={22} size={1}/>
        <Controls onInteractiveChange={(interactive)=>setTopologyUnlocked(interactive)}/>
      </ReactFlow>
    </div>
    <div className="topology-footnote"><span>{topologyUnlocked ? "Layout unlocked · drag nodes to arrange them" : "Layout locked · open the padlock to move nodes"} · drag empty space to move the canvas · positions are saved</span></div>
  </div>;
}

function routingMapNode(id:string,fallback:{x:number;y:number},saved:Record<string,{x:number;y:number}>,label:React.ReactNode,kind:"wan"|"interface"|"vlan"|"network"|"container"|"wireguard"|"route"|"nat"|"firewall"|"external"):Node{
  const palette:Record<string,{border:string;background:string}>={
    wan:{border:"#6a4f2f",background:"#1d1710"},interface:{border:"#31506e",background:"#101a26"},
    vlan:{border:"#4a3970",background:"#171225"},network:{border:"#26344c",background:"#111927"},
    container:{border:"#243149",background:"#0d1420"},wireguard:{border:"#285b55",background:"#0d1c1b"},
    route:{border:"#5e5732",background:"#1a190f"},nat:{border:"#65404f",background:"#1d1218"},
    firewall:{border:"#4f5731",background:"#171a10"},external:{border:"#5a445f",background:"#18121a"}
  };
  const p=palette[kind];
  return {id,position:saved[id]??fallback,selectable:true,data:{label},style:{width:300,borderRadius:12,border:`1px solid ${p.border}`,background:p.background,color:"#e9f0fb",padding:4}};
}

function ipv4ToInt(ip:string){
  const parts=ip.split(".").map(Number);
  if(parts.length!==4||parts.some(x=>!Number.isInteger(x)||x<0||x>255))return null;
  return (((parts[0]<<24)>>>0)+((parts[1]<<16)>>>0)+((parts[2]<<8)>>>0)+parts[3])>>>0;
}
function ipv4InCidr(ip:string,cidr:string){
  const plain=ip.split("/")[0];
  const [base,prefixRaw]=cidr.split("/");
  const value=ipv4ToInt(plain),network=ipv4ToInt(base),prefix=Number(prefixRaw??32);
  if(value===null||network===null||!Number.isInteger(prefix)||prefix<0||prefix>32)return false;
  if(prefix===0)return true;
  const mask=(0xffffffff << (32-prefix))>>>0;
  return (value&mask)===(network&mask);
}
function normalizeCidr(value:string,family:4|6=4){
  if(!value||value==="default")return family===4?"0.0.0.0/0":"::/0";
  if(value.includes("/"))return value;
  return family===4&&value.includes(".")?`${value}/32`:family===6&&value.includes(":")?`${value}/128`:value;
}
function plainIp(value:string|null|undefined){return String(value??"").split("/")[0].split(":").slice(0,1).join(":");}

function buildRoutingMap(data:Topology|null,firewall:FirewallStatus|null,routing:RoutingStatus|null,nat:NatStatus|null,interfaces:HostInterfaceManagementStatus|null,wireguard:WireGuardStatus|null):{nodes:Node[];edges:Edge[]}{
  if(!data)return{nodes:[],edges:[]};
  const nodes:Node[]=[];const edges:Edge[]=[];const saved=loadTopologyPositions();const nodeIds=new Set<string>();
  const pushNode=(node:Node)=>{if(!nodeIds.has(node.id)){nodes.push(node);nodeIds.add(node.id)}};
  const addEdge=(edge:Edge)=>{if(!edges.some(e=>e.id===edge.id))edges.push(edge)};

  const networks=[...data.networks].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));
  const containers=[...data.containers].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));
  const topologyContainerByName=new Map(containers.map(c=>[c.name,c]));

  // Build a host-interface inventory from three independent runtime sources.
  const ifaceMap=new Map<string,{name:string;kind:string;state:string;up:boolean;mac:string|null;mtu:number|null;ipv4:string[];vlanId:number|null;parent:string|null}>();
  for(const i of interfaces?.interfaces??[]){
    ifaceMap.set(i.name,{name:i.name,kind:i.kind||"physical",state:i.state||"UNKNOWN",up:i.up,mac:i.mac??null,mtu:i.mtu??null,ipv4:i.ipv4??[],vlanId:i.vlanId??null,parent:i.parent??null});
  }
  for(const i of nat?.hostInterfaces??[]){
    if(!ifaceMap.has(i.name))ifaceMap.set(i.name,{name:i.name,kind:"physical",state:i.state||"UNKNOWN",up:i.state==="UP",mac:null,mtu:null,ipv4:i.addresses??[],vlanId:null,parent:null});
    else{
      const row=ifaceMap.get(i.name)!;
      if(!row.ipv4.length)row.ipv4=i.addresses??[];
    }
  }
  const routeAddressRows=routing?.addresses??[];
  for(const row of routeAddressRows){
    const name=String(row.ifname??"");
    if(!name||name==="lo"||name.startsWith("docker")||name.startsWith("br-")||name.startsWith("veth"))continue;
    const ipv4=(row.addr_info??[]).filter((a:any)=>a.family==="inet").map((a:any)=>`${a.local}/${a.prefixlen}`);
    if(!ifaceMap.has(name))ifaceMap.set(name,{name,kind:"physical",state:row.operstate??"UNKNOWN",up:(row.flags??[]).includes("UP"),mac:row.address??null,mtu:row.mtu??null,ipv4,vlanId:null,parent:null});
    else if(!ifaceMap.get(name)!.ipv4.length)ifaceMap.get(name)!.ipv4=ipv4;
  }

  const runtimeRoutes4=(routing?.routes4??[]) as any[];
  const defaultRoutes=runtimeRoutes4.filter(r=>r.dst==="default"||!r.dst);
  const wanNames=new Set<string>([
    nat?.defaultWanInterface??"",
    wireguard?.defaultWanInterface??"",
    ...defaultRoutes.map(r=>String(r.dev??"")),
    ...(nat?.config.rules??[]).flatMap((r:any)=>r.type==="dnat"?[r.inInterface]:[r.outInterface])
  ].filter(Boolean));

  const physical=[...ifaceMap.values()].filter(i=>i.kind!=="vlan"&&!i.name.startsWith("wg"));
  physical.forEach((iface,index)=>{
    const isWan=wanNames.has(iface.name),id=`rmap-if-${iface.name}`;
    pushNode(routingMapNode(id,{x:40,y:70+index*145},saved,<div className="flow-node">
      <div className={`flow-node-icon ${isWan?"external":"network"}`}>{isWan?<Wifi size={18}/>:<Cable size={18}/>}</div>
      <div><strong>{iface.name}{isWan?" · WAN":""}</strong><span>{iface.ipv4.join(" · ")||"No IPv4"}</span><small>{iface.state}{iface.mac?` · ${iface.mac}`:""}</small></div>
    </div>,isWan?"wan":"interface"));
  });

  const vlanRows=[...ifaceMap.values()].filter(i=>i.kind==="vlan");
  vlanRows.forEach((iface,index)=>{
    const id=`rmap-if-${iface.name}`;
    pushNode(routingMapNode(id,{x:380,y:70+index*145},saved,<div className="flow-node">
      <div className="flow-node-icon network"><Network size={18}/></div>
      <div><strong>{iface.name}</strong><span>VLAN {iface.vlanId??"?"}{iface.parent?` · parent ${iface.parent}`:""}</span><small>{iface.ipv4.join(" · ")||"No IPv4"}</small></div>
    </div>,"vlan"));
    if(iface.parent&&nodeIds.has(`rmap-if-${iface.parent}`))addEdge({
      id:`rmap-parent-${iface.parent}-${iface.name}`,source:`rmap-if-${iface.parent}`,target:id,
      markerEnd:{type:MarkerType.ArrowClosed,color:"#8b6ad9"},label:`802.1Q ${iface.vlanId??""}`,
      labelStyle:{fill:"#b9a3ff",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
      style:{stroke:"#8b6ad9",strokeWidth:2}
    });
  });

  // WAN/Internet anchor guarantees that default routes and DNAT always have a visible endpoint.
  const internetId="rmap-internet";
  pushNode(routingMapNode(internetId,{x:40,y:850},saved,<div className="flow-node">
    <div className="flow-node-icon external"><Wifi size={18}/></div>
    <div><strong>Internet / Default</strong><span>0.0.0.0/0</span><small>External routing domain</small></div>
  </div>,"external"));

  // Docker networks.
  networks.forEach((network,index)=>{
    const id=`rmap-net-${network.id}`;
    pushNode(routingMapNode(id,{x:1100,y:60+index*145},saved,<div className="flow-node">
      <div className="flow-node-icon network"><Network size={18}/></div>
      <div><strong>{network.name}</strong><span>{network.subnets.map(x=>x.subnet).filter(Boolean).join(" · ")||network.driver}</span><small>{network.driver}{network.parent?` · parent ${network.parent}`:""}</small></div>
    </div>,"network"));

    // Prefer explicit Docker parent. If Docker reports a VLAN ID separately, resolve parent.vlan as fallback.
    let parentName=network.parent||"";
    if(parentName&&!nodeIds.has(`rmap-if-${parentName}`)){
      const possibleVlan=vlanRows.find(v=>v.name===parentName||(`${v.parent}.${v.vlanId}`===parentName));
      if(possibleVlan)parentName=possibleVlan.name;
    }
    if(parentName&&nodeIds.has(`rmap-if-${parentName}`))addEdge({
      id:`rmap-net-parent-${network.id}`,source:`rmap-if-${parentName}`,target:id,
      markerEnd:{type:MarkerType.ArrowClosed,color:"#4d8dff"},label:network.driver,
      labelStyle:{fill:"#76a7ff",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
      style:{stroke:"#4d8dff",strokeWidth:1.8}
    });
  });

  // Containers.
  containers.forEach((container,index)=>{
    const id=`rmap-ctr-${container.id}`;
    pushNode(routingMapNode(id,{x:1460,y:50+index*125},saved,<div className="flow-node">
      <div className="flow-node-icon container"><Container size={17}/></div>
      <div><strong>{container.name}</strong><span>{containerAddressSummary(container)}</span><small>{portSummary(container)}</small></div>
    </div>,"container"));
    container.networks.forEach(net=>{
      if(net.networkId&&nodeIds.has(`rmap-net-${net.networkId}`))addEdge({
        id:`rmap-attach-${net.networkId}-${container.id}`,source:`rmap-net-${net.networkId}`,target:id,
        markerEnd:{type:MarkerType.ArrowClosed,color:"#38577f"},style:{stroke:"#38577f",strokeWidth:1.4}
      });
    });
  });

  // WireGuard nodes.
  (wireguard?.interfaces??[]).forEach((wg,index)=>{
    const id=`rmap-wg-${wg.name}`;
    pushNode(routingMapNode(id,{x:380,y:720+index*145},saved,<div className="flow-node">
      <div className="flow-node-icon container"><KeyRound size={17}/></div>
      <div><strong>{wg.name}</strong><span>{[wg.address,wg.ipv6Address].filter(Boolean).join(" · ")}</span><small>{wg.peers.length} peers</small></div>
    </div>,"wireguard"));
  });

  function endpointForCidr(cidr:string,preferContainer=false){
    const normalized=normalizeCidr(cidr,4);
    if(normalized==="0.0.0.0/0")return internetId;

    // Exact Docker subnet first.
    const exactNet=networks.find(n=>n.subnets.some(sn=>normalizeCidr(sn.subnet||"",4)===normalized));
    if(exactNet)return `rmap-net-${exactNet.id}`;

    // Host interface IP contained in destination subnet.
    const iface=[...ifaceMap.values()].find(i=>i.ipv4.some(addr=>ipv4InCidr(addr.split("/")[0],normalized)));
    if(iface&&nodeIds.has(`rmap-if-${iface.name}`))return `rmap-if-${iface.name}`;

    // Container exact IP / containment.
    const ctr=containers.find(c=>c.networks.some(n=>{
      const ip=(n.ipv4Address??"").split("/")[0];
      return ip&&(normalized.endsWith("/32")?ip===normalized.split("/")[0]:ipv4InCidr(ip,normalized));
    }));
    if(ctr&&(preferContainer||normalized.endsWith("/32")))return `rmap-ctr-${ctr.id}`;

    return "";
  }

  // ACTUAL runtime IPv4 routes, not just routes created inside DRM.
  runtimeRoutes4.forEach((route:any,index)=>{
    const destination=normalizeCidr(String(route.dst??"default"),4);
    const routeId=`rmap-runtime-route-${index}-${route.dev??"none"}-${destination}`;
    const dev=String(route.dev??"");
    const sourceId=nodeIds.has(`rmap-if-${dev}`)?`rmap-if-${dev}`:nodeIds.has(`rmap-wg-${dev}`)?`rmap-wg-${dev}`:"";
    let targetId=endpointForCidr(destination);
    if(!targetId){
      targetId=`rmap-route-dst-${index}-${destination}`;
      pushNode(routingMapNode(targetId,{x:760,y:720+index*105},saved,<div className="flow-node">
        <div className="flow-node-icon network"><Waypoints size={17}/></div>
        <div><strong>{destination}</strong><span>{route.gateway?`via ${route.gateway}`:"direct"}</span><small>{dev||"kernel"}{route.metric!=null?` · metric ${route.metric}`:""}</small></div>
      </div>,"route"));
    }
    if(sourceId)addEdge({
      id:routeId,source:sourceId,target:targetId,animated:destination==="0.0.0.0/0",
      markerEnd:{type:MarkerType.ArrowClosed,color:"#d1b94e"},
      label:`ROUTE${route.gateway?` via ${route.gateway}`:""}`,
      labelStyle:{fill:"#e6d26f",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.94},
      style:{stroke:"#d1b94e",strokeWidth:2,strokeDasharray:"5 4"}
    });
  });

  // Explicit managed route nodes are still shown when they are currently waiting/not in runtime.
  (routing?.managedRoutes??[]).filter((r:any)=>r.enabled!==false).forEach((route:any,index)=>{
    const exists=runtimeRoutes4.some((rr:any)=>normalizeCidr(String(rr.dst??"default"),4)===normalizeCidr(route.destination,4)&&String(rr.dev??"")===String(route.dev??""));
    if(exists)return;
    const id=`rmap-managed-route-${route.id}`;
    pushNode(routingMapNode(id,{x:760,y:1180+index*100},saved,<div className="flow-node">
      <div className="flow-node-icon network"><Waypoints size={17}/></div>
      <div><strong>{route.destination}</strong><span>{route.gateway?`via ${route.gateway}`:"direct"}</span><small>managed · waiting/runtime mismatch</small></div>
    </div>,"route"));
    const src=nodeIds.has(`rmap-if-${route.dev}`)?`rmap-if-${route.dev}`:nodeIds.has(`rmap-wg-${route.dev}`)?`rmap-wg-${route.dev}`:"";
    if(src)addEdge({id:`rmap-managed-route-edge-${route.id}`,source:src,target:id,markerEnd:{type:MarkerType.ArrowClosed,color:"#d1b94e"},style:{stroke:"#d1b94e",strokeWidth:1.8,strokeDasharray:"3 5"}});
  });

  // Site-to-site WireGuard remote networks.
  (wireguard?.interfaces??[]).forEach((wg,wgIndex)=>wg.peers.filter(p=>p.enabled!==false).forEach((peer,peerIndex)=>(peer.remoteNetworks??[]).forEach((remote,remoteIndex)=>{
    const rid=`rmap-wg-remote-${wg.name}-${peer.id}-${remoteIndex}`;
    pushNode(routingMapNode(rid,{x:760,y:1430+wgIndex*190+peerIndex*95+remoteIndex*70},saved,<div className="flow-node">
      <div className="flow-node-icon network"><Route size={17}/></div>
      <div><strong>{remote}</strong><span>{peer.name}</span><small>via {wg.name}</small></div>
    </div>,"route"));
    addEdge({id:`rmap-wg-edge-${wg.name}-${peer.id}-${remoteIndex}`,source:`rmap-wg-${wg.name}`,target:rid,animated:true,
      markerEnd:{type:MarkerType.ArrowClosed,color:"#44b8a7"},label:"WG route",
      labelStyle:{fill:"#72d7c8",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.94},
      style:{stroke:"#44b8a7",strokeWidth:2}});
  })));

  // DRM NAT config rules as first-class nodes.
  (nat?.config.rules??[]).filter((r:any)=>r.enabled).forEach((rule:any,index)=>{
    const runtime=nat?.runtime?.[rule.id];
    const id=`rmap-nat-${rule.id}`;
    const title=rule.type==="dnat"
      ? `${rule.externalIp==="0.0.0.0"?"*":rule.externalIp}:${rule.externalPort}/${rule.protocol}`
      : rule.type.toUpperCase();
    const detail=rule.type==="dnat"
      ? `→ ${runtime?.destination?.[0]??"waiting"}:${rule.internalPort}`
      : `${runtime?.source?.join(", ")||"waiting"} → ${rule.outInterface}`;
    pushNode(routingMapNode(id,{x:760,y:60+index*135},saved,<div className="flow-node">
      <div className="flow-node-icon port"><Route size={17}/></div>
      <div><strong>{rule.type.toUpperCase()}</strong><span>{title}</span><small>{detail}</small></div>
    </div>,"nat"));

    if(rule.type==="dnat"){
      const src=nodeIds.has(`rmap-if-${rule.inInterface}`)?`rmap-if-${rule.inInterface}`:internetId;
      addEdge({id:`rmap-dnat-in-${rule.id}`,source:src,target:id,animated:true,markerEnd:{type:MarkerType.ArrowClosed,color:"#d66d9c"},label:"DNAT",labelStyle:{fill:"#f08ab8",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.94},style:{stroke:"#d66d9c",strokeWidth:2.4}});
      const destIp=(runtime?.destination?.[0]??"").split("/")[0];
      const ctr=containers.find(c=>c.networks.some(n=>(n.ipv4Address??"").split("/")[0]===destIp));
      const dst=ctr?`rmap-ctr-${ctr.id}`:endpointForCidr(destIp?`${destIp}/32`:"");
      if(dst)addEdge({id:`rmap-dnat-out-${rule.id}`,source:id,target:dst,animated:true,markerEnd:{type:MarkerType.ArrowClosed,color:"#d66d9c"},label:`:${rule.internalPort}`,labelStyle:{fill:"#f08ab8",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.94},style:{stroke:"#d66d9c",strokeWidth:2.4}});
    }else{
      const sources=runtime?.source??[];
      let src="";
      for(const cidr of sources){src=endpointForCidr(cidr);if(src)break}
      const dst=nodeIds.has(`rmap-if-${rule.outInterface}`)?`rmap-if-${rule.outInterface}`:internetId;
      if(src)addEdge({id:`rmap-snat-in-${rule.id}`,source:src,target:id,animated:true,markerEnd:{type:MarkerType.ArrowClosed,color:"#d66d9c"},label:rule.type.toUpperCase(),labelStyle:{fill:"#f08ab8",fontSize:9,fontWeight:700},labelBgStyle:{fill:"#0a1019",fillOpacity:.94},style:{stroke:"#d66d9c",strokeWidth:2.4}});
      addEdge({id:`rmap-snat-out-${rule.id}`,source:id,target:dst,animated:true,markerEnd:{type:MarkerType.ArrowClosed,color:"#d66d9c"},style:{stroke:"#d66d9c",strokeWidth:2.4}});
    }
  });

  // Runtime NAT rules not represented by DRM config (Docker/system DNAT/SNAT/MASQUERADE).
  const representedTargets=new Set((nat?.config.rules??[]).map((r:any)=>r.id));
  (nat?.allNatRules??[]).filter(rule=>["DNAT","SNAT","MASQUERADE"].includes(rule.target)).slice(0,80).forEach((rule,index)=>{
    // Avoid duplicating the obvious DRM managed entries; the DRM nodes above are richer.
    if(rule.owner==="DRM")return;
    const id=`rmap-runtime-nat-${rule.id}`;
    const translation=rule.toDestination||rule.toSource||rule.target;
    pushNode(routingMapNode(id,{x:760,y:520+index*90},saved,<div className="flow-node">
      <div className="flow-node-icon port"><Route size={16}/></div>
      <div><strong>{rule.owner} · {rule.target}</strong><span>{rule.chain} #{rule.position}</span><small>{translation}{rule.destinationPort?` · dport ${rule.destinationPort}`:""}</small></div>
    </div>,"nat"));

    let src=rule.inInterface&&nodeIds.has(`rmap-if-${rule.inInterface}`)?`rmap-if-${rule.inInterface}`:"";
    if(!src&&rule.source&&rule.source!=="0.0.0.0/0")src=endpointForCidr(normalizeCidr(rule.source,4));
    if(!src&&rule.target==="DNAT")src=internetId;

    let dst="";
    if(rule.toDestination){
      const ip=rule.toDestination.replace(/^\[/,"").split("]")[0].split(":")[0];
      dst=endpointForCidr(ip?`${ip}/32`:"",true);
    }
    if(!dst&&rule.outInterface&&nodeIds.has(`rmap-if-${rule.outInterface}`))dst=`rmap-if-${rule.outInterface}`;
    if(!dst&&["SNAT","MASQUERADE"].includes(rule.target))dst=internetId;

    if(src)addEdge({id:`rmap-runtime-nat-in-${rule.id}`,source:src,target:id,markerEnd:{type:MarkerType.ArrowClosed,color:"#b95d8a"},style:{stroke:"#b95d8a",strokeWidth:1.5,strokeDasharray:"4 3"}});
    if(dst)addEdge({id:`rmap-runtime-nat-out-${rule.id}`,source:id,target:dst,markerEnd:{type:MarkerType.ArrowClosed,color:"#b95d8a"},style:{stroke:"#b95d8a",strokeWidth:1.5,strokeDasharray:"4 3"}});
  });

  // DRM Firewall config rules are explicit nodes: source -> FW -> destination.
  let fwIndex=0;
  const pushFirewallPath=(id:string,label:string,action:string,protocol:string,sourceId:string,destinationId:string,detail:string)=>{
    if(!sourceId&&!destinationId)return;
    const blocked=action==="DROP"||action==="REJECT";
    const color=blocked?"#ff5b68":"#32d296";
    const fwId=`rmap-fw-node-${id}`;
    pushNode(routingMapNode(fwId,{x:1100,y:850+fwIndex*105},saved,<div className="flow-node">
      <div className={`flow-node-icon port ${blocked?"blocked":""}`}><Shield size={16}/></div>
      <div><strong>{label}</strong><span>{action} · {protocol}</span><small>{detail}</small></div>
    </div>,"firewall"));
    fwIndex+=1;
    if(sourceId)addEdge({id:`rmap-fw-in-${id}`,source:sourceId,target:fwId,markerEnd:{type:MarkerType.ArrowClosed,color},style:{stroke:color,strokeWidth:1.8,strokeDasharray:blocked?"6 4":undefined}});
    if(destinationId)addEdge({id:`rmap-fw-out-${id}`,source:fwId,target:destinationId,markerEnd:{type:MarkerType.ArrowClosed,color},style:{stroke:color,strokeWidth:1.8,strokeDasharray:blocked?"6 4":undefined}});
  };

  (firewall?.config.rules??[]).filter(r=>r.enabled).forEach(rule=>{
    const src=nodeIds.has(`rmap-net-${rule.sourceNetworkId}`)?`rmap-net-${rule.sourceNetworkId}`:"";
    const dst=nodeIds.has(`rmap-net-${rule.destinationNetworkId}`)?`rmap-net-${rule.destinationNetworkId}`:"";
    pushFirewallPath(rule.id,"DRM Network Firewall",rule.action,`${rule.protocol.toUpperCase()} ${rule.destinationPort??"ANY"}`,src,dst,rule.description||"Network policy");
  });

  (firewall?.config.accessRules??[]).filter(r=>r.enabled).forEach(rule=>{
    const resolved=firewall?.accessRuleResolution?.[rule.id];
    const sourceCidr=resolved?.source?.[0]??"";
    const destCidr=resolved?.destination?.[0]??"";
    const src=sourceCidr?endpointForCidr(sourceCidr,true):"";
    const dst=destCidr?endpointForCidr(destCidr,true):"";
    pushFirewallPath(rule.id,"DRM Container Access",rule.action,`${rule.protocol.toUpperCase()} ${rule.destinationPort??"ANY"}`,src,dst,rule.description||`${sourceCidr||"?"} → ${destCidr||"?"}`);
  });

  // Runtime filter rules: show resolvable ACCEPT/DROP/REJECT rules, including Docker/System.
  (firewall?.allFirewallRules??[])
    .filter(rule=>["ACCEPT","DROP","REJECT"].includes(rule.target))
    .filter(rule=>rule.chain==="INPUT"||rule.chain==="FORWARD"||rule.chain==="DOCKER-USER"||rule.chain.startsWith("DOCKER")||rule.chain.startsWith("DRM"))
    .slice(0,100)
    .forEach(rule=>{
      if(rule.owner==="DRM")return; // richer DRM config paths are already above.
      let src="";
      let dst="";
      if(rule.source&&rule.source!=="0.0.0.0/0")src=endpointForCidr(normalizeCidr(rule.source,4),true);
      if(!src&&rule.inInterface&&nodeIds.has(`rmap-if-${rule.inInterface}`))src=`rmap-if-${rule.inInterface}`;
      if(!src&&rule.chain==="INPUT")src=internetId;

      if(rule.destination&&rule.destination!=="0.0.0.0/0")dst=endpointForCidr(normalizeCidr(rule.destination,4),true);
      if(!dst&&rule.outInterface&&nodeIds.has(`rmap-if-${rule.outInterface}`))dst=`rmap-if-${rule.outInterface}`;
      if(!dst&&rule.chain==="INPUT"){
        const wan=[...wanNames][0];
        if(wan&&nodeIds.has(`rmap-if-${wan}`))dst=`rmap-if-${wan}`;
      }
      if(!src&&!dst)return;
      pushFirewallPath(`runtime-${rule.id}`,`${rule.owner} Firewall`,rule.target,`${rule.protocol.toUpperCase()} ${rule.destinationPort??"ANY"}`,src,dst,`${rule.chain} #${rule.position}${rule.state?` · ${rule.state}`:""}`);
    });

  return{nodes,edges};
}

function buildFlow(data:Topology|null, firewall:FirewallStatus|null):{nodes:Node[];edges:Edge[]} {
  if(!data)return{nodes:[],edges:[]};

  const nodes:Node[]=[];
  const edges:Edge[]=[];
  const saved=loadTopologyPositions();
  const pos=(id:string,fallback:{x:number;y:number})=>saved[id] ?? fallback;
  const stableNetworks=[...data.networks].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));
  const stableContainers=[...data.containers].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));

  const publishedRules=firewall?.config.publishedPortRules ?? [];

  // Internet node.
  nodes.push({
    id:"external-internet",
    position:pos("external-internet",{x:40,y:80}),
    selectable:true,
    data:{label:<div className="flow-node external-node">
      <div className="flow-node-icon external"><Wifi size={18}/></div>
      <div><strong>External / Internet</strong><span>Inbound traffic</span></div>
    </div>},
    style:{
      width:260,borderRadius:12,border:"1px solid #34445e",
      background:"#101724",color:"#e9f0fb",padding:4
    }
  });

  // Docker network nodes.
  stableNetworks.forEach((network,index)=>{
    const y=80+index*210;
    nodes.push({
      id:`net-${network.id}`,
      position:pos(`net-${network.id}`,{x:1320,y}),
      selectable:true,
      data:{label:<div className="flow-node">
        <div className="flow-node-icon network"><Network size={18}/></div>
        <div><strong>{network.name}</strong><span>{network.subnets[0]?.subnet || network.driver}</span></div>
      </div>},
      style:{
        width:270,borderRadius:12,border:"1px solid #26344c",
        background:"#111927",color:"#e9f0fb",padding:4
      }
    });
  });

  // Container nodes.
  stableContainers.forEach((container,index)=>{
    const y=50+index*150;
    nodes.push({
      id:`ctr-${container.id}`,
      position:pos(`ctr-${container.id}`,{x:880,y}),
      selectable:true,
      data:{label:<div className="flow-node">
        <div className="flow-node-icon container"><Container size={17}/></div>
        <div><strong>{container.name}</strong>
          <span>{containerAddressSummary(container)}</span>
          <small>{portSummary(container)}</small>
        </div>
      </div>},
      style:{
        width:310,borderRadius:12,border:"1px solid #243149",
        background:"#0d1420",color:"#e9f0fb",padding:4
      }
    });

    // Network attachment edges.
    container.networks.forEach(net=>{
      if(!net.networkId)return;
      edges.push({
        id:`attach-${net.networkId}-${container.id}`,
        source:`ctr-${container.id}`,
        target:`net-${net.networkId}`,
        animated:false,
        markerEnd:{type:MarkerType.ArrowClosed},
        style:{stroke:"#38577f",strokeWidth:1.5}
      });
    });
  });

  // Published port nodes and Internet -> port -> container paths.
  let publishedIndex=0;
  for(const container of stableContainers){
    for(const port of container.ports){
      for(const binding of port.published){
        const matching=publishedRules.filter(r=>r.enabled&&r.containerId===container.id&&r.protocol===port.protocol&&r.publishedPort===binding.hostPort&&r.containerPort===port.port&&(r.hostIp===binding.hostIp||(!r.hostIp&&!binding.hostIp)));
        const blocks=matching.filter(r=>r.action==="DROP"||r.action==="REJECT");
        const accepts=matching.filter(r=>r.action==="ACCEPT");
        const fullBlock=blocks.some(r=>r.sourceCidr==="0.0.0.0/0");
        const restricted=!fullBlock && (blocks.length>0 || (accepts.length>0 && !accepts.some(r=>r.sourceCidr==="0.0.0.0/0")));
        const isExplicitAccept=!fullBlock&&!restricted&&accepts.some(r=>r.sourceCidr==="0.0.0.0/0");
        const isBlocked=fullBlock;
        const color=isBlocked ? "#ff5b68" : restricted ? "#ffb84d" : isExplicitAccept ? "#32d296" : "#4d8dff";
        const stateLabel=isBlocked ? "BLOCKED" : restricted ? "RESTRICTED" : isExplicitAccept ? "ALLOW" : "OPEN";

        const portNodeId=`pub-${container.id}-${binding.hostIp}-${binding.hostPort}-${port.protocol}-${port.port}-${publishedIndex}`;
        const y=60+publishedIndex*115;

        nodes.push({
          id:portNodeId,
          position:pos(portNodeId,{x:460,y}),
              selectable:true,
          data:{label:<div className="flow-node port-node">
            <div className={isBlocked ? "flow-node-icon port blocked" : restricted ? "flow-node-icon port restricted" : "flow-node-icon port"}>
              <Plug size={17}/>
            </div>
            <div>
              <strong>{binding.hostIp || "0.0.0.0"}:{binding.hostPort}/{port.protocol}</strong>
              <span>→ {container.name}:{port.port}</span>
              <small className={isBlocked ? "blocked-text" : ""}>{stateLabel}</small>
            </div>
          </div>},
          style:{
            width:300,borderRadius:12,
            border:`1px solid ${isBlocked ? "#67313a" : restricted ? "#634d2d" : "#2a3d5a"}`,
            background:isBlocked ? "#1b1115" : restricted ? "#1c1810" : "#101825",
            color:"#e9f0fb",padding:4
          }
        });

        edges.push({
          id:`internet-${portNodeId}`,
          source:"external-internet",
          target:portNodeId,
          animated:!isBlocked && !restricted,
          markerEnd:{type:MarkerType.ArrowClosed,color},
          label:`${binding.hostIp || "0.0.0.0"}:${binding.hostPort}/${port.protocol}`,
          labelStyle:{fill:color,fontSize:9,fontWeight:700},
          labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
          style:{stroke:color,strokeWidth:isBlocked?2.8:2,strokeDasharray:restricted?"7 4":undefined}
        });

        edges.push({
          id:`port-container-${portNodeId}`,
          source:portNodeId,
          target:`ctr-${container.id}`,
          animated:!isBlocked && !restricted,
          markerEnd:{type:MarkerType.ArrowClosed,color},
          label:`${port.port}/${port.protocol}`,
          labelStyle:{fill:color,fontSize:9,fontWeight:700},
          labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
          style:{stroke:color,strokeWidth:isBlocked?2.8:2,strokeDasharray:restricted?"7 4":undefined}
        });

        publishedIndex+=1;
      }
    }
  }

  // Network-to-network firewall policy edges.
  const networkById=new Map(stableNetworks.map(n=>[n.id,n]));
  (firewall?.config.rules ?? []).filter(r=>r.enabled).forEach((rule,index)=>{
    if(!networkById.has(rule.sourceNetworkId) || !networkById.has(rule.destinationNetworkId))return;

    const isBlocked=rule.action==="DROP" || rule.action==="REJECT";
    const color=isBlocked ? "#ff5b68" : "#32d296";
    edges.push({
      id:`fw-net-${rule.id}`,
      source:`net-${rule.sourceNetworkId}`,
      target:`net-${rule.destinationNetworkId}`,
      animated:!isBlocked,
      markerEnd:{type:MarkerType.ArrowClosed,color},
      label:`${rule.protocol.toUpperCase()} ${rule.destinationPort ?? "ANY"} · ${rule.action}`,
      labelStyle:{fill:color,fontSize:9,fontWeight:700},
      labelBgStyle:{fill:"#0a1019",fillOpacity:.94},
      style:{stroke:color,strokeWidth:2.2,strokeDasharray:isBlocked?"6 4":undefined}
    });
  });

  return{nodes,edges};
}

function formatHandshakeAge(seconds:number|null,status:"active"|"idle"|"never"){
  if(status==="never" || seconds===null) return "Never";
  if(seconds<60) return `${seconds}s ago`;
  if(seconds<3600) return `${Math.floor(seconds/60)}m ${seconds%60}s ago`;
  if(seconds<86400) return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m ago`;
  return `${Math.floor(seconds/86400)}d ago`;
}

function formatBytes(value:number){if(value<1024)return `${value.toFixed(0)} B`;if(value<1024*1024)return `${(value/1024).toFixed(1)} KB`;if(value<1024*1024*1024)return `${(value/(1024*1024)).toFixed(1)} MB`;return `${(value/(1024*1024*1024)).toFixed(2)} GB`;}
function formatRate(value:number){return `${formatBytes(value)}/s`;}

function portSummary(c:DockerContainer) {
  if(!c.ports.length)return "No exposed ports";
  return c.ports.slice(0,4).map(p=>{
    const pub=p.published[0];
    return pub ? `${pub.hostPort}→${p.containerPort}` : p.containerPort;
  }).join(" · ") + (c.ports.length>4 ? ` +${c.ports.length-4}` : "");
}
function formatHostIp(ip:string){ return !ip || ip==="0.0.0.0" ? "0.0.0.0" : ip==="::" ? "[::]" : ip; }
function NetworkRow({network}:{network:DockerNetwork}) { return <div className="network-row">
  <div className="network-symbol small"><Wifi size={16}/></div><div className="grow"><strong>{network.name}</strong><span>{network.driver} · {network.scope}</span></div>
  <div className="right-meta"><code>{network.subnets[0]?.subnet || "—"}</code><span>{network.containers.length} endpoints</span></div></div>; }
function PanelTitle({title,subtitle}:{title:string;subtitle:string}) { return <div className="panel-title"><div><h2>{title}</h2><span>{subtitle}</span></div></div>; }
function Metric({label,value}:{label:string;value:string}) { return <div className="metric"><span>{label}</span><strong>{value}</strong></div>; }
function Empty({text}:{text:string}) { return <div className="empty"><Server size={22}/><span>{text}</span></div>; }
export default AuthenticatedApp;
