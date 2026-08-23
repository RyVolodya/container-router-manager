import { useEffect, useMemo, useState } from "react";
import {
  Activity, Boxes, Container, GitBranch, LayoutDashboard, Network,
  RefreshCw, Route, Search, Server, Shield, Wifi, CircleDot, Plug, Trash2, KeyRound, Waypoints, Plus, UserCog, LogOut, Moon, Sun, Download, QrCode, X, CheckCircle2, AlertTriangle, Info, ChevronLeft, ChevronRight
} from "lucide-react";
import { Background, Controls, Edge, MarkerType, Node, ReactFlow, useNodesState } from "@xyflow/react";
import { getUpdateStatus,  addManagementUser, changeManagementRole, changePassword, createFirewallRule, createHostInputRule, createPublishedPortRule, createAccessRule, updateAccessRule, removeAccessRule, reorderAccessRules, firewallAction, getFirewallStatus, getMe, getNetworkStats, getTopology, listManagementUsers, login, logout, removeFirewallRule, removeHostInputRule, removeManagementUser, removePublishedPortRule, resetManagementPassword, createRoute, createWgInterface, createWgPeer, getRoutingStatus, getWgClientConfig, getWgClientQr, getWireGuard, removeRoute, updateRoute, removeWgInterface, removeWgPeer, setRoutingForward, setRoutingForward6, setWgAccessPolicy, setWgIpv6, updateWgPeer, setWgPeerEnabled } from "./api";
import type { DockerContainer, DockerNetwork, FirewallStatus, NetworkStatsResponse, RoutingStatus, Topology, WireGuardStatus } from "./types";

type Page = "dashboard" | "networks" | "containers" | "ports" | "topology" | "firewall" | "routing" | "wireguard" | "management";

type AuthUser = {id:string;username:string;role:"administrator"|"operator"|"viewer";mustChangePassword:boolean;createdAt:string;updatedAt:string;lastLoginAt:string|null;disabled:boolean};

const navigation = [
  { id: "dashboard" as Page, label: "Dashboard", icon: LayoutDashboard },
  { id: "networks" as Page, label: "Networks", icon: Network },
  { id: "containers" as Page, label: "Containers", icon: Container },
  { id: "ports" as Page, label: "Ports", icon: Plug },
  { id: "topology" as Page, label: "Topology", icon: GitBranch },
  { id: "firewall" as Page, label: "Firewall", icon: Shield },
  { id: "routing" as Page, label: "Routing", icon: Waypoints },
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
          <div className="brand-text"><strong>Docker Router</strong><span>Manager</span></div>
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
          <div className="version">DRM v0.10.12</div>
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
        {page === "networks" && <Networks networks={filteredNetworks}/>}
        {page === "containers" && <Containers containers={filteredContainers}/>}
        {page === "ports" && <Ports containers={filteredContainers} firewall={firewallStatus}/>}
        {page === "topology" && <TopologyView data={data} firewall={firewallStatus}/>}
        {page === "firewall" && <FirewallEngine/>}
        {page === "routing" && <RoutingPage/>}
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
    <div className="auth-brand"><div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div><div><strong>Docker Router Manager</strong><span>Secure management access</span></div></div>
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

function Networks({networks}:{networks:DockerNetwork[]}) {
  return <section className="cards">{networks.map(network=>
    <article className="network-card" key={network.id}>
      <div className="network-card-head"><div className="network-symbol"><Network size={20}/></div>
        <div className="grow"><strong>{network.name}</strong><span>{network.id.slice(0,12)}</span></div>
        <span className="pill blue">{network.driver}</span></div>
      <div className="network-details">
        <Metric label="Subnets" value={network.subnets.map(x=>x.subnet).filter(Boolean).join(" · ") || "—"}/>
        <Metric label="Gateways" value={network.subnets.map(x=>x.gateway).filter(Boolean).join(" · ") || "—"}/>
        <Metric label="Containers" value={String(network.containers.length)}/>
        <Metric label="Scope" value={network.scope}/>
      </div>
      <div className="endpoint-block"><span className="section-label">ATTACHED ENDPOINTS</span>
        {network.containers.length ? network.containers.map(e=>
          <div className="endpoint" key={e.id}><span className="status-dot"/><strong>{e.name}</strong><code>{networkEndpointAddress(e.ipv4Address,e.ipv6Address)}</code></div>)
        : <span className="muted">No attached containers</span>}
      </div>
    </article>)}
    {!networks.length && <Empty text="No matching networks"/>}
  </section>;
}

function Containers({containers}:{containers:DockerContainer[]}) {
  return <div className="table-panel">
    <div className="table-head ports-aware dual-stack-containers"><span>Container</span><span>Image</span><span>Network</span><span>IPv4</span><span>IPv6</span><span>Ports</span><span>Status</span></div>
    {containers.map(c=><div className="table-row ports-aware dual-stack-containers" key={c.id}>
      <div className="name-cell"><div className="container-icon"><Container size={16}/></div>
        <div><strong>{c.name}</strong><span>{c.id.slice(0,12)}</span></div></div>
      <span className="truncate">{c.image}</span>
      <span>{c.networks[0]?.networkName || "—"}</span>
      <code>{c.networks[0]?.ipv4Address || "—"}</code>
      <code className="ipv6-value">{c.networks[0]?.ipv6Address || "—"}</code>
      <div className="port-mini">{c.ports.length ? c.ports.slice(0,3).map(p=><span key={p.containerPort}>{p.containerPort}</span>) : <span>—</span>}</div>
      <span><span className={c.state==="running"?"pill green":"pill"}>{c.state}</span></span>
    </div>)}
    {!containers.length && <Empty text="No matching containers"/>}
  </div>;
}

function Ports({containers,firewall}:{containers:DockerContainer[];firewall:FirewallStatus|null}) {
  const rows = containers.flatMap(c => c.ports.map(p => ({c,p})));

  function publishedRuleState(c:DockerContainer, p:DockerContainer["ports"][number]) {
    const rules=firewall?.config.publishedPortRules ?? [];
    const matching=p.published.flatMap(binding => rules.filter(r => r.enabled && r.containerId===c.id && r.protocol===p.protocol && r.publishedPort===binding.hostPort && r.containerPort===p.port && (r.hostIp===binding.hostIp || (!r.hostIp && !binding.hostIp))));
    const blocks=matching.filter(r=>r.action==="DROP" || r.action==="REJECT"); const accepts=matching.filter(r=>r.action==="ACCEPT");
    const anyDst=(r:any)=>!r.destinationCidr || r.destinationCidr==="0.0.0.0/0" || r.destinationCidr==="::/0";
    if(blocks.some(r=>(r.sourceCidr==="0.0.0.0/0"||r.sourceCidr==="::/0")&&anyDst(r))) return {state:"blocked" as const,detail:"All sources blocked"};
    if(blocks.length) return {state:"restricted" as const,detail:`Blocked: ${blocks.map(r=>`${r.sourceCidr} → ${r.destinationCidr||"ANY"}`).join(", ")}`};
    if(accepts.some(r=>(r.sourceCidr==="0.0.0.0/0"||r.sourceCidr==="::/0")&&anyDst(r))) return {state:"allowed" as const,detail:"Explicit allow"};
    if(accepts.length) return {state:"restricted" as const,detail:`Allowed: ${accepts.map(r=>`${r.sourceCidr} → ${r.destinationCidr||"ANY"}`).join(", ")}`};
    return {state:"open" as const,detail:"No firewall rule"};
  }

  return <div className="table-panel">
    <div className="port-table-head"><span>Container</span><span>Container IP</span><span>Internal port</span><span>Published on host</span><span>Firewall</span></div>

    {rows.map(({c,p},i)=>{
      const policy=publishedRuleState(c,p);
      const state=policy.state;
      const portClass=state==="blocked" ? "port-number blocked" : state==="allowed" ? "port-number allowed" : state==="restricted" ? "port-number restricted" : "port-number open";

      return <div className="port-table-row" key={`${c.id}-${p.containerPort}-${i}`}>
        <div className="name-cell">
          <div className="container-icon"><Plug size={15}/></div>
          <div><strong>{c.name}</strong><span>{c.image}</span></div>
        </div>

        <code className="dual-ip-code">{networkEndpointAddress(c.networks[0]?.ipv4Address,c.networks[0]?.ipv6Address)}</code>

        <code className={portClass}>{p.containerPort}</code>

        <div className="published-list">
          {p.published.length ? p.published.map((x,j)=>
            <code className={portClass} key={j}>
              {formatHostIp(x.hostIp)}:{x.hostPort} → {p.containerPort}
            </code>)
            : <span className="pill">not published</span>}
        </div>

        <div className="port-firewall-state"><span className={state==="blocked" ? "pill danger" : state==="allowed" ? "pill green" : state==="restricted" ? "pill warning" : "pill blue"}>{state==="blocked" ? "BLOCKED" : state==="allowed" ? "ALLOW" : state==="restricted" ? "RESTRICTED" : "NO RULE"}</span><small>{policy.detail}</small></div>
      </div>;
    })}

    {!rows.length && <Empty text="No exposed or published ports"/>}
  </div>;
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
  const [publishedSource,setPublishedSource]=useState("0.0.0.0/0");
  const [publishedDestination,setPublishedDestination]=useState("0.0.0.0/0");
  const [publishedDestinationType,setPublishedDestinationType]=useState<"any"|"docker-network"|"custom">("any");
  const [publishedDestinationNetwork,setPublishedDestinationNetwork]=useState("");
  const [publishedAction,setPublishedAction]=useState<"DROP"|"REJECT"|"ACCEPT">("DROP");
  const [publishedDescription,setPublishedDescription]=useState("");
  const [hostPortKey,setHostPortKey]=useState("");
  const [hostInterface,setHostInterface]=useState("*");
  const [hostFamily,setHostFamily]=useState<4|6|"both">(4);
  const [hostSource,setHostSource]=useState("0.0.0.0/0");
  const [hostProtocol,setHostProtocol]=useState<"all"|"tcp"|"udp"|"icmp"|"icmpv6">("tcp");
  const [hostPort,setHostPort]=useState("");
  const [hostAction,setHostAction]=useState<"ACCEPT"|"DROP"|"REJECT">("DROP");
  const [hostDescription,setHostDescription]=useState("");
  const [accessFamily,setAccessFamily]=useState<4|6>(4);
  const [accessSourceType,setAccessSourceType]=useState<"custom"|"docker-network"|"container"|"wireguard">("wireguard");
  const [accessSourceKey,setAccessSourceKey]=useState("");
  const [accessSourceCustom,setAccessSourceCustom]=useState("");
  const [accessDestinationType,setAccessDestinationType]=useState<"custom"|"docker-network"|"container"|"wireguard">("container");
  const [accessDestinationKey,setAccessDestinationKey]=useState("");
  const [accessDestinationCustom,setAccessDestinationCustom]=useState("");
  const [accessProtocol,setAccessProtocol]=useState<"all"|"tcp"|"udp"|"icmp"|"icmpv6">("all");
  const [accessPort,setAccessPort]=useState("");
  const [accessAction,setAccessAction]=useState<"ACCEPT"|"DROP"|"REJECT">("DROP");
  const [accessDescription,setAccessDescription]=useState("");
  const [editingAccessId,setEditingAccessId]=useState<string|null>(null);


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
        sourceCidr:publishedSource || (publishedFamily===6 ? "::/0" : "0.0.0.0/0"),
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
  async function addHostRule(){setBusy(true);try{await createHostInputRule({family:hostFamily,interfaceName:hostInterface,localAddress:selectedHostPort&&!["0.0.0.0","*","::"].includes(selectedHostPort.listenAddress)?selectedHostPort.listenAddress:null,protocol:hostProtocol,destinationPort:["tcp","udp"].includes(hostProtocol)&&hostPort?Number(hostPort):null,sourceCidr:hostSource,action:hostAction,description:hostDescription});setHostDescription("");await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function removeHostRule(id:string){setBusy(true);try{await removeHostInputRule(id);await load();}catch(e){setMessage(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}

  const accessNetworkOptions=(status?.networkRefs??[]).filter(n=>n.subnets.some(c=>accessFamily===6?c.includes(":"):c.includes(".")));
  const accessContainerOptions=(status?.containerRefs??[]).filter(c=>c.addresses.some(a=>a.family===accessFamily));
  const accessWireGuardOptions=(status?.wireguardRefs??[]).filter(w=>w.family===accessFamily);

  function selectorFrom(type:"custom"|"docker-network"|"container"|"wireguard",key:string,custom:string){
    if(type==="custom")return {type,value:custom.trim(),label:custom.trim()};
    if(type==="docker-network"){const ref=(status?.networkRefs??[]).find(n=>n.id===key);return {type,refId:key,label:ref?.name||key};}
    if(type==="container"){const ref=(status?.containerRefs??[]).find(c=>c.id===key);return {type,refId:key,label:ref?.name||key};}
    const ref=(status?.wireguardRefs??[]).find(w=>w.id===key);return {type,refId:key,value:ref?.cidr||"",label:ref?`${ref.name} · ${ref.cidr}`:key};
  }
  function accessSelectorReady(type:string,key:string,custom:string){return type==="custom"?Boolean(custom.trim()):Boolean(key);}

  async function saveAccessRule(){
    if(!accessSelectorReady(accessSourceType,accessSourceKey,accessSourceCustom)||!accessSelectorReady(accessDestinationType,accessDestinationKey,accessDestinationCustom)){setMessage("Select source and destination");return;}
    const payload={
      family:accessFamily,
      source:selectorFrom(accessSourceType,accessSourceKey,accessSourceCustom),
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
    setAccessSourceType(rule.source.type);setAccessSourceKey(rule.source.refId||"");setAccessSourceCustom(rule.source.type==="custom"?(rule.source.value||""):"");
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
        <label><span>Source CIDR</span><input value={hostSource} onChange={e=>setHostSource(e.target.value)} placeholder={hostFamily===6?"::/0":"0.0.0.0/0"}/></label>
        <label><span>Protocol</span><select value={hostProtocol} onChange={e=>setHostProtocol(e.target.value as any)}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option><option value="all">ANY</option></select></label>
        <label><span>Port</span><input disabled={!["tcp","udp"].includes(hostProtocol)} value={hostPort} onChange={e=>setHostPort(e.target.value.replace(/\D/g,""))}/></label>
        <label><span>Action</span><select value={hostAction} onChange={e=>setHostAction(e.target.value as any)}><option value="ACCEPT">ACCEPT</option><option value="DROP">DROP</option><option value="REJECT">REJECT</option></select></label>
        <label><span>Description</span><input value={hostDescription} onChange={e=>setHostDescription(e.target.value)} placeholder="Optional"/></label>
        <button className="btn add-rule" disabled={busy} onClick={addHostRule}>Add rule</button>
      </div>
      <div className="host-input-list">{(status?.config.hostInputRules??[]).map(rule=><div className="host-input-row" key={rule.id}><div><strong>{rule.interfaceName==="*"?"ANY":rule.interfaceName}</strong><small>{rule.localAddress||"any host IP"}</small></div><code>{rule.family===6?"IPv6":rule.family==="both"?"Dual":"IPv4"} · {rule.protocol.toUpperCase()} {rule.destinationPort??"ANY"}</code><code>{rule.sourceCidr}</code><span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>{counterView(ruleCounter("input",rule.id))}<span className="truncate">{rule.description||"—"}</span><button className="icon-danger" onClick={()=>removeHostRule(rule.id)}><Trash2 size={15}/></button></div>)}{!status?.config.hostInputRules?.length&&<div className="muted published-empty">No host INPUT rules configured</div>}</div>
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
        <label><span>Address family</span><select value={publishedFamily} onChange={e=>{const v=Number(e.target.value) as 4|6;setPublishedFamily(v);const any=v===6?"::/0":"0.0.0.0/0";setPublishedSource(any);setPublishedDestination(any);setPublishedDestinationType("any");setPublishedDestinationNetwork("");}}><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
        <label><span>Source CIDR</span>
          <input value={publishedSource} onChange={e=>setPublishedSource(e.target.value)} placeholder={publishedFamily===6?"::/0":"0.0.0.0/0"}/>
        </label>
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
        {(status?.config.publishedPortRules ?? []).map(rule=>
          <div className="published-policy-row" key={rule.id}>
            <div><strong>{rule.family===6?"IPv6":"IPv4"} · {rule.hostIp}:{rule.publishedPort}/{rule.protocol}</strong>
              <small>→ {rule.containerName}:{rule.containerPort}</small></div>
            <div className="published-cidrs"><code>{rule.sourceCidr}</code><small>→ {rule.destinationCidr || (rule.family===6?"::/0":"0.0.0.0/0")}</small></div>
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
        <PanelTitle title="Container Access / Forwarding" subtitle="Control forwarded traffic from WireGuard, Docker containers/networks, or custom IP/CIDR sources"/>
      </div>
      <div className="session-policy-note"><Shield size={15}/><div><strong>First match wins</strong><span>Rules are evaluated from top to bottom before generic WireGuard/Docker forwarding allows. Changes are draft until Apply changes.</span></div></div>

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
            <div><span className="access-family">{rule.family===6?"IPv6":"IPv4"}</span><strong>{selectorLabel(rule.source)}</strong><small>{rule.source.type}</small></div>
            <div className="access-arrow">→</div>
            <div><strong>{selectorLabel(rule.destination)}</strong><small>{rule.destination.type}</small></div>
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
      <div className="fw-table-head"><span>Source</span><span>Destination</span><span>Protocol</span><span>Port</span><span>Action</span><span>Hits / Traffic</span><span>Description</span><span></span></div>
      {(status?.config.rules ?? []).map(rule=><div className="fw-table-row" key={rule.id}>
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

    <div className="panel runtime-panel">
      <PanelTitle title="Runtime rules" subtitle="Rules currently installed in DRM-FIREWALL on the Docker host"/>
      <pre>{status?.runtime.installedRules.length ? status.runtime.installedRules.join("\n") : "No DRM runtime rules installed."}</pre>
    </div>
  </div>;
}



function RoutingPage(){
  const [status,setStatus]=useState<RoutingStatus|null>(null);
  const [error,setError]=useState('');
  const [family,setFamily]=useState<4|6>(4);
  const [destination,setDestination]=useState('');
  const [gateway,setGateway]=useState('');
  const [dev,setDev]=useState('');
  const [metric,setMetric]=useState('100');
  const [editingId,setEditingId]=useState<string|null>(null);

  async function load(){try{setStatus(await getRoutingStatus());setError('')}catch(e){setError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{load();const t=window.setInterval(load,5000);return()=>window.clearInterval(t)},[]);
  function clearForm(){setEditingId(null);setDestination('');setGateway('');setDev('');setMetric('100')}
  function editRoute(r:any){setEditingId(r.id);setFamily(r.family);setDestination(r.destination);setGateway(r.gateway||'');setDev(r.dev||'');setMetric(r.metric==null?'':String(r.metric))}
  async function save(){try{const body={family,destination,gateway:gateway||null,dev:dev||null,metric:metric?Number(metric):null};if(editingId)await updateRoute(editingId,body);else await createRoute(body);clearForm();await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}

  return <div className="firewall-stack">
    {error&&<div className="error-banner"><Route size={18}/><div><strong>Routing error</strong><span>{error}</span></div></div>}
    <div className="routing-forward-grid">
      <div className="panel routing-status"><div><PanelTitle title="IPv4 forwarding" subtitle="Host forwarding for IPv4 VPN, Docker, VLAN and LAN"/></div><button className={status?.ipForward?'engine-toggle on':'engine-toggle'} onClick={async()=>{await setRoutingForward(!status?.ipForward);await load()}}><span className="toggle-knob"/><span className="toggle-label">{status?.ipForward?'ON':'OFF'}</span></button></div>
      <div className="panel routing-status"><div><PanelTitle title="IPv6 forwarding" subtitle="Host forwarding for WireGuard and Docker IPv6 networks"/></div><button className={status?.ipForward6?'engine-toggle on':'engine-toggle'} onClick={async()=>{await setRoutingForward6(!status?.ipForward6);await load()}}><span className="toggle-knob"/><span className="toggle-label">{status?.ipForward6?'ON':'OFF'}</span></button></div>
    </div>
    <div className="panel"><PanelTitle title={editingId?'Edit static route':'Add static route'} subtitle="Manage persistent IPv4 and IPv6 routes on the Docker host"/><div className="route-builder route-builder-dual">
      <label><span>Family</span><div className="family-switch"><button type="button" className={family===4?"family-option active":"family-option"} onClick={()=>{setFamily(4);setDestination('');setGateway('')}}>IPv4</button><button type="button" className={family===6?"family-option active ipv6":"family-option"} onClick={()=>{setFamily(6);setDestination('');setGateway('')}}>IPv6</button></div></label>
      <label><span>Destination</span><input value={destination} onChange={e=>setDestination(e.target.value)} placeholder={family===4?'10.50.0.0/16':'2001:db8:100::/64'}/></label>
      <label><span>Gateway</span><input value={gateway} onChange={e=>setGateway(e.target.value)} placeholder={family===4?'192.168.150.1':'fd42:8::2'}/></label>
      <label><span>Interface</span><input value={dev} onChange={e=>setDev(e.target.value)} placeholder="wg0 / eth0"/></label>
      <label><span>Metric</span><input value={metric} onChange={e=>setMetric(e.target.value.replace(/\D/g,''))}/></label>
      <button className="btn primary" onClick={save}>{editingId?'Save route':'Add route'}</button>{editingId&&<button className="btn secondary" onClick={clearForm}>Cancel</button>}
    </div></div>
    <div className="table-panel"><div className="route-table-head route-table-dual"><span>Family</span><span>Destination</span><span>Gateway</span><span>Interface</span><span>Protocol</span><span>Metric</span></div>{(status?.routes??[]).map((r:any,i)=><div className="route-table-row route-table-dual" key={`${r.family}-${i}`}><span className={r.family===6?'pill ipv6-pill':'pill blue'}>IPv{r.family}</span><code>{r.dst||'default'}</code><code>{r.gateway||'direct'}</code><span>{r.dev||'—'}</span><span>{r.protocol||r.type||'kernel'}</span><span>{r.metric??'—'}</span></div>)}</div>
    <div className="panel"><PanelTitle title="DRM managed routes" subtitle="Only DRM-managed routes can be edited or deleted"/>{(status?.managedRoutes??[]).map(r=><div className="managed-route managed-route-dual" key={r.id}><span className={r.family===6?'pill ipv6-pill':'pill blue'}>IPv{r.family}</span><code>{r.destination}</code><span>via {r.gateway||'direct'} dev {r.dev||'auto'} metric {r.metric??'—'}</span><div className="managed-route-actions"><button className="btn secondary small" onClick={()=>editRoute(r)}>Edit</button><button className="icon-danger" onClick={async()=>{await removeRoute(r.id);await load()}}><Trash2 size={15}/></button></div></div>)}{!status?.managedRoutes.length&&<Empty text="No DRM managed routes"/>}</div>
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

function WireGuardPage({topology}:{topology:Topology|null}){
  const [status,setStatus]=useState<WireGuardStatus|null>(null);
  const [error,setError]=useState('');
  const [name,setName]=useState('wg0');
  const [address,setAddress]=useState('10.8.0.1/24');
  const [ipv6Enabled,setIpv6Enabled]=useState(false);
  const [ipv6Address,setIpv6Address]=useState('');
  const [listenPort,setListenPort]=useState('51820');
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

  async function createIface(){try{await createWgInterface({name,address:address.trim()||undefined,ipv6Enabled,ipv6Address:ipv6Enabled?(ipv6Address.trim()||autoWgIpv6Gateway(address)):undefined,listenPort:Number(listenPort),mtu:1420});await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  async function addPeer(){try{
    await createWgPeer(selected,{name:peerName,mode:peerMode,clientAddress:clientAddress.trim()||undefined,clientIpv6Address:clientIpv6Address.trim()||undefined,remoteNetworks:remoteNetworks.split(',').map(x=>x.trim()).filter(Boolean),endpointHost:endpointHost.trim(),endpointPort:Number(endpointPort),serverAllowedIps:serverAllowed.split(',').map(x=>x.trim()).filter(Boolean),clientAllowedIps:clientAllowed.split(',').map(x=>x.trim()).filter(Boolean),dns:dns.trim()||undefined,persistentKeepalive:Number(keepalive||0)});
    setQrSvg('');setConfig('');await load();
  }catch(e){setError(e instanceof Error?e.message:String(e))}}

  function editPeer(peer:any){
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
    <div className="panel"><PanelTitle title="Create WireGuard interface" subtitle="Native Linux WireGuard with optional automatic IPv6 dual-stack"/><div className="route-builder wg-interface-builder wg-interface-builder-dual"><label><span>Name</span><input value={name} onChange={e=>setName(e.target.value)}/></label><label><span>IPv4 gateway</span><input value={address} onChange={e=>setAddress(e.target.value)} placeholder="10.8.0.1/24"/></label><label className="wg-ipv6-toggle"><span>IPv6</span><div className="wg-ipv6-check"><input type="checkbox" checked={ipv6Enabled} onChange={e=>setIpv6Enabled(e.target.checked)}/><strong>Enable IPv6</strong></div></label>{ipv6Enabled&&<label><span>IPv6 gateway</span><input value={ipv6Address} onChange={e=>setIpv6Address(e.target.value)} placeholder="fd42:8::1/64"/><small className="field-hint">Generated automatically; you can edit it.</small></label>}<label><span>Listen port</span><input value={listenPort} onChange={e=>setListenPort(e.target.value.replace(/\D/g,''))}/></label><button className="btn primary" onClick={createIface}>Create interface</button></div></div>
    <div className="wg-layout"><div className="panel"><PanelTitle title="Interfaces" subtitle="Configured by DRM"/>{(status?.interfaces??[]).map(i=>
      <div className={selected===i.name?'wg-interface-card active':'wg-interface-card'} key={i.name}>
        <button className="wg-interface-select" onClick={()=>{setSelected(i.name);setEndpointPortTouched(false);setConfig('');setQrSvg('')}}>
          <div><strong>{i.name}</strong><span>{[i.address,i.ipv6Address].filter(Boolean).join(' · ')} · UDP {i.listenPort}</span></div><code>{i.peers.length} peers</code>
        </button>
        <button className="wg-interface-delete" title={`Delete ${i.name}`} onClick={()=>deleteInterface(i.name)}><Trash2 size={15}/></button>
      </div>
    )}{!status?.interfaces.length&&<Empty text="No WireGuard interfaces"/>}</div>
    <div className="panel"><PanelTitle title={iface?`${iface.name} peers`:'Peers'} subtitle={iface?`Public key: ${iface.publicKey}`:'Select an interface'}/>{iface&&<>
      <div className="wg-existing-ipv6">
        <label className="wg-network-check"><input type="checkbox" checked={Boolean(iface.ipv6Address)} onChange={e=>toggleSelectedIpv6(e.target.checked)}/><span><strong>IPv6</strong><small>{iface.ipv6Address?'Enabled for this WireGuard interface':'Enable automatic IPv6 addressing'}</small></span></label>
        {iface.ipv6Address&&<label><span>IPv6 gateway</span><div className="wg-inline-save"><input value={selectedIpv6Gateway} onChange={e=>setSelectedIpv6Gateway(e.target.value)}/><button className="btn secondary" onClick={()=>toggleSelectedIpv6(true)}>Apply</button></div><small className="field-hint">Peers are assigned ::2/128, ::3/128, ... automatically.</small></label>}
      </div>
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

      <div className="wg-settings-grid">
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
      </div>

</>}</div></div>
    {config&&<div className="panel"><PanelTitle title="Generated client configuration" subtitle="Private key is sensitive; download and QR are available only to Operator/Administrator"/><pre className="wg-config">{config}</pre><div className="wg-config-actions"><button className="btn secondary" onClick={()=>navigator.clipboard.writeText(config)}>Copy config</button><button className="btn primary" onClick={downloadConfig}><Download size={14}/> Download .conf</button>{qrSvg&&<button className="btn secondary" onClick={()=>setQrSvg('')}>Hide QR</button>}</div>{qrSvg&&<div className="wg-qr"><div dangerouslySetInnerHTML={{__html:qrSvg}}/><span>Scan with the WireGuard mobile app</span></div>}</div>}
  </div>
}

const topologyStorageKey="drm-topology-positions-v1";
function loadTopologyPositions():Record<string,{x:number;y:number}>{try{return JSON.parse(localStorage.getItem(topologyStorageKey)||"{}");}catch{return {};}}
function saveTopologyPosition(id:string,position:{x:number;y:number}){const p=loadTopologyPositions();p[id]=position;localStorage.setItem(topologyStorageKey,JSON.stringify(p));}

function TopologyView({data,firewall}:{data:Topology|null;firewall:FirewallStatus|null}) {
  const built=useMemo(()=>buildFlow(data,firewall),[data,firewall]);
  const [nodes,setNodes,onNodesChange]=useNodesState(built.nodes);
  const [topologyUnlocked,setTopologyUnlocked]=useState(()=>localStorage.getItem("drm-topology-unlocked")==="1");

  useEffect(()=>{const current=new Map(nodes.map(n=>[n.id,n]));setNodes(built.nodes.map(n=>current.get(n.id)?{...n,position:current.get(n.id)!.position}:n));},[built.nodes]);
  useEffect(()=>{localStorage.setItem("drm-topology-unlocked",topologyUnlocked?"1":"0")},[topologyUnlocked]);

  const edges=built.edges;

  return <div className="topology-shell">
    <div className="topology-toolbar">
      <div>
        <strong>Live network topology</strong>
        <span>{topologyUnlocked ? "Layout unlocked · drag nodes to arrange them" : "Layout locked · open the padlock to move nodes"} · drag empty space to move the canvas · positions are saved</span>
      </div>
      <div className="legend topology-legend">
        <span><i className="legend-network"/> Network</span>
        <span><i className="legend-container"/> Container</span>
        <span><i className="legend-port"/> Published port</span>
        <span><i className="legend-allow"/> Allowed path</span>
        <span><i className="legend-block"/> Blocked path</span>
      </div>
    </div>
    <div className="flow">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onNodeDragStop={(_e,node)=>saveTopologyPosition(node.id,node.position)}
        fitView
        minZoom={0.12}
        maxZoom={1.6}
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
  </div>;
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
