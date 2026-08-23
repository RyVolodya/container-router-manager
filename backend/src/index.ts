import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { authenticate, adminResetPassword, changeOwnPassword, createUser, deleteUser, destroySession, getSession, initializeAuth, listUsers, secureCompare, updateUserRole } from "./authService.js";
import { getContainerNetworkStats, getDockerInfo, getTopology, listContainers, listNetworks } from "./dockerService.js";
import { addManagedRoute, deleteManagedRoute, getRoutingStatus, restoreManagedRoutes, setIpForward, setIpForward6, updateManagedRoute } from "./routingService.js";
import { addWireGuardPeer, createWireGuardInterface, deleteWireGuardInterface, deleteWireGuardPeer, getClientConfig, getClientConfigQrSvg, getWireGuardStatus, restoreWireGuard, setWireGuardAccessPolicy, configureWireGuardIpv6, updateWireGuardPeer, setWireGuardPeerEnabled } from "./wireguardService.js";
import { addFirewallRule, addHostInputRule, addPublishedPortRule, addContainerAccessRule, updateContainerAccessRule, deleteContainerAccessRule, reorderContainerAccessRules, applyFirewall, deleteFirewallRule, deleteHostInputRule, deletePublishedPortRule, disableFirewall, getFirewallStatus, rollbackFirewall } from "./firewallService.js";
import { getUpdateStatus } from "./updateService.js";

const app = express();
const port = Number(process.env.PORT ?? 8080);

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: "64kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "docker-router-manager", version: "0.10.12" });
});


const sessionCookieName = "drm_session";
const cookieSecure = process.env.COOKIE_SECURE === "true";

function parseCookies(header: string | undefined) {
  const result: Record<string,string> = {};
  for (const part of (header ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    result[decodeURIComponent(part.slice(0,index).trim())] = decodeURIComponent(part.slice(index+1).trim());
  }
  return result;
}

function setSessionCookie(res: express.Response, sessionId: string) {
  const maxAge = Math.floor(Number(process.env.SESSION_TTL_MS ?? 24 * 60 * 60 * 1000) / 1000);
  const secure = cookieSecure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookieName}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`);
}

function clearSessionCookie(res: express.Response) {
  const secure = cookieSecure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "too_many_attempts", message: "Too many login attempts. Try again later." }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { user, session } = await authenticate(String(req.body?.username ?? ""), String(req.body?.password ?? ""));
    setSessionCookie(res, session.id);
    res.json({ user, csrfToken: session.csrfToken });
  } catch (error) {
    res.status(401).json({ error: "invalid_credentials", message: error instanceof Error ? error.message : String(error) });
  }
});

app.use("/api", async (req, res, next) => {
  if (req.path === "/auth/login") return next();
  const cookies = parseCookies(req.headers.cookie);
  const auth = await getSession(cookies[sessionCookieName]);
  if (!auth) return res.status(401).json({ error: "unauthorized", message: "Authentication required" });
  (req as any).auth = auth;

  // Keep the HttpOnly cookie aligned with the rolling server-side session.
  // The session ID itself is not rotated here; only Max-Age is refreshed.
  setSessionCookie(res, auth.session.id);

  if (auth.user.mustChangePassword && !["/auth/me","/auth/change-password","/auth/logout"].includes(req.path)) {
    return res.status(428).json({ error: "password_change_required", message: "Password change required before using DRM" });
  }

  if (!["GET","HEAD","OPTIONS"].includes(req.method)) {
    const csrf = String(req.header("X-CSRF-Token") ?? "");
    if (!csrf || !secureCompare(csrf, auth.session.csrfToken)) {
      return res.status(403).json({ error: "csrf_failed", message: "Invalid CSRF token" });
    }
  }
  next();
});

app.get("/api/auth/me", (req, res) => {
  const auth = (req as any).auth;
  res.json({ user: auth.publicUser, csrfToken: auth.session.csrfToken });
});

app.get("/api/system/update", async (_req, res) => {
  try {
    res.json(await getUpdateStatus());
  } catch (error) {
    res.status(502).json({ error: "update_check_failed", message: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  const auth = (req as any).auth;
  await destroySession(auth.session.id);
  clearSessionCookie(res);
  res.status(204).end();
});

app.post("/api/auth/change-password", async (req, res) => {
  try {
    const auth = (req as any).auth;
    const user = await changeOwnPassword(auth.user.id, String(req.body?.currentPassword ?? ""), String(req.body?.newPassword ?? ""), auth.session.id);
    // Current session remains valid; refresh session data on the next request.
    res.json({ user });
  } catch (error) {
    res.status(400).json({ error: "password_change_failed", message: error instanceof Error ? error.message : String(error) });
  }
});

function paramString(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
}

function requireRole(...roles: string[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const auth = (req as any).auth;
    if (!auth || !roles.includes(auth.user.role)) return res.status(403).json({ error: "forbidden", message: "Insufficient permissions" });
    next();
  };
}

app.get("/api/management/users", requireRole("administrator"), async (_req, res) => {
  res.json(await listUsers());
});
app.post("/api/management/users", requireRole("administrator"), async (req, res) => {
  try { res.status(201).json(await createUser(req.body)); }
  catch (e) { res.status(400).json({ message: e instanceof Error ? e.message : String(e) }); }
});
app.patch("/api/management/users/:id/role", requireRole("administrator"), async (req, res) => {
  try { res.json(await updateUserRole((req as any).auth.user.id, paramString(req.params.id), req.body.role)); }
  catch (e) { res.status(400).json({ message: e instanceof Error ? e.message : String(e) }); }
});
app.post("/api/management/users/:id/reset-password", requireRole("administrator"), async (req, res) => {
  try { res.json(await adminResetPassword((req as any).auth.user.id, paramString(req.params.id), String(req.body?.password ?? ""))); }
  catch (e) { res.status(400).json({ message: e instanceof Error ? e.message : String(e) }); }
});
app.delete("/api/management/users/:id", requireRole("administrator"), async (req, res) => {
  try { await deleteUser((req as any).auth.user.id, paramString(req.params.id)); res.status(204).end(); }
  catch (e) { res.status(400).json({ message: e instanceof Error ? e.message : String(e) }); }
});

// Read-only GET endpoints are available to all authenticated roles.
// Network-changing endpoints are restricted to Administrator/Operator.
app.use("/api/firewall", (req,res,next)=> ["GET","HEAD","OPTIONS"].includes(req.method) ? next() : requireRole("administrator","operator")(req,res,next));
app.use("/api/routing", (req,res,next)=> ["GET","HEAD","OPTIONS"].includes(req.method) ? next() : requireRole("administrator","operator")(req,res,next));
app.use("/api/wireguard", (req,res,next)=> {
  if (req.path.endsWith("/config") || req.path.endsWith("/qr")) return requireRole("administrator","operator")(req,res,next);
  return ["GET","HEAD","OPTIONS"].includes(req.method) ? next() : requireRole("administrator","operator")(req,res,next);
});

app.get("/api/docker/info", async (_req, res) => {
  try {
    const info = await getDockerInfo();
    res.json({
      name: info.Name,
      serverVersion: info.ServerVersion,
      containers: info.Containers,
      containersRunning: info.ContainersRunning,
      containersStopped: info.ContainersStopped,
      images: info.Images,
      driver: info.Driver,
      operatingSystem: info.OperatingSystem,
      architecture: info.Architecture,
      ncpu: info.NCPU,
      memTotal: info.MemTotal
    });
  } catch (error) {
    res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.get("/api/networks", async (_req, res) => {
  try { res.json(await listNetworks()); }
  catch (error) {
    res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.get("/api/containers", async (_req, res) => {
  try { res.json(await listContainers()); }
  catch (error) {
    res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.get("/api/topology", async (_req, res) => {
  try { res.json(await getTopology()); }
  catch (error) {
    res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
  }
});




app.get("/api/firewall/status", async (_req, res) => {
  try {
    res.json(await getFirewallStatus());
  } catch (error) {
    res.status(500).json({ error: "firewall_status_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/api/firewall/rules", async (req, res) => {
  try {
    const rule = await addFirewallRule(req.body);
    res.status(201).json(rule);
  } catch (error) {
    res.status(400).json({ error: "invalid_firewall_rule", message: error instanceof Error ? error.message : String(error) });
  }
});

app.delete("/api/firewall/rules/:id", async (req, res) => {
  try {
    await deleteFirewallRule(paramString(req.params.id));
    res.status(204).end();
  } catch (error) {
    res.status(404).json({ error: "firewall_rule_not_found", message: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/api/firewall/apply", async (_req, res) => {
  try {
    res.json(await applyFirewall());
  } catch (error) {
    res.status(500).json({ error: "firewall_apply_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/api/firewall/disable", async (_req, res) => {
  try {
    res.json(await disableFirewall());
  } catch (error) {
    res.status(500).json({ error: "firewall_disable_error", message: error instanceof Error ? error.message : String(error) });
  }
});

app.post("/api/firewall/rollback", async (_req, res) => {
  try {
    res.json(await rollbackFirewall());
  } catch (error) {
    res.status(500).json({ error: "firewall_rollback_error", message: error instanceof Error ? error.message : String(error) });
  }
});




app.post("/api/firewall/published-port-rules", async (req, res) => {
  try {
    const rule = await addPublishedPortRule(req.body);
    res.status(201).json(rule);
  } catch (error) {
    res.status(400).json({ error: "invalid_published_port_rule", message: error instanceof Error ? error.message : String(error) });
  }
});

app.delete("/api/firewall/published-port-rules/:id", async (req, res) => {
  try {
    await deletePublishedPortRule(paramString(req.params.id));
    res.status(204).end();
  } catch (error) {
    res.status(404).json({ error: "published_port_rule_not_found", message: error instanceof Error ? error.message : String(error) });
  }
});
app.get("/api/published-ports", async (_req, res) => {
  try {
    const topology = await getTopology();
    const ports = topology.containers.flatMap((container) =>
      container.ports.flatMap((port) =>
        port.published.map((binding) => ({
          containerId: container.id,
          containerName: container.name,
          protocol: port.protocol,
          containerPort: port.port,
          hostIp: binding.hostIp || "0.0.0.0",
          hostPort: binding.hostPort
        }))
      )
    );
    res.json(ports);
  } catch (error) {
    res.status(500).json({ error: "published_ports_error", message: error instanceof Error ? error.message : String(error) });
  }
});




app.get("/api/stats/network", async (_req, res) => {
  try { res.json(await getContainerNetworkStats()); }
  catch (error) { res.status(502).json({ error: "docker_stats_error", message: error instanceof Error ? error.message : String(error) }); }
});





app.post("/api/firewall/host-input-rules", async (req,res)=>{try{res.status(201).json(await addHostInputRule(req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.delete("/api/firewall/host-input-rules/:id", async (req,res)=>{try{await deleteHostInputRule(paramString(req.params.id));res.status(204).end()}catch(e){res.status(404).json({message:e instanceof Error?e.message:String(e)})}});

app.post("/api/firewall/access-rules", async (req,res)=>{try{res.status(201).json(await addContainerAccessRule(req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.put("/api/firewall/access-rules/:id", async (req,res)=>{try{res.json(await updateContainerAccessRule(paramString(req.params.id),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.delete("/api/firewall/access-rules/:id", async (req,res)=>{try{await deleteContainerAccessRule(paramString(req.params.id));res.status(204).end()}catch(e){res.status(404).json({message:e instanceof Error?e.message:String(e)})}});
app.post("/api/firewall/access-rules/reorder", async (req,res)=>{try{res.json(await reorderContainerAccessRules(Array.isArray(req.body?.ids)?req.body.ids.map(String):[]))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});


app.get('/api/routing/status', async (_req,res)=>{try{res.json(await getRoutingStatus())}catch(e){res.status(500).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/routing/ip-forward', async (req,res)=>{try{res.json(await setIpForward(Boolean(req.body.enabled)))}catch(e){res.status(500).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/routing/ip-forward6', async (req,res)=>{try{res.json(await setIpForward6(Boolean(req.body.enabled)))}catch(e){res.status(500).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/routing/routes', async (req,res)=>{try{res.status(201).json(await addManagedRoute(req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.put('/api/routing/routes/:id', async (req,res)=>{try{res.json(await updateManagedRoute(paramString(req.params.id),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.delete('/api/routing/routes/:id', async (req,res)=>{try{await deleteManagedRoute(paramString(req.params.id));res.status(204).end()}catch(e){res.status(404).json({message:e instanceof Error?e.message:String(e)})}});

app.get('/api/wireguard/status', async (_req,res)=>{try{res.json(await getWireGuardStatus())}catch(e){res.status(500).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/wireguard/interfaces', async (req,res)=>{try{res.status(201).json(await createWireGuardInterface(req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.delete('/api/wireguard/interfaces/:name', async (req,res)=>{try{await deleteWireGuardInterface(paramString(req.params.name));res.status(204).end()}catch(e){res.status(404).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/wireguard/interfaces/:name/peers', async (req,res)=>{try{res.status(201).json(await addWireGuardPeer(paramString(req.params.name),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.put('/api/wireguard/interfaces/:name/peers/:id', async (req,res)=>{try{res.json(await updateWireGuardPeer(paramString(req.params.name),paramString(req.params.id),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.post('/api/wireguard/interfaces/:name/peers/:id/enabled', async (req,res)=>{try{res.json(await setWireGuardPeerEnabled(paramString(req.params.name),paramString(req.params.id),Boolean(req.body.enabled)))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.put('/api/wireguard/interfaces/:name/access', async (req,res)=>{try{res.json(await setWireGuardAccessPolicy(paramString(req.params.name),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.put('/api/wireguard/interfaces/:name/ipv6', async (req,res)=>{try{res.json(await configureWireGuardIpv6(paramString(req.params.name),req.body))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.delete('/api/wireguard/interfaces/:name/peers/:id', async (req,res)=>{try{await deleteWireGuardPeer(paramString(req.params.name),paramString(req.params.id));res.status(204).end()}catch(e){res.status(404).json({message:e instanceof Error?e.message:String(e)})}});
app.get('/api/wireguard/interfaces/:name/peers/:id/config', async (req,res)=>{try{res.type('text/plain').send(await getClientConfig(paramString(req.params.name),paramString(req.params.id)))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});
app.get('/api/wireguard/interfaces/:name/peers/:id/qr', async (req,res)=>{try{res.type('image/svg+xml').send(await getClientConfigQrSvg(paramString(req.params.name),paramString(req.params.id)))}catch(e){res.status(400).json({message:e instanceof Error?e.message:String(e)})}});

Promise.all([initializeAuth(),restoreManagedRoutes(),restoreWireGuard()]).catch(e=>console.warn('DRM startup restore warning',e));

app.listen(port, "0.0.0.0", () => console.log(`DRM backend listening on ${port}`));
