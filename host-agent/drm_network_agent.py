#!/usr/bin/env python3
"""Restricted host-side IPv6 networkd helper for DRM; Ubuntu/systemd-networkd only."""
import ipaddress, json, os, re, socketserver, subprocess, threading, time
from pathlib import Path

SOCK = Path('/run/drm-network-agent/agent.sock')
STATE = Path('/var/lib/drm-network-agent')
PENDING = STATE / 'pending.json'
LOCK = threading.RLock()

def command(*args):
    p = subprocess.run(args, text=True, capture_output=True, timeout=25)
    if p.returncode: raise RuntimeError(f'{" ".join(args)}: {p.stderr.strip()}')
    return p.stdout

def target(name):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name) or name == 'lo': raise ValueError('Invalid interface name')
    network = Path('/run/systemd/network') / f'10-netplan-{name}.network'
    if not network.is_file(): raise RuntimeError('Only interfaces managed by Netplan/systemd-networkd are supported')
    if f'Name={name}' not in network.read_text(): raise RuntimeError('Mismatched networkd configuration')
    # This drop-in corresponds to Netplan-generated networkd .network basename.
    dropin = Path('/etc/systemd/network') / (network.name + '.d') / '90-drm-ipv6.conf'
    return dropin

def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(data)
    os.replace(temp, path)

def dns_snapshot(name):
    try:
        result = command('resolvectl','dns',name).split(':',1)[-1]
        return [x for x in result.split() if _valid_ip(x)]
    except Exception: return []

def _valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except ValueError: return False

def set_dns(name, servers):
    if servers: command('resolvectl','dns',name,*servers)
    else: command('resolvectl','revert',name)

def ipv6_dns_from_dropin(name):
    path = target(name)
    if not path.exists(): return []
    result = []
    for value in re.findall(r'^DNS=([^\n]+)$', path.read_text(), re.M):
        for item in value.split():
            try:
                if ipaddress.ip_address(item).version == 6 and item not in result: result.append(item)
            except ValueError: pass
    return result

def netplan_dns(name):
    """Read only the DNS field from DRM's own generated overlay."""
    path = Path('/etc/netplan') / f'99-drm-{name}.yaml'
    if not path.exists(): return []
    match = re.search(r'^      nameservers:\n        addresses: \[([^\]\n]*)\]', path.read_text(), re.M)
    if not match: return []
    return [v.strip() for v in match.group(1).split(',') if _valid_ip(v.strip())]

def sync_netplan_dns(name, dns4, dns6):
    """Persist the combined DNS list, preserving unrelated Netplan keys and IPv4 routes."""
    path = Path('/etc/netplan') / f'99-drm-{name}.yaml'
    if not path.exists(): return None
    old = path.read_text()
    values = list(dict.fromkeys(dns4 + dns6))
    new = re.sub(r'^      nameservers:\n        addresses: \[[^\]\n]*\]\n?', '', old, flags=re.M)
    # The DRM overlay contains exactly one interface at six spaces indentation.
    if values:
        if not new.endswith('\n'): new += '\n'
        new += '      nameservers:\n        addresses: ['+', '.join(values)+']\n'
    if new != old:
        atomic(path, new)
        os.chmod(path, 0o600)
        try: command('netplan', 'generate')
        except Exception:
            atomic(path,old); os.chmod(path,0o600)
            command('netplan','generate')
            raise
    return old

def ipv6_snapshot(name):
    addr = json.loads(command('ip','-j','-6','addr','show','dev',name))[0].get('addr_info', [])
    routes = json.loads(command('ip','-j','-6','route','show','default'))
    # Full multipath route with mixed interfaces must never be changed by this agent.
    owned = [r for r in routes if (r.get('dev') == name or
             (r.get('nexthops') and all(h.get('dev') == name for h in r['nexthops'])))]
    return {'addresses': [x for x in addr if x.get('family') == 'inet6' and x.get('scope') != 'link'],
            'routes': owned}

def drop_route(r, name):
    metric = str(r.get('metric', 1024))
    # iproute2 deletes the whole equal-cost multipath route as a unit.
    args = ['ip','-6','route','del','default']
    if r.get('nexthops'):
        for h in r['nexthops']:
            args += ['nexthop','via',h['gateway'],'dev',h['dev'],'weight',str(h.get('weight',1))]
    elif r.get('gateway'):
        args += ['via',r['gateway'],'dev',r.get('dev',name)]
    else:
        args += ['dev',r.get('dev',name)]
    args += ['metric',metric]
    command(*args)

def add_route(r, name):
    args = ['ip','-6','route','replace','default']
    if r.get('nexthops'):
        for h in r['nexthops']:
            args += ['nexthop', 'via', h['gateway'], 'dev', h['dev'], 'weight', str(h.get('weight',1))]
    elif r.get('gateway'):
        args += ['via',r['gateway'],'dev',r.get('dev',name)]
    else:
        args += ['dev',r.get('dev',name)]
    if r.get('metric') is not None: args += ['metric',str(r['metric'])]
    command(*args)

def remove_dynamic_ipv6(name, addresses):
    for a in addresses:
        if a.get('dynamic') or a.get('valid_life_time') != 'forever':
            command('ip','-6','addr','del',f"{a['local']}/{a['prefixlen']}",'dev',name)

def reload_link(name):
    command('networkctl', 'reload')
    command('networkctl', 'reconfigure', name)

def ensure_ipv4_persistent_before_reconfigure(name):
    """Fail closed if reconfigure would replace a live static IPv4 with DHCP."""
    import socket
    # Regenerate networkd configuration from all Netplan overlays, including DRM's.
    command('netplan', 'generate')
    base = (Path('/run/systemd/network') / f'10-netplan-{name}.network').read_text()
    dhcp_match = re.search(r'^DHCP\s*=\s*(.+)$', base, re.M)
    dhcp = dhcp_match.group(1).strip().lower() if dhcp_match else 'no'
    addresses = json.loads(command('ip', '-j', '-4', 'addr', 'show', 'dev', name))[0].get('addr_info', [])
    live_static = any(a.get('family') == 'inet' and not a.get('dynamic') and a.get('scope') == 'global' for a in addresses)
    if live_static and dhcp in ('ipv4', 'yes', 'true'):
        raise RuntimeError('Refusing IPv6 RA reconfigure: live IPv4 is static but Netplan still enables DHCPv4')
    if live_static:
        configured = set(re.findall(r'^Address\s*=\s*(\S+)', base, re.M))
        # Netplan may put static addresses in the [Address] section.
        live = {f"{a['local']}/{a['prefixlen']}" for a in addresses if a.get('family') == 'inet' and not a.get('dynamic') and a.get('scope') == 'global'}
        if not live.issubset(configured):
            raise RuntimeError('Refusing IPv6 RA reconfigure: live IPv4 address missing from generated Netplan configuration')

def restore(p):
    path = target(p['interface'])
    name = p['interface']
    if p.get('static_live'):
        # Block RA during restoration and remove only the route/address we added.
        for key in ('accept_ra','autoconf','accept_ra_defrtr'):
            Path(f'/proc/sys/net/ipv6/conf/{name}/{key}').write_text('0')
        try: command('ip','-6','addr','del',p['new_address'],'dev',name)
        except Exception: pass
        current = ipv6_snapshot(name)
        for r in current['routes']:
            try: drop_route(r,name)
            except Exception: pass
        snap = p.get('previous_ipv6',{})
        for a in snap.get('addresses',[]):
            cidr = f"{a['local']}/{a['prefixlen']}"
            try: command('ip','-6','addr','add',cidr,'dev',name)
            except Exception: pass
        for r in snap.get('routes',[]):
            try: add_route(r,name)
            except Exception: pass
        for key, value in p.get('old_sysctls',{}).items():
            Path(f'/proc/sys/net/ipv6/conf/{name}/{key}').write_text(value)
    if p['old_exists']: atomic(path,p['old'])
    else: path.unlink(missing_ok=True)
    if p.get('old_netplan_dns') is not None:
        netplan_path = Path('/etc/netplan') / f'99-drm-{name}.yaml'
        atomic(netplan_path, p['old_netplan_dns'])
        os.chmod(netplan_path, 0o600)
        command('netplan','generate')
    if p.get('static_ra'):
        # Restore the previous RA policy as well as the previous addresses.
        reload_link(name)
    elif not p.get('static_live'):
        reload_link(name)
    if 'old_dns' in p:
        try: set_dns(name,p['old_dns'])
        except Exception: pass
    PENDING.unlink(missing_ok=True)

def ipv4_netplan_override(name, config):
    """Persist DRM IPv4 ownership in a late Netplan overlay without replacing base YAML."""
    target(name)
    path = Path('/etc/netplan') / f'99-drm-{name}.yaml'
    mode = config.get('mode')
    if mode not in ('static', 'dhcp'): raise ValueError('Invalid IPv4 mode')
    if mode == 'static':
        address = ipaddress.IPv4Interface(config.get('address', ''))
        gateway = config.get('gateway')
        if gateway: gateway = ipaddress.IPv4Address(gateway)
        lines = ['network:', '  version: 2', '  ethernets:', f'    {name}:', '      dhcp4: false', '      addresses:', f'        - {address}']
        if gateway and config.get('addDefaultRoute', True):
            lines += ['      routes:', '        - to: default', f'          via: {gateway}', f'          metric: {int(config.get("metric") or 100)}']
    else:
        lines = ['network:', '  version: 2', '  ethernets:', f'    {name}:', '      dhcp4: true', '      dhcp4-overrides:', '        use-dns: true', '      addresses: []', '      routes: []']
    dns=config.get('dns',[])
    if not isinstance(dns,list) or len(dns)>8 or any(ipaddress.ip_address(x).version != 4 for x in dns): raise ValueError('Invalid IPv4 DNS')
    # Preserve only manually configured IPv6 resolvers. DHCPv4 resolvers are acquired by networkd.
    dropin_text = target(name).read_text() if target(name).exists() else ''
    is_auto_v6 = 'UseAutonomousPrefix=yes' in dropin_text or 'DHCPv6Client=always' in dropin_text
    old_dns6 = ([] if is_auto_v6 else [x for x in netplan_dns(name) if ipaddress.ip_address(x).version == 6])
    all_dns=list(dict.fromkeys((dns if mode == 'static' else []) + old_dns6))
    if all_dns: lines += ['      nameservers:', '        addresses: ['+', '.join(all_dns)+']']
    old_exists = path.exists()
    old = path.read_text() if old_exists else ''
    atomic(path, '\n'.join(lines)+'\n')
    os.chmod(path, 0o600)
    try:
        command('netplan','generate')
    except Exception:
        if old_exists:
            atomic(path,old)
            os.chmod(path, 0o600)
        else:
            path.unlink(missing_ok=True)
        raise
    # Transition code activates generated Netplan via networkd after snapshot.
    return {'saved':True, 'path':str(path)}

def ipv4_transition(name, config, token):
    """Stage IPv4 Netplan with a rollback snapshot; networkd owns DHCPv4."""
    target(name)
    if not re.fullmatch(r'[0-9a-f-]{36}', token): raise ValueError('Invalid token')
    backup = STATE / ('ipv4-' + name + '.json')
    if backup.exists(): raise RuntimeError('An IPv4 transition is pending')
    path = Path('/etc/netplan') / f'99-drm-{name}.yaml'
    old_exists, old = path.exists(), path.read_text() if path.exists() else ''
    # Record the old state before any operation that could interrupt connectivity.
    STATE.mkdir(parents=True, exist_ok=True)
    atomic(backup, json.dumps({'token':token,'old_exists':old_exists,'old':old}))
    try:
        ipv4_netplan_override(name, config)
        # Remove only existing IPv4 globals and default routes; IPv6 is untouched.
        # Preserve gateway reachability on the Proxmox console during the switch.
        command('ip','-4','addr','flush','dev',name,'scope','global')
        for row in json.loads(command('ip','-j','-4','route','show','default','dev',name)):
            try: command('ip','-4','route','del','default','dev',name)
            except Exception: pass
        command('networkctl','reload')
        command('networkctl','reconfigure',name)
        # Discard DNS overrides written by older CRM versions. Networkd will
        # republish DHCPv4, RDNSS and DHCPv6 DNS during link reconfiguration.
        try:
            command('resolvectl','revert',name)
            command('networkctl','reconfigure',name)
        except Exception: pass
        return {'staged':True,'mode':config.get('mode')}
    except Exception:
        restore_ipv4_transition(name,token)
        raise

def restore_ipv4_transition(name, token, confirm=False):
    target(name)
    backup=STATE / ('ipv4-' + name + '.json')
    if not backup.exists(): return {'restored':False}
    data=json.loads(backup.read_text())
    if data['token'] != token: raise RuntimeError('Invalid IPv4 transition token')
    if not confirm:
        path=Path('/etc/netplan') / f'99-drm-{name}.yaml'
        if data['old_exists']:
            atomic(path,data['old'])
            os.chmod(path,0o600)
        else: path.unlink(missing_ok=True)
        command('netplan','generate')
        command('networkctl','reload')
        command('networkctl','reconfigure',name)
    backup.unlink(missing_ok=True)
    return {'confirmed':True} if confirm else {'restored':True}

def request(req):
    with LOCK:
        op = req.get('operation')
        if op == 'status':
            return {'pending': json.loads(PENDING.read_text()) if PENDING.exists() else None}
        if op == 'get_dns':
            name = str(req.get('interface', ''))
            target(name)
            return {'servers': dns_snapshot(name)}
        if op == 'set_dns':
            name = str(req.get('interface', ''))
            target(name)
            servers = req.get('servers')
            if not isinstance(servers, list) or len(servers) > 16 or any(not isinstance(x, str) or not _valid_ip(x) for x in servers):
                raise ValueError('Invalid DNS servers')
            set_dns(name, servers)
            return {'servers': dns_snapshot(name)}
        if op == 'apply_ipv4':
            return ipv4_transition(str(req.get('interface','')), req.get('config',{}), str(req.get('token','')))
        if op == 'confirm_ipv4':
            return restore_ipv4_transition(str(req.get('interface','')), str(req.get('token','')), True)
        if op == 'rollback_ipv4':
            return restore_ipv4_transition(str(req.get('interface','')), str(req.get('token','')))
        if op == 'persist_ipv4':
            return ipv4_netplan_override(str(req.get('interface','')), req.get('config',{}))
        if op == 'apply':
            if PENDING.exists(): raise RuntimeError('Another Safe Apply is pending')
            name = str(req.get('interface', ''))
            path = target(name)
            config = req.get('config', {})
            if config.get('enabled') is not True: raise ValueError('IPv6 must be enabled')
            mode = config.get('mode')
            if mode not in ('auto', 'static'): raise ValueError('Invalid IPv6 mode')
            metric = config.get('metric')
            if metric is None: metric = 100
            if type(metric) is not int or not 0 <= metric <= 4294967295: raise ValueError('Invalid metric')
            if type(config.get('addDefaultRoute', True)) is not bool: raise ValueError('Invalid default route flag')
            if mode == 'auto':
                if type(config.get('slaac')) is not bool or type(config.get('dhcpv6')) is not bool: raise ValueError('Invalid automatic IPv6 flags')
                if not (config['slaac'] or config['dhcpv6']): raise ValueError('Enable SLAAC or DHCPv6')
                if config.get('address') or config.get('gateway'): raise ValueError('Automatic IPv6 cannot have a static address or gateway')
            else:
                try: address = ipaddress.IPv6Interface(config.get('address', ''))
                except (ValueError, TypeError) as exc: raise ValueError('Invalid static IPv6 address/prefix') from exc
                if '/' not in str(config.get('address', '')): raise ValueError('Static IPv6 requires a prefix')
                gateway = config.get('gateway')
                if gateway:
                    try: gateway = ipaddress.IPv6Address(gateway)
                    except (ValueError, TypeError) as exc: raise ValueError('Invalid static IPv6 gateway') from exc
                if config.get('slaac') or config.get('dhcpv6'): raise ValueError('Static IPv6 cannot use SLAAC or DHCPv6')
                if config.get('addDefaultRoute', False) and gateway: raise ValueError('RA gateway and manual gateway are mutually exclusive')
            old_exists = path.exists()
            old = path.read_text() if old_exists else ''
            if mode == 'auto':
                content = ('# Managed by DRM host agent; do not edit manually\n'
                           '[Network]\nIPv6AcceptRA=yes\n'
                           '\n[IPv6AcceptRA]\n'
                           f'UseAutonomousPrefix={"yes" if config["slaac"] else "no"}\n'
                           f'DHCPv6Client={"always" if config["dhcpv6"] else "no"}\n'
                           f'UseGateway={"yes" if config.get("addDefaultRoute", True) else "no"}\n'
                           f'RouteMetric={metric}\n'
                           'UseDNS=yes\n'
                           '\n[DHCPv6]\nUseDNS=yes\n')
            else:
                # Preserve the pre-existing IPv4 DHCP state when overriding dual-stack DHCP.
                base = (Path('/run/systemd/network') / f'10-netplan-{name}.network').read_text()
                match = re.search(r'^DHCP\s*=\s*(yes|true|ipv6|ipv4|no|false)\s*$',base,re.M|re.I)
                value = match.group(1).lower() if match else 'no'
                dhcp_override = ('DHCP=ipv4\n' if value in ('yes','true') else 'DHCP=no\n') if value in ('yes','true','ipv6') else ''
                content = ('# Managed by DRM host agent; do not edit manually\n'
                           '[Network]\nIPv6AcceptRA=' + ('yes' if config.get('addDefaultRoute', False) and not gateway else 'no') + '\n' + dhcp_override +
                           '' +
                           ('\n[IPv6AcceptRA]\nUseAutonomousPrefix=no\nDHCPv6Client=no\nUseGateway=yes\nUseDNS=no\n' if config.get('addDefaultRoute', False) and not gateway else '') +
                           '\n[Address]\nAddress=' + str(address) + '\n')
                if gateway:
                    content += f'\n[Route]\nDestination=::/0\nGateway={gateway}\nMetric={metric}\n'
            dns = config.get('dns', [])
            if not isinstance(dns,list) or len(dns)>8 or any(ipaddress.ip_address(x).version != 6 for x in dns):
                raise ValueError('Invalid IPv6 DNS')
            if dns:
                content += '\n[Network]\n' + ''.join(f'DNS={server}\n' for server in dns)
            static_live = mode == 'static'
            static_ra = static_live and bool(config.get('addDefaultRoute', False)) and not gateway
            if static_ra:
                ensure_ipv4_persistent_before_reconfigure(name)
            old_sysctls = {}
            previous_ipv6 = None
            if static_live:
                previous_ipv6 = ipv6_snapshot(name)
                before = json.loads(command('ip','-j','-6','addr','show','dev',name))[0].get('addr_info',[])
                existing = [x for x in before if x.get('family') == 'inet6' and x.get('local') == str(address.ip)]
                if existing and not any(x.get('dynamic') for x in existing): raise ValueError('Static IPv6 address already exists; no changes applied')
                for key in ('accept_ra', 'autoconf', 'accept_ra_defrtr'):
                    old_sysctls[key] = Path(f'/proc/sys/net/ipv6/conf/{name}/{key}').read_text().strip()
            item = {'interface':name,'old_exists':old_exists,'old':old,'expires_at':time.time()+60,'token':req.get('token'),
                    'static_live':static_live,'static_ra':static_ra,'new_address':str(address) if static_live else None,
                    'new_gateway':str(gateway) if static_live and config.get('addDefaultRoute',False) else None,
                    'old_sysctls':old_sysctls,'previous_ipv6':previous_ipv6,'old_dns':dns_snapshot(name),
                    'old_netplan_dns':None}

            # Persist backup BEFORE modifying live network settings.
            atomic(PENDING, json.dumps(item))
            try:
                # Save combined IPv4+IPv6 DNS into DRM's persistent Netplan overlay.
                # This prevents a later networkd reconfigure from replacing the
                # resolver list with IPv4-only DNS. Rollback restores the file.
                old_stored = netplan_dns(name)
                v4_dns = [x for x in old_stored if ipaddress.ip_address(x).version == 4]
                if not v4_dns and re.search(r'^DHCP=ipv4$', (Path('/run/systemd/network') / f'10-netplan-{name}.network').read_text(), re.M) is None:
                    v4_dns = [x for x in item['old_dns'] if ipaddress.ip_address(x).version == 4]
                old_netplan_text = sync_netplan_dns(name, v4_dns, dns if mode == 'static' else [])
                if old_netplan_text is not None:
                    item['old_netplan_dns'] = old_netplan_text
                    atomic(PENDING, json.dumps(item))
                atomic(path, content)
                if static_live:
                    # Avoid networkctl reconfigure: it can renew or replace IPv4 DHCP.
                    for key in ('accept_ra','autoconf','accept_ra_defrtr'):
                        Path(f'/proc/sys/net/ipv6/conf/{name}/{key}').write_text('0')
                    # Remove old dynamic IPv6 leases and old single-interface default routes.
                    # Stop rather than alter any multipath route shared with another interface.
                    for r in previous_ipv6['routes']:
                        drop_route(r,name)
                    remove_dynamic_ipv6(name,previous_ipv6['addresses'])
                    command('ip','-6','addr','replace',str(address),'dev',name)
                    if gateway:
                        command('ip','-6','route','replace','default','via',str(gateway),'dev',name,'metric',str(metric))
                    elif static_ra:
                        # systemd-networkd is the ONLY RA consumer; no kernel RA
                        # fallback (that creates the second default route at metric 1024).
                        # A reconfigure is required for networkd to adopt its new RA
                        # policy; the IPv4 persistence guard above prevents DHCP reset.
                        reload_link(name)
                        for key in ('accept_ra', 'autoconf', 'accept_ra_defrtr'):
                            Path(f'/proc/sys/net/ipv6/conf/{name}/{key}').write_text('0')
                        # Reconfigure may preserve obsolete addresses/routes.
                        now = ipv6_snapshot(name)
                        remove_dynamic_ipv6(name, now['addresses'])
                        for route in now['routes']:
                            if route.get('metric') == 1024 and route.get('protocol') == 'ra':
                                drop_route(route, name)
                else:
                    reload_link(name)
                # No resolvectl dns here: it replaces networkd's DHCPv4/RDNSS/DHCPv6
                # resolver list and can suppress subsequent automatic DNS updates.
                # Static resolvers are persisted in the .network drop-in/Netplan.
            except Exception:
                try: restore(item)
                except Exception as e: raise RuntimeError(f'Apply failed; rollback ALSO FAILED: {e}')
                raise
            return {'expiresAt':item['expires_at']}
        if op in ('confirm','rollback'):
            if not PENDING.exists(): raise RuntimeError('No pending Safe Apply')
            item = json.loads(PENDING.read_text())
            if req.get('token') != item['token']: raise RuntimeError('Invalid Safe Apply token')
            if op == 'confirm': PENDING.unlink(); return {'confirmed':True}
            restore(item)
            return {'rolledBack':True}
        raise ValueError('Unknown operation')

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline(65536)
            if not line: return
            response = {'ok':True,'result':request(json.loads(line))}
        except Exception as exc:
            response = {'ok':False,'error':str(exc)}
        self.wfile.write((json.dumps(response)+'\n').encode())

class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True

def monitor():
    while True:
        with LOCK:
            if PENDING.exists():
                try:
                    item=json.loads(PENDING.read_text())
                    if time.time() >= item['expires_at']:
                        restore(item)
                        print('Auto rollback completed:',item['interface'],flush=True)
                except Exception as exc: print('CRITICAL auto rollback failed:',exc,flush=True)
        time.sleep(2)

if __name__ == '__main__':
    STATE.mkdir(parents=True,exist_ok=True)
    SOCK.parent.mkdir(parents=True,exist_ok=True)
    SOCK.unlink(missing_ok=True)
    server=Server(str(SOCK),Handler)
    os.chmod(SOCK,0o600)
    threading.Thread(target=monitor,daemon=True).start()
    print('DRM networkd helper ready',flush=True)
    server.serve_forever()
