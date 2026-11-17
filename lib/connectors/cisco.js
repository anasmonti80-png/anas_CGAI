// CG-041 Cisco connectors. Pure converters from the documented API responses of Catalyst Center (Intent API),
// Secure Firewall Management Center (FMC REST), Identity Services Engine (ERS ANC) and IOS XE RESTCONF into
// cg.telemetry/1 events. Read-only: the converters never call a device. Unresolved values are reported, not guessed.
import { isIP } from 'node:net';

const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const ipOnly = v => (isIP(String(v || '')) ? String(v) : null);

// Catalyst Center family/role -> CyberGuard device type.
export function catalystDeviceType(device) {
  const family = String(device.family || '').toLowerCase(), role = String(device.role || '').toLowerCase();
  if (family.includes('wireless controller')) return 'access-point';
  if (family.includes('unified ap') || family.includes('access point')) return 'access-point';
  if (family.includes('router') || role === 'border router') return 'router';
  if (family.includes('switch')) return 'switch';
  if (family.includes('firewall') || family.includes('security')) return 'firewall';
  return 'unknown';
}

// GET /dna/intent/api/v1/network-device
export function catalystInventory(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.response)) throw new Error('not a Catalyst Center network-device response (response[] missing)');
  return v.response.filter(d => d && d.id).map(d => ({
    asset: { external_id: `cisco-catalyst:${d.id}`, hostname: short(d.hostname, 200), os_family: 'network', device_type: catalystDeviceType(d), addresses: [ipOnly(d.managementIpAddress)].filter(Boolean) },
    facts: { platform: short(d.platformId, 120), software_type: short(d.softwareType, 40), software_version: short(d.softwareVersion, 60), serial: short(d.serialNumber, 80), role: short(d.role, 60), reachability: short(d.reachabilityStatus, 40), last_updated: short(d.lastUpdated, 60) },
  }));
}

// GET /dna/intent/api/v1/topology/physical-topology
export function catalystTopology(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json, t = v?.response;
  if (!t || !Array.isArray(t.nodes) || !Array.isArray(t.links)) throw new Error('not a Catalyst Center physical-topology response (response.nodes/links missing)');
  const nodes = t.nodes.filter(n => n && n.id).slice(0, 2000).map(n => ({ node_id: short(n.id, 120), label: short(n.label || n.hostname, 200), ip: ipOnly(n.ip), device_type: catalystDeviceType({ family: n.family || n.deviceType, role: n.role }), platform: short(n.platformId, 120) }));
  const ids = new Set(nodes.map(n => n.node_id));
  const links = t.links.filter(l => l && ids.has(l.source) && ids.has(l.target)).slice(0, 5000).map(l => ({ source: short(l.source, 120), target: short(l.target, 120), source_port: short(l.startPortName, 120), target_port: short(l.endPortName, 120), status: ['up', 'down'].includes(String(l.linkStatus).toLowerCase()) ? String(l.linkStatus).toLowerCase() : 'unknown' }));
  return { nodes, links, dropped_links: t.links.length - links.length };
}

// GET /dna/intent/api/v1/device-health
export function catalystHealth(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.response)) throw new Error('not a Catalyst Center device-health response (response[] missing)');
  const score = x => (Number.isFinite(Number(x)) && Number(x) >= 0 && Number(x) <= 10 ? Number(x) : null), pct = x => (Number.isFinite(Number(x)) && Number(x) >= 0 && Number(x) <= 100 ? Number(x) : null);
  return v.response.filter(d => d && (d.uuid || d.name)).slice(0, 5000).map(d => ({ device_ref: d.uuid ? `cisco-catalyst:${d.uuid}` : null, name: short(d.name, 200), ip: ipOnly(d.ipAddress), overall_health: score(d.overallHealth), reachability: String(d.reachabilityHealth || '').toUpperCase() === 'REACHABLE' ? 'reachable' : d.reachabilityHealth ? 'unreachable' : 'unknown', cpu_percent: pct(d.cpuUtilization ?? d.cpuUlitilization), memory_percent: pct(d.memoryUtilization), issue_count: Number.isInteger(d.issueCount) ? d.issueCount : null }));
}

// FMC: GET /api/fmc_config/v1/domain/{domain}/policy/accesspolicies/{policy}/accessrules?expanded=true
const protoName = p => ({ '6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6' })[String(p)] || (p ? String(p).toLowerCase() : 'any');
export function fmcAccessRules(json, { policyName = 'access-policy' } = {}) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.items)) throw new Error('not an FMC accessrules response (items[] missing)');
  const networks = side => {
    if (!side) return { values: ['any'], readable: true };
    const literals = (side.literals || []).map(l => String(l.value || '')).filter(x => x && x.split('/')[0] && isIP(x.split('/')[0]));
    const objects = (side.objects || []).map(o => (o.value && isIP(String(o.value).split('/')[0]) ? String(o.value) : null));
    // Objects without a resolved value (named objects, groups) cannot be evaluated: report them, never guess.
    return { values: [...literals, ...objects.filter(Boolean)], readable: objects.every(Boolean) };
  };
  const ports = side => {
    if (!side) return { protocol: 'any', values: ['any'], readable: true };
    const all = [...(side.literals || []), ...(side.objects || [])].map(p => ({ protocol: protoName(p.protocol), port: p.port ? String(p.port) : null }));
    const resolved = all.filter(p => p.port && /^\d{1,5}(-\d{1,5})?$/.test(p.port));
    const protocols = [...new Set(all.map(p => p.protocol))];
    return { protocol: protocols.length === 1 ? protocols[0] : 'any', values: resolved.length ? resolved.map(p => p.port) : ['any'], readable: resolved.length === all.length };
  };
  const rules = v.items.slice(0, 5000).map((r, i) => {
    const src = networks(r.sourceNetworks), dst = networks(r.destinationNetworks), dp = ports(r.destinationPorts), action = String(r.action || '').toUpperCase();
    const scope = [...(r.sourceZones?.objects || []).map(z => `src-zone:${z.name}`), ...(r.destinationZones?.objects || []).map(z => `dst-zone:${z.name}`), ...(r.applications ? ['application-filter'] : []), ...(r.users ? ['user-identity'] : [])].map(x => short(x, 120)).slice(0, 20);
    return { rule_id: short(r.id || `rule-${i + 1}`, 300), name: short(r.name, 300) || `rule-${i + 1}`, position: i + 1, enabled: r.enabled !== false, direction: 'in', action: ['ALLOW', 'TRUST'].includes(action) ? 'allow' : 'deny', protocol: dp.protocol, src: src.values.length ? src.values : ['any'], dst: dst.values.length ? dst.values : ['any'], src_ports: ['any'], dst_ports: dp.values, application: null, profile: short(policyName, 120), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: src.readable && dst.readable && dp.readable, scope_constraints: scope };
  });
  return { rules, unreadable: rules.filter(r => !r.filters_readable).length, monitor_only: v.items.filter(r => String(r.action).toUpperCase() === 'MONITOR').length };
}

// IOS XE RESTCONF: GET /restconf/data/Cisco-IOS-XE-native:native
export function iosxeNative(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json, n = v?.['Cisco-IOS-XE-native:native'];
  if (!n) throw new Error('not an IOS XE RESTCONF native response (Cisco-IOS-XE-native:native missing)');
  const dns = [...new Set([...(n.ip?.['name-server']?.['no-vrf'] || []), ...(Array.isArray(n.ip?.['name-server']) ? n.ip['name-server'] : [])].map(String).filter(x => isIP(x)))];
  const ntp = (n.ntp?.['Cisco-IOS-XE-ntp:server']?.['server-list'] || []).map(s => String(s['ip-address'] || '')).filter(x => isIP(x));
  // VTY lines: transport input protocols, restricted when every line carries an access-class ("acccess-list" is the YANG spelling).
  const vty = n.line?.vty || [], restrictedVty = vty.length > 0 && vty.every(line => line['access-class']), protocols = new Map();
  for (const line of vty) { const input = line.transport?.input?.input || line.transport?.input || []; for (const proto of (Array.isArray(input) ? input : [input])) if (['telnet', 'ssh', 'all'].includes(String(proto))) for (const p of proto === 'all' ? ['telnet', 'ssh'] : [String(proto)]) protocols.set(p, restrictedVty); }
  const enabled = v => v === true || v === '' || (Array.isArray(v) && v.length > 0);
  if (enabled(n.ip?.http?.server)) protocols.set('http', Boolean(n.ip?.http?.['access-class']));
  if (enabled(n.ip?.http?.['secure-server'])) protocols.set('https', Boolean(n.ip?.http?.['access-class']));
  const snmp = n['snmp-server'] || {}; if (snmp['Cisco-IOS-XE-snmp:community'] || snmp.community) protocols.set('snmpv2c', (snmp['Cisco-IOS-XE-snmp:community'] || snmp.community || []).every?.(c => c['access-list-name'] || c.acl) || false);
  const management = [...protocols].map(([protocol, restricted_sources]) => ({ protocol, enabled: true, exposed_to: 'unknown', restricted_sources }));
  return { hostname: short(n.hostname, 200), firmware_version: short(n.version, 60), dns_servers: dns, ntp_servers: ntp, management };
}

// ISE ERS ANC request bodies for the governed response connector. The connector sends these only for an
// approved CyberGuard job; CyberGuard itself never calls ISE.
export function iseAncRequest(phase, target) {
  const mac = String(target.mac || '').toUpperCase();
  if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)) throw new Error('invalid MAC address');
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(String(target.policy_name || ''))) throw new Error('invalid ANC policy name');
  return { method: 'PUT', path: phase === 'execute' ? '/ers/config/ancendpoint/apply' : '/ers/config/ancendpoint/clear', body: { OperationAdditionalData: { additionalData: [{ name: 'macAddress', value: mac }, { name: 'policyName', value: target.policy_name }] } } };
}
