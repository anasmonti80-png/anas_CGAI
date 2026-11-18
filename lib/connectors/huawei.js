// CG-042 Huawei connectors. Pure converters from iMaster NCE-Campus northbound device queries and from VRP
// device output ("display version", "display current-configuration", "display lldp neighbor brief").
// Read-only; secrets in the configuration (cipher passwords, SNMP communities, keys) are never copied.
import { isIP } from 'node:net';

const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const ipOnly = v => (isIP(String(v || '')) ? String(v) : null);
const typeMap = { AR: 'router', NE: 'router', LSW: 'switch', CE: 'switch', AP: 'access-point', AC: 'access-point', FW: 'firewall', USG: 'firewall' };

// NCE-Campus: GET /controller/campus/v3/devices -> {errcode:"0", data:[{id,name,esn,mac,ip,deviceModel,deviceType,status,version}]}
// status: 0 normal, 1 alarm, 3 offline, 4 unregistered.
export function nceDevices(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.data)) throw new Error('not an NCE-Campus device query response (data[] missing)');
  if (v.errcode !== undefined && String(v.errcode) !== '0') throw new Error(`NCE-Campus returned errcode ${v.errcode}: ${short(v.errmsg, 120) || 'no message'}`);
  return v.data.filter(d => d && d.id).slice(0, 5000).map(d => {
    const status = String(d.status ?? ''), ip = ipOnly(d.ip || d.manageIp || d.ipAddress);
    return {
      asset: { external_id: `huawei-nce:${d.id}`, hostname: short(d.name, 200), os_family: 'network', device_type: typeMap[String(d.deviceType || '').toUpperCase()] || 'unknown', addresses: [ip].filter(Boolean) },
      health: { device_ref: `huawei-nce:${d.id}`, name: short(d.name, 200), ip, overall_health: null, reachability: status === '3' ? 'unreachable' : ['0', '1'].includes(status) ? 'reachable' : 'unknown', cpu_percent: null, memory_percent: null, issue_count: status === '1' ? 1 : status === '0' ? 0 : null },
      facts: { model: short(d.deviceModel, 120), version: short(d.version, 120), esn: short(d.esn, 80), status: { 0: 'normal', 1: 'alarm', 3: 'offline', 4: 'unregistered' }[status] || 'unknown' },
    };
  });
}

// VRP "display version" + "display current-configuration".
export function parseHuaweiVrp(displayVersion, currentConfig) {
  const version = displayVersion.match(/Version [\d.]+ \(([^)]+)\)/)?.[1]?.split(/\s+/).pop() || displayVersion.match(/VRP \(R\) software, Version ([\w.]+)/)?.[1] || null;
  const model = displayVersion.match(/^(?:HUAWEI|Quidway) (\S+)(?: [\w ]+)? uptime is/m)?.[1] || displayVersion.match(/Version [\d.]+ \((\S+) V\d/)?.[1] || null;
  const lines = currentConfig.split(/\r?\n/), has = re => lines.some(l => re.test(l));
  const hostname = currentConfig.match(/^ ?sysname (\S+)/m)?.[1] || null;
  const dns = [...new Set(lines.map(l => l.match(/^ ?dns server (\S+)/)?.[1]).filter(x => isIP(x || '')))];
  const ntp = [...new Set(lines.map(l => l.match(/^ ?ntp-service unicast-server (\S+)/)?.[1]).filter(x => isIP(x || '')))];
  const vpn = [];
  let peer = null;
  for (const l of lines) {
    let m = l.match(/^ike peer (\S+)/); if (m) { peer = m[1]; continue; }
    m = l.match(/^ remote-address (\S+)/); if (m && peer && isIP(m[1])) vpn.push({ name: `ike-peer-${peer}`, peer: m[1], protocol: 'ipsec' });
    if (/^\S/.test(l) && !/^ike peer/.test(l)) peer = null;
    m = l.match(/^sslvpn (?:gateway )?(\S+)/); if (m) vpn.push({ name: m[1], peer: null, protocol: 'ssl-vpn' });
  }
  const vty = []; let block = null;
  for (const l of lines) { if (/^user-interface vty/.test(l)) { block = []; vty.push(block); continue; } if (block && /^\S/.test(l)) block = null; if (block) block.push(l.trim()); }
  const inbound = new Set(); for (const b of vty) { const p = b.find(x => x.startsWith('protocol inbound'))?.split(/\s+/)[2]; for (const x of p === 'all' || !p ? ['telnet', 'ssh'] : [p]) inbound.add(x); }
  const restricted = vty.length > 0 && vty.every(b => b.some(x => /^acl (?:ipv6 )?\S+ inbound/.test(x)));
  const telnetOn = has(/^ ?telnet server enable/) && !has(/^ ?undo telnet server enable/), sshOn = has(/^ ?stelnet server enable/);
  const management = [
    { protocol: 'telnet', enabled: telnetOn && (vty.length === 0 || inbound.has('telnet')), exposed_to: 'unknown', restricted_sources: restricted },
    { protocol: 'ssh', enabled: sshOn && (vty.length === 0 || inbound.has('ssh')), exposed_to: 'unknown', restricted_sources: restricted },
    { protocol: 'http', enabled: has(/^ ?http server enable/), exposed_to: 'unknown', restricted_sources: has(/^ ?http (?:server )?acl /) },
    { protocol: 'https', enabled: has(/^ ?http secure-server enable/), exposed_to: 'unknown', restricted_sources: has(/^ ?http (?:server )?acl /) },
    { protocol: 'snmpv2c', enabled: has(/^ ?snmp-agent sys-info version .*v2c/) || has(/^ ?snmp-agent community /), exposed_to: 'unknown', restricted_sources: lines.filter(l => /^ ?snmp-agent community /.test(l)).every(l => /\sacl \S+/.test(l)) && has(/^ ?snmp-agent community /) },
    { protocol: 'snmpv3', enabled: has(/^ ?snmp-agent sys-info version .*v3/), exposed_to: 'unknown', restricted_sources: false },
  ];
  return { vendor: 'huawei', model, hostname, firmware_version: version, dns_servers: dns, ntp_servers: ntp, vpn_profiles: vpn, management };
}

// VRP "display lldp neighbor brief": both column orders seen across versions.
export function vrpLldp(text, localName) {
  const lines = String(text).split(/\r?\n/), header = lines.findIndex(l => /Local\s+Intf|Local\s+Interface/i.test(l) && /Neighbor/i.test(l));
  if (header < 0) throw new Error('not a "display lldp neighbor brief" output (header missing)');
  const deviceFirst = /Local\s+Intf\s+Neighbor\s+Dev/i.test(lines[header]);
  const rows = lines.slice(header + 1).map(l => l.trim()).filter(l => l && !/^-+$/.test(l)).map(l => l.split(/\s+/)).filter(c => c.length >= 4);
  const neighbors = rows.map(c => (deviceFirst ? { local_port: c[0], device: c[1], remote_port: c[2] } : { local_port: c[0], remote_port: c[2], device: c.slice(3).join(' ') }));
  const id = name => `vrp:${String(name).toLowerCase()}`;
  const nodes = [{ node_id: id(localName), label: short(localName, 200), ip: null, device_type: 'switch', platform: null }, ...[...new Set(neighbors.map(n => n.device))].map(d => ({ node_id: id(d), label: short(d, 200), ip: null, device_type: 'unknown', platform: null }))];
  return { nodes, links: neighbors.map(n => ({ source: id(localName), target: id(n.device), source_port: short(n.local_port, 120), target_port: short(n.remote_port, 120), status: 'up' })) };
}
