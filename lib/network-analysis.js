// CG-019 network analysis over normalised records (flows, firewall, IDS, DNS, VPN):
// device-to-device connections, Internet exposure, unusual DNS and lateral-movement indicators.
const privateIp = ip => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|f[cd][0-9a-f]{2}:)/i.test(ip || '');
const adminPorts = new Map([[22, 'SSH'], [23, 'Telnet'], [135, 'RPC'], [139, 'NetBIOS'], [445, 'SMB'], [3389, 'RDP'], [5900, 'VNC'], [5985, 'WinRM'], [5986, 'WinRM-TLS']]);
const entropy = value => { const counts = {}; for (const c of value) counts[c] = (counts[c] || 0) + 1; return -Object.values(counts).reduce((sum, n) => sum + (n / value.length) * Math.log2(n / value.length), 0); };
const parentDomain = name => name.split('.').slice(-2).join('.');

export function analyseNetwork(records) {
  const pairs = new Map(), exposures = new Map(), fanout = new Map(), dnsFindings = [], subdomains = new Map();
  for (const r of records) {
    if (r.src_ip && r.dst_ip && ['flow', 'firewall', 'ids', 'vpn'].includes(r.category)) {
      const zone = `${privateIp(r.src_ip) ? 'internal' : 'external'}->${privateIp(r.dst_ip) ? 'internal' : 'external'}`, key = `${r.src_ip}|${r.dst_ip}`;
      const pair = pairs.get(key) || { src_ip: r.src_ip, dst_ip: r.dst_ip, zone, ports: new Set(), events: 0, bytes: 0, blocked: 0, first: r.time, last: r.time };
      pair.events++; pair.bytes += r.bytes || 0; if (r.dst_port !== null) pair.ports.add(r.dst_port); if (r.action === 'blocked') pair.blocked++; if (r.time < pair.first) pair.first = r.time; if (r.time > pair.last) pair.last = r.time; pairs.set(key, pair);
      if (zone === 'external->internal' && r.action !== 'blocked' && r.dst_port !== null) {
        const ek = `${r.dst_ip}|${r.dst_port}`, ex = exposures.get(ek) || { internal_ip: r.dst_ip, port: r.dst_port, service: adminPorts.get(r.dst_port) || null, sources: new Set(), events: 0 };
        ex.sources.add(r.src_ip); ex.events++; exposures.set(ek, ex);
      }
      if (zone === 'internal->internal' && adminPorts.has(r.dst_port) && r.action !== 'blocked') {
        const f = fanout.get(r.src_ip) || { src_ip: r.src_ip, targets: new Set(), ports: new Set(), first: r.time, last: r.time };
        f.targets.add(r.dst_ip); f.ports.add(r.dst_port); if (r.time < f.first) f.first = r.time; if (r.time > f.last) f.last = r.time; fanout.set(r.src_ip, f);
      }
    }
    if (r.category === 'dns' && r.query) {
      const name = r.query.toLowerCase().replace(/\.$/, ''), labels = name.split('.'), first = labels[0] || '', parent = parentDomain(name);
      const reasons = [];
      if (first.length >= 20 && entropy(first) >= 3.5) reasons.push('random-looking-label');
      if (name.length > 100 || labels.some(l => l.length > 50)) reasons.push('very-long-name');
      if (r.outcome === 'TXT' || r.outcome === 'NULL') reasons.push(`${r.outcome.toLowerCase()}-query`);
      if (reasons.length) dnsFindings.push({ query: name, client_ip: r.src_ip, reasons, time: r.time });
      if (labels.length > 2) { const set = subdomains.get(parent) || new Set(); set.add(labels.slice(0, -2).join('.')); subdomains.set(parent, set); }
    }
  }
  for (const [parent, set] of subdomains) if (set.size >= 30) dnsFindings.push({ query: parent, client_ip: null, reasons: [`many-unique-subdomains:${set.size}`], time: null });
  const lateral = [...fanout.values()].filter(f => f.targets.size >= 5).map(f => ({ src_ip: f.src_ip, targets: f.targets.size, ports: [...f.ports].map(p => `${p}/${adminPorts.get(p)}`), first: f.first, last: f.last, severity: f.targets.size >= 20 ? 'high' : 'medium' }));
  const exposure = [...exposures.values()].map(e => ({ internal_ip: e.internal_ip, port: e.port, service: e.service, external_sources: e.sources.size, events: e.events, severity: e.service ? 'high' : 'medium' })).sort((a, b) => (a.severity === 'high' ? -1 : 1) - (b.severity === 'high' ? -1 : 1) || b.external_sources - a.external_sources);
  const connections = [...pairs.values()].map(p => ({ ...p, ports: [...p.ports].sort((a, b) => a - b).slice(0, 20) })).sort((a, b) => b.events - a.events);
  const zones = {}; for (const c of connections) zones[c.zone] = (zones[c.zone] || 0) + 1;
  return { connections, zones, exposure, unusual_dns: dnsFindings, lateral_movement: lateral };
}
