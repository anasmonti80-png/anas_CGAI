// CG-021 network-device configuration parsing and monitoring: firmware version, DNS, VPN and
// management-plane exposure, plus change detection between snapshots of the same device.
const insecure = new Set(['telnet', 'http', 'snmpv1', 'snmpv2c']);

// Parse Cisco IOS / IOS-XE "show version" and "show running-config" text exactly as the device prints it.
export function parseCiscoIos(showVersion, runningConfig) {
  const version = showVersion.match(/Cisco IOS(?: XE)? Software.*?Version ([\w.()]+)/i)?.[1] || showVersion.match(/^Version ([\w.()]+)/m)?.[1] || null;
  const model = showVersion.match(/^[Cc]isco (\S+) \(.*?\) processor/m)?.[1] || showVersion.match(/^Model [Nn]umber\s*:\s*(\S+)/m)?.[1] || null;
  const hostname = runningConfig.match(/^hostname (\S+)/m)?.[1] || null;
  const lines = runningConfig.split(/\r?\n/);
  const dns = [...new Set(lines.flatMap(l => (l.match(/^ip name-server (?:vrf \S+ )?(.+)$/) || [, ''])[1].split(/\s+/).filter(Boolean)))];
  const ntp = [...new Set(lines.map(l => l.match(/^ntp server (?:vrf \S+ )?(\S+)/)?.[1]).filter(Boolean))];
  const vpn = [];
  for (const l of lines) {
    let m = l.match(/^crypto isakmp key \S+ address (\S+)/); if (m) vpn.push({ name: `isakmp-${m[1]}`, peer: m[1], protocol: 'ipsec-ikev1' });
    m = l.match(/^\s*set peer (\S+)/); if (m) vpn.push({ name: `crypto-map-${m[1]}`, peer: m[1], protocol: 'ipsec' });
    m = l.match(/^crypto ikev2 profile (\S+)/); if (m) vpn.push({ name: m[1], peer: null, protocol: 'ipsec-ikev2' });
    m = l.match(/^webvpn gateway (\S+)/); if (m) vpn.push({ name: m[1], peer: null, protocol: 'ssl-vpn' });
  }
  const vtyBlocks = []; let inVty = false, block = [];
  for (const l of lines) { if (/^line vty/.test(l)) { if (inVty) vtyBlocks.push(block); inVty = true; block = []; continue; } if (inVty && /^\S/.test(l)) { vtyBlocks.push(block); inVty = false; } if (inVty) block.push(l.trim()); }
  if (inVty) vtyBlocks.push(block);
  const transports = new Set(), restricted = vtyBlocks.length > 0 && vtyBlocks.every(b => b.some(l => /^access-class \S+ in/.test(l)));
  for (const b of vtyBlocks) { const t = b.find(l => l.startsWith('transport input')); const v = t ? t.replace('transport input', '').trim().split(/\s+/) : ['all']; for (const x of v) { if (x === 'all') { transports.add('telnet'); transports.add('ssh'); } else if (x !== 'none') transports.add(x); } }
  const management = [];
  for (const p of ['ssh', 'telnet']) management.push({ protocol: p, enabled: transports.has(p), exposed_to: 'unknown', restricted_sources: restricted });
  management.push({ protocol: 'http', enabled: lines.some(l => /^ip http server$/.test(l)), exposed_to: 'unknown', restricted_sources: lines.some(l => /^ip http access-class/.test(l)) });
  management.push({ protocol: 'https', enabled: lines.some(l => /^ip http secure-server$/.test(l)), exposed_to: 'unknown', restricted_sources: lines.some(l => /^ip http access-class/.test(l)) });
  const communities = lines.filter(l => /^snmp-server community \S+/.test(l));
  management.push({ protocol: 'snmpv2c', enabled: communities.length > 0, exposed_to: 'unknown', restricted_sources: communities.length > 0 && communities.every(l => /\s(RO|RW)\s+\S+\s*$/.test(l) || /\s\d+\s*$/.test(l)) });
  management.push({ protocol: 'snmpv3', enabled: lines.some(l => /^snmp-server group \S+ v3/.test(l)), exposed_to: 'unknown', restricted_sources: false });
  return { vendor: 'cisco', model, hostname, firmware_version: version, dns_servers: dns, ntp_servers: ntp, vpn_profiles: vpn, management };
}

const versionParts = v => String(v || '').split(/[^0-9]+/).filter(Boolean).map(Number);
export const compareVersions = (a, b) => { const x = versionParts(a), y = versionParts(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0 ? 1 : -1; } return 0; };

export function analyseDeviceConfig(current, previous, advisories = []) {
  const findings = [];
  for (const m of current.management.filter(m => m.enabled)) {
    if (insecure.has(m.protocol)) findings.push({ type: 'insecure-management-protocol', severity: m.protocol === 'telnet' || m.protocol === 'snmpv1' ? 'high' : 'medium', detail: `${m.protocol} enabled` });
    if (['external', 'any'].includes(m.exposed_to) && !m.restricted_sources) findings.push({ type: 'management-exposed', severity: 'high', detail: `${m.protocol} reachable from ${m.exposed_to} without source restriction` });
  }
  const norm = s => String(s || '').toLowerCase();
  for (const a of advisories) {
    if (norm(a.vendor) && norm(a.vendor) !== norm(current.vendor)) continue;
    if (norm(a.product) !== norm(current.model) && norm(a.product) !== norm(current.vendor)) continue;
    const v = current.firmware_version; if (!v) continue;
    const inRange = (!a.affected.min_version || compareVersions(v, a.affected.min_version) >= 0) && (!a.affected.max_version_exclusive || compareVersions(v, a.affected.max_version_exclusive) < 0);
    if (inRange) findings.push({ type: 'firmware-vulnerable', severity: a.kev ? 'critical' : (a.cvss ?? 0) >= 7 ? 'high' : 'medium', detail: `${a.vuln_id} affects ${current.firmware_version}${a.fixed_version ? `; fixed in ${a.fixed_version}` : ''}` });
  }
  const changes = [];
  if (previous) {
    const set = x => JSON.stringify([...(x || [])].sort());
    if (set(previous.dns_servers) !== set(current.dns_servers)) changes.push({ type: 'dns-changed', severity: 'high', before: previous.dns_servers, after: current.dns_servers });
    const vpnKey = p => `${p.protocol}|${p.name}|${p.peer || ''}`;
    if (set(previous.vpn_profiles.map(vpnKey)) !== set(current.vpn_profiles.map(vpnKey))) changes.push({ type: 'vpn-changed', severity: 'medium', before: previous.vpn_profiles.map(vpnKey), after: current.vpn_profiles.map(vpnKey) });
    const mgmt = list => list.filter(m => m.enabled).map(m => `${m.protocol}@${m.exposed_to}${m.restricted_sources ? '/restricted' : ''}`);
    if (set(mgmt(previous.management)) !== set(mgmt(current.management))) {
      const newlyOpen = current.management.filter(m => m.enabled && !previous.management.some(p => p.protocol === m.protocol && p.enabled && p.exposed_to === m.exposed_to));
      changes.push({ type: 'management-changed', severity: newlyOpen.some(m => ['external', 'any'].includes(m.exposed_to) || insecure.has(m.protocol)) ? 'high' : 'medium', before: mgmt(previous.management), after: mgmt(current.management) });
    }
    if (previous.firmware_version && current.firmware_version && previous.firmware_version !== current.firmware_version) {
      const cmp = compareVersions(current.firmware_version, previous.firmware_version);
      changes.push({ type: cmp < 0 ? 'firmware-downgraded' : 'firmware-upgraded', severity: cmp < 0 ? 'high' : 'info', before: previous.firmware_version, after: current.firmware_version });
    }
  }
  return { findings, changes };
}
