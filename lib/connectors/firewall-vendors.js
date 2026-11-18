// CG-043 multi-vendor firewall policy converters into the CG-020 firewall.ruleset rule shape.
// Inputs are the vendors' documented read outputs: PAN-OS REST SecurityRules, FortiOS REST cmdb/firewall/policy,
// MikroTik RouterOS REST ip/firewall/filter, OPNsense filter searchRule, Junos "display set" security policies and
// Linux "iptables-save". Named objects whose values are not in the input are reported as unreadable, never guessed.
import { isIP } from 'node:net';

const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const isCidr = v => { const [a, b, ...r] = String(v).split('/'); return !r.length && isIP(a) !== 0 && (b === undefined || /^\d{1,3}$/.test(b)); };
const isPort = v => /^\d{1,5}(-\d{1,5})?$/.test(String(v));
// Address list: 'any' aliases resolve to any; literals are kept; anything else is a named object.
function addresses(list, anyNames = ['any', 'all', '0.0.0.0/0']) {
  const items = (Array.isArray(list) ? list : [list]).filter(x => x !== undefined && x !== null && x !== '').map(String);
  if (!items.length || items.some(x => anyNames.includes(x.toLowerCase()))) return { values: ['any'], readable: true };
  const literals = items.filter(isCidr).map(x => (x.includes('/') ? x : x)), named = items.filter(x => !isCidr(x));
  return { values: literals.length ? literals : ['any'], readable: named.length === 0 };
}
function rule(base) {
  return { rule_id: short(base.id, 300), name: short(base.name, 300) || short(base.id, 300), position: base.position, enabled: base.enabled, direction: base.direction || 'in', action: base.action, protocol: base.protocol || 'any', src: base.src.values, dst: base.dst.values, src_ports: ['any'], dst_ports: base.ports?.values || ['any'], application: short(base.application, 300), profile: short(base.profile, 120), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, filters_readable: base.src.readable && base.dst.readable && (base.ports?.readable ?? true) && (base.extraReadable ?? true), scope_constraints: (base.scope || []).map(x => short(x, 120)).filter(Boolean).slice(0, 20) };
}
const summary = (vendor, rules) => ({ vendor, rules, unreadable: rules.filter(r => !r.filters_readable).length });
// Well-known service names shared by the vendors' predefined service objects.
const wellKnown = { http: ['tcp', '80'], https: ['tcp', '443'], ssh: ['tcp', '22'], telnet: ['tcp', '23'], rdp: ['tcp', '3389'], dns: ['udp', '53'], smb: ['tcp', '445'], ftp: ['tcp', '21'], smtp: ['tcp', '25'], snmp: ['udp', '161'], ntp: ['udp', '123'], ldap: ['tcp', '389'], 'ms-rdp': ['tcp', '3389'] };

// PAN-OS: GET /restapi/v10.x/Policies/SecurityRules?location=vsys&vsys=vsys1
export function panosRules(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json, entries = v?.result?.entry;
  if (v?.['@status'] !== 'success' || !Array.isArray(entries)) throw new Error('not a PAN-OS SecurityRules response (@status success and result.entry[] required)');
  return summary('palo-alto', entries.slice(0, 5000).map((e, i) => {
    const members = x => x?.member || [], services = members(e.service), apps = members(e.application);
    const resolved = services.map(s => (s === 'any' ? ['any', 'any'] : s === 'application-default' ? null : s.startsWith('service-') ? wellKnown[s.slice(8)] || null : null));
    const ports = services.includes('any') || (services.includes('application-default') && apps.includes('any')) ? { values: ['any'], readable: true } : { values: resolved.filter(Boolean).map(r => r[1]).filter(isPort).length ? resolved.filter(Boolean).map(r => r[1]) : ['any'], readable: resolved.every(Boolean) };
    return rule({ id: e['@uuid'] || e['@name'], name: e['@name'], position: i + 1, enabled: e.disabled !== 'yes', action: e.action === 'allow' ? 'allow' : 'deny', protocol: resolved.filter(Boolean).map(r => r[0]).filter(p => p !== 'any').length === resolved.length && resolved.length ? resolved[0][0] : 'any', src: addresses(members(e.source)), dst: addresses(members(e.destination)), ports, application: apps.includes('any') ? null : apps.join(','), scope: [...members(e.from).map(z => `src-zone:${z}`), ...members(e.to).map(z => `dst-zone:${z}`), ...(apps.length && !apps.includes('any') ? ['application-filter'] : []), ...(members(e['source-user']).some(u => u !== 'any') ? ['user-identity'] : [])] });
  }));
}

// FortiOS: GET /api/v2/cmdb/firewall/policy
export function fortiosPolicies(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.results)) throw new Error('not a FortiOS firewall/policy response (results[] missing)');
  const names = list => (list || []).map(x => x.name);
  return summary('fortigate', v.results.slice(0, 5000).map((p, i) => {
    const svc = names(p.service), resolved = svc.map(s => (s.toUpperCase() === 'ALL' ? ['any', 'any'] : wellKnown[s.toLowerCase()] || null));
    const ports = svc.some(s => s.toUpperCase() === 'ALL') ? { values: ['any'], readable: true } : { values: resolved.filter(Boolean).map(r => r[1]).length ? resolved.filter(Boolean).map(r => r[1]) : ['any'], readable: resolved.every(Boolean) };
    return rule({ id: `policy-${p.policyid}`, name: p.name || `policy ${p.policyid}`, position: i + 1, enabled: p.status !== 'disable', action: p.action === 'accept' ? 'allow' : 'deny', protocol: resolved.length && resolved.every(r => r && r[0] === resolved[0]?.[0]) ? resolved[0][0] : 'any', src: addresses(names(p.srcaddr)), dst: addresses(names(p.dstaddr)), ports, scope: [...names(p.srcintf).map(x => `src-intf:${x}`), ...names(p.dstintf).map(x => `dst-intf:${x}`), ...(names(p.users).length || names(p.groups).length ? ['user-identity'] : [])] });
  }));
}

// MikroTik RouterOS v7 REST: GET /rest/ip/firewall/filter
export function mikrotikFilter(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!Array.isArray(v)) throw new Error('not a RouterOS ip/firewall/filter response (array expected)');
  return summary('mikrotik', v.filter(r => ['input', 'forward', 'output'].includes(r.chain)).slice(0, 5000).map((r, i) => {
    const port = r['dst-port'] ? String(r['dst-port']).split(',') : ['any'];
    return rule({ id: r['.id'] || `rule-${i + 1}`, name: r.comment || `${r.chain} ${r.action} ${r['.id'] || i + 1}`, position: i + 1, enabled: String(r.disabled) !== 'true', direction: r.chain === 'output' ? 'out' : 'in', action: ['accept', 'passthrough'].includes(r.action) ? 'allow' : 'deny', protocol: r.protocol || 'any', src: r['src-address-list'] ? { values: ['any'], readable: false } : addresses(r['src-address'] ? String(r['src-address']).replace(/^!/, '') : 'any'), dst: r['dst-address-list'] ? { values: ['any'], readable: false } : addresses(r['dst-address'] ? String(r['dst-address']).replace(/^!/, '') : 'any'), ports: { values: port, readable: port.every(p => p === 'any' || isPort(p)) }, extraReadable: !String(r['src-address'] || '').startsWith('!') && !String(r['dst-address'] || '').startsWith('!'), scope: [`chain:${r.chain}`, ...(r['in-interface'] ? [`in-interface:${r['in-interface']}`] : []), ...(r['connection-state'] ? [`state:${r['connection-state']}`] : [])] });
  }).filter(x => x.action === 'deny' || x.action === 'allow'));
}

// OPNsense: GET /api/firewall/filter/searchRule
export function opnsenseRules(json) {
  const v = typeof json === 'string' ? JSON.parse(json) : json;
  if (!v || !Array.isArray(v.rows)) throw new Error('not an OPNsense searchRule response (rows[] missing)');
  return summary('opnsense', v.rows.slice(0, 5000).map((r, i) => {
    const port = r.destination_port ? String(r.destination_port).split(',') : ['any'];
    return rule({ id: r.uuid, name: r.description || r.uuid, position: Number(r.sequence) || i + 1, enabled: String(r.enabled) === '1', direction: r.direction === 'out' ? 'out' : 'in', action: r.action === 'pass' ? 'allow' : 'deny', protocol: String(r.protocol || 'any').toLowerCase(), src: addresses(r.source_net || 'any'), dst: addresses(r.destination_net || 'any'), ports: { values: port, readable: port.every(p => p === 'any' || isPort(p)) }, extraReadable: String(r.source_not) !== '1' && String(r.destination_not) !== '1', scope: r.interface ? [`interface:${r.interface}`] : [] });
  }));
}

// Junos: "show configuration security policies | display set"
export function junosSetPolicies(text) {
  const lines = String(text).split(/\r?\n/).map(l => l.trim()).filter(l => l.startsWith('set security policies '));
  if (!lines.length) throw new Error('not a Junos "display set" security policies output');
  const policies = new Map();
  for (const l of lines) {
    const m = l.match(/^set security policies (?:from-zone (\S+) to-zone (\S+)|global) policy (\S+) (.+)$/); if (!m) continue;
    const key = `${m[1] || 'global'}>${m[2] || 'global'}:${m[3]}`, p = policies.get(key) || { from: m[1] || 'global', to: m[2] || 'global', name: m[3], src: [], dst: [], apps: [], action: null, inactive: false };
    const rest = m[4], match = rest.match(/^match (source-address|destination-address|application) (\S+)/);
    if (match) p[{ 'source-address': 'src', 'destination-address': 'dst', application: 'apps' }[match[1]]].push(match[2]);
    const then = rest.match(/^then (permit|deny|reject)/); if (then) p.action = then[1];
    policies.set(key, p);
  }
  const junosApp = { 'junos-ssh': wellKnown.ssh, 'junos-http': wellKnown.http, 'junos-https': wellKnown.https, 'junos-telnet': wellKnown.telnet, 'junos-dns-udp': wellKnown.dns, 'junos-smb': wellKnown.smb, 'junos-ftp': wellKnown.ftp, 'junos-ms-rdp': wellKnown.rdp, 'junos-ntp': wellKnown.ntp };
  return summary('juniper-srx', [...policies.values()].filter(p => p.action).slice(0, 5000).map((p, i) => {
    const resolved = p.apps.map(a => (a === 'any' ? ['any', 'any'] : junosApp[a] || null));
    return rule({ id: `${p.from}>${p.to}:${p.name}`, name: p.name, position: i + 1, enabled: true, action: p.action === 'permit' ? 'allow' : 'deny', protocol: resolved.length && resolved.every(r => r && r[0] === resolved[0]?.[0]) ? resolved[0][0] : 'any', src: addresses(p.src), dst: addresses(p.dst), ports: p.apps.includes('any') || !p.apps.length ? { values: ['any'], readable: true } : { values: resolved.filter(Boolean).map(r => r[1]).length ? resolved.filter(Boolean).map(r => r[1]) : ['any'], readable: resolved.every(Boolean) }, scope: [`src-zone:${p.from}`, `dst-zone:${p.to}`] });
  }));
}

// Linux: "iptables-save" (filter table INPUT and FORWARD chains; policy lines become final rules).
export function iptablesSave(text) {
  const lines = String(text).split(/\r?\n/); let table = null, n = 0; const rules = [];
  if (!lines.some(l => l.startsWith('*filter'))) throw new Error('not an iptables-save output with a *filter table');
  const policies = {};
  for (const l of lines) {
    if (l.startsWith('*')) { table = l.slice(1).trim(); continue; }
    if (table !== 'filter') continue;
    const pol = l.match(/^:(INPUT|FORWARD|OUTPUT) (ACCEPT|DROP)/); if (pol) { policies[pol[1]] = pol[2]; continue; }
    const m = l.match(/^-A (INPUT|FORWARD|OUTPUT) (.*)$/); if (!m) continue;
    const opt = (re) => m[2].match(re)?.[1], target = opt(/-j (\S+)/);
    if (!['ACCEPT', 'DROP', 'REJECT'].includes(target)) continue;
    const dport = opt(/--dports? (\S+)/), src = opt(/(?:^| )-s (\S+)/), dst = opt(/(?:^| )-d (\S+)/), negated = /(^| )! -[sd] /.test(m[2]);
    const ports = dport ? dport.replace(/:/g, '-').split(',') : ['any'];
    rules.push(rule({ id: `${m[1]}-${++n}`, name: `${m[1]} ${target}${dport ? ` ${dport}` : ''}`, position: n, enabled: true, direction: m[1] === 'OUTPUT' ? 'out' : 'in', action: target === 'ACCEPT' ? 'allow' : 'deny', protocol: opt(/-p (\S+)/) || 'any', src: addresses(src || 'any'), dst: addresses(dst || 'any'), ports: { values: ports, readable: ports.every(isPort) }, extraReadable: !negated && !/--match-set|-m set /.test(m[2]), scope: [`chain:${m[1]}`, ...(opt(/-i (\S+)/) ? [`in-interface:${opt(/-i (\S+)/)}`] : []), ...(/--(c)?state /.test(m[2]) ? ['connection-state'] : [])] }));
  }
  for (const [chain, policy] of Object.entries(policies)) if (chain !== 'OUTPUT') rules.push(rule({ id: `${chain}-policy`, name: `${chain} default policy ${policy}`, position: ++n, enabled: true, action: policy === 'ACCEPT' ? 'allow' : 'deny', src: { values: ['any'], readable: true }, dst: { values: ['any'], readable: true }, scope: [`chain:${chain}`, 'default-policy'] }));
  return summary('iptables', rules);
}
