// CG-131 Network change safety. Before an ACL, firewall or route change, the required flows (application dependencies)
// are evaluated against the current configuration snapshots and against the proposed one: which flows break, which open,
// and which paths move to another next hop. Rules whose behaviour this engine cannot model (application or user based
// rules, unreadable filters, scope constraints) and IPv6 routes are reported as unsupported and any flow they could
// touch gets the verdict "unknown", which blocks a "safe" decision. This is configuration analysis, not a guarantee of
// how the live network will behave. Batfish was researched as an external analyzer (see docs/research/register.json R-019).
import { randomUUID } from 'node:crypto';
import { evaluate } from './firewall-analyzer.js';
import { fail, text, choice, integer } from './common.js';

const ip4 = s => { const p = String(s).split('.').map(Number); return p.length === 4 && p.every(n => Number.isInteger(n) && n >= 0 && n <= 255) ? ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0 : null; };
const cidr = c => { const [a, b] = String(c).split('/'), base = ip4(a), len = b === undefined ? 32 : Number(b); if (base === null || !(len >= 0 && len <= 32)) return null; const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; return { net: (base & mask) >>> 0, mask, len }; };
const inCidr = (ip, c) => { const x = ip4(ip), r = c === 'any' || c === '0.0.0.0/0' ? { net: 0, mask: 0 } : cidr(c); return x !== null && r && ((x & r.mask) >>> 0) === r.net; };
const covers = (list, ip) => (list || []).some(v => v === 'any' || inCidr(ip, v.includes('/') ? v : `${v}/32`));
const portOk = (ports, port) => (ports || ['any']).some(p => p === 'any' || String(p) === String(port) || (/^\d+-\d+$/.test(p) && port >= Number(p.split('-')[0]) && port <= Number(p.split('-')[1])));
export const unsupportedRule = r => r.enabled && (Boolean(r.application) || r.filters_readable === false || (r.scope_constraints || []).length > 0);

export function verdict(ruleset, flow) {
  const f = { direction: flow.direction || 'in', protocol: flow.protocol, src: flow.src_ip, dst: flow.dst_ip, port: flow.port };
  const e = evaluate(ruleset, f), matchedPos = e.rule_id ? ruleset.rules.find(r => r.rule_id === e.rule_id).position : Infinity;
  const shadowing = ruleset.rules.filter(r => unsupportedRule(r) && (ruleset.evaluation === 'deny-overrides' || r.position < matchedPos) && (r.direction === f.direction || r.direction === 'any') && (r.protocol === 'any' || r.protocol === f.protocol) && covers(r.src, f.src) && covers(r.dst, f.dst) && portOk(r.dst_ports, f.port));
  return shadowing.length ? { action: 'unknown', rule_id: e.rule_id, unsupported_rules: shadowing.map(r => r.rule_id) } : { action: e.action, rule_id: e.rule_id, unsupported_rules: [] };
}
// Longest-prefix match over IPv4 routes; IPv6 routes are reported as unsupported.
export function nextHop(routes, ip) {
  const v4 = (routes || []).map(r => ({ ...r, c: cidr(r.destination) })).filter(r => r.c), m = v4.filter(r => inCidr(ip, r.destination)).sort((a, b) => b.c.len - a.c.len)[0];
  return { next_hop: m ? m.gateway || m.interface || 'connected' : null, route: m ? m.destination : null, unsupported_routes: (routes || []).filter(r => !cidr(r.destination)).map(r => r.destination) };
}
export function applyRouteChange(routes, change) {
  const out = (routes || []).map(r => ({ ...r }));
  if (change.op === 'add') out.push({ destination: change.destination, gateway: change.gateway || null, interface: change.interface || null });
  else if (change.op === 'remove') { const i = out.findIndex(r => r.destination === change.destination && (!change.gateway || r.gateway === change.gateway)); fail(i >= 0, 404, 'route_not_found'); out.splice(i, 1); }
  else fail(false, 400, 'invalid_route_change_op'); return out;
}
// Compare required flows across every device on their path, before and after.
export function analyse({ before, after, flows }) {
  const results = flows.map(fl => {
    const hops = fl.path.map(dev => { const b = before[dev] || {}, a = after[dev] || {}, vb = b.ruleset ? verdict(b.ruleset, fl) : { action: 'allow', rule_id: null, unsupported_rules: [], note: 'no ruleset: forwarding only' }, va = a.ruleset ? verdict(a.ruleset, fl) : { action: 'allow', rule_id: null, unsupported_rules: [], note: 'no ruleset: forwarding only' };
      const nb = nextHop(b.routes, fl.dst_ip), na = nextHop(a.routes, fl.dst_ip); return { device_ref: dev, before: vb, after: va, next_hop_before: nb.next_hop, next_hop_after: na.next_hop, unsupported_routes: [...new Set([...nb.unsupported_routes, ...na.unsupported_routes])] }; });
    const pathChanged = hops.some(h => h.next_hop_before !== h.next_hop_after), lost = hops.some(h => h.next_hop_before && !h.next_hop_after);
    const agg = side => hops.some(h => h[side].action === 'deny') ? 'deny' : hops.some(h => h[side].action === 'unknown') ? 'unknown' : 'allow', b = agg('before'), a = lost ? 'no-route' : agg('after');
    const effect = a === 'unknown' || b === 'unknown' ? 'cannot-verify' : b === 'allow' && (a === 'deny' || a === 'no-route') ? 'breaks' : b === 'deny' && a === 'allow' ? 'opens' : pathChanged ? 'path-changes' : 'unchanged';
    return { name: fl.name, criticality: fl.criticality, src_ip: fl.src_ip, dst_ip: fl.dst_ip, protocol: fl.protocol, port: fl.port, before: b, after: a, effect, path_changed: pathChanged, hops };
  });
  const broken = results.filter(r => r.effect === 'breaks'), unknown = results.filter(r => r.effect === 'cannot-verify'), opened = results.filter(r => r.effect === 'opens');
  return { results, summary: { flows: results.length, breaks: broken.length, opens: opened.length, path_changes: results.filter(r => r.path_changed).length, cannot_verify: unknown.length },
    decision: broken.length ? 'unsafe' : unknown.length ? 'cannot-verify' : 'safe', excluded_from_decision: [...new Set(results.flatMap(r => r.hops.flatMap(h => [...h.before.unsupported_rules, ...h.after.unsupported_rules, ...h.unsupported_routes])))],
    disclaimer: 'Configuration analysis only: it does not guarantee how the live network will perform (state, NAT, load balancers, asymmetric routing and device bugs are not modelled).', disclaimer_ar: 'تحليل للإعدادات فقط: لا يضمن سلوك الشبكة الفعلي (الحالة، NAT، موزعات الحمل، التوجيه غير المتماثل وأخطاء الأجهزة غير ممثلة).' };
}

export class ChangeSafety {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  addFlow(actor, input) {
    const f = { id: randomUUID(), name: text(input.name, 'flow_name', 200), src_ip: text(input.src_ip, 'flow_src_ip', 45), dst_ip: text(input.dst_ip, 'flow_dst_ip', 45), protocol: choice(input.protocol, ['tcp', 'udp', 'icmp'], 'flow_protocol'), port: integer(input.port ?? 0, 0, 65535, 'flow_port'), criticality: choice(input.criticality || 'high', ['low', 'medium', 'high', 'critical'], 'flow_criticality'), path: (Array.isArray(input.path) ? input.path : []).slice(0, 20).map((p, i) => text(p, `flow_path_${i}`, 200)) };
    fail(ip4(f.src_ip) !== null && ip4(f.dst_ip) !== null, 400, 'flow_addresses_must_be_ipv4'); fail(f.path.length >= 1, 400, 'flow_requires_a_device_path');
    this.s.run('INSERT INTO required_flows(id,name,src_ip,dst_ip,protocol,port,criticality,path,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)', f.id, f.name, f.src_ip, f.dst_ip, f.protocol, f.port, f.criticality, JSON.stringify(f.path), actor, this.now());
    this.s.audit(actor, 'change_safety.flow.added', f.id, { name: f.name }, this.now()); return f;
  }
  flows() { return this.s.all('SELECT * FROM required_flows ORDER BY name').map(f => ({ ...f, path: JSON.parse(f.path) })); }
  // Current snapshot per device: the latest stored firewall ruleset and the latest discovered routes.
  snapshot(devices) {
    const out = {}; for (const dev of devices) {
      const rs = this.s.all("SELECT payload FROM events WHERE kind='firewall.ruleset' ORDER BY observed_at DESC,received_at DESC").map(r => JSON.parse(r.payload).details).find(d => d.device_ref === dev) || null;
      const rt = this.s.get("SELECT e.payload FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='discovery.observed' AND a.external_id=? ORDER BY e.observed_at DESC LIMIT 1", dev);
      out[dev] = { ruleset: rs, routes: rt ? JSON.parse(rt.payload).details.routes || [] : [] };
    } return out;
  }
  analyseChange(actor, input) {
    const device_ref = text(input.device_ref, 'change_device_ref', 200), flows = this.flows(); fail(flows.length, 409, 'no_required_flows_registered');
    const devices = [...new Set([device_ref, ...flows.flatMap(f => f.path)])], before = this.snapshot(devices), after = structuredClone(before);
    if (input.rule_change) { fail(before[device_ref].ruleset, 409, 'no_ruleset_snapshot_for_device'); after[device_ref].ruleset = { ...before[device_ref].ruleset, rules: applyRuleChange(before[device_ref].ruleset, input.rule_change) }; }
    for (const rc of input.route_changes || []) after[device_ref].routes = applyRouteChange(after[device_ref].routes, rc);
    const r = analyse({ before, after, flows }), id = randomUUID();
    this.s.run('INSERT INTO change_analyses(id,device_ref,requested_by,at,decision,summary,change) VALUES (?,?,?,?,?,?,?)', id, device_ref, actor, this.now(), r.decision, JSON.stringify(r.summary), JSON.stringify({ rule_change: input.rule_change || null, route_changes: input.route_changes || [] }));
    this.s.audit(actor, 'change_safety.analysed', id, { device_ref, decision: r.decision, ...r.summary }, this.now()); return { id, device_ref, ...r };
  }
  history() { return this.s.all('SELECT id,device_ref,requested_by,at,decision,summary FROM change_analyses ORDER BY at DESC LIMIT 50').map(r => ({ ...r, summary: JSON.parse(r.summary) })); }
}
function applyRuleChange(ruleset, change) {
  // Reuse the CG-097 what-if change format; only the resulting rule list is needed here.
  const rules = ruleset.rules.map(r => ({ ...r })), i = rules.findIndex(r => r.rule_id === change.rule_id);
  if (change.op === 'add') { fail(change.rule && typeof change.rule === 'object', 400, 'rule_required'); rules.push({ enabled: true, filters_readable: true, scope_constraints: [], application: null, src_ports: ['any'], direction: 'in', ...change.rule }); }
  else { fail(i >= 0, 404, 'rule_not_found'); if (change.op === 'remove') rules.splice(i, 1); else if (change.op === 'disable') rules[i].enabled = false; else if (change.op === 'modify') rules[i] = { ...rules[i], ...change.rule, rule_id: rules[i].rule_id }; else fail(false, 400, 'invalid_rule_change_op'); }
  return rules;
}
