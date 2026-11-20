// CG-020 firewall rule analyser: duplicates, shadowed/conflicting rules, overly broad rules, stale rules,
// expired or expiring exceptions, and change impact between two rulesets of the same device.
import { isIP } from 'node:net';
import { detailAr } from './i18n-ar.js';

const DAY = 86400000;
const adminPorts = new Set([22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986]);
const toV4 = ip => ip.split('.').reduce((n, p) => n * 256 + Number(p), 0);
function cidrRange(value) {
  if (value === 'any') return { any: true };
  const [addr, bits] = value.includes('/') ? value.split('/') : [value, isIP(value) === 6 ? '128' : '32'];
  if (isIP(addr) === 4) { const prefix = Number(bits), size = 2 ** (32 - prefix), start = Math.floor(toV4(addr) / size) * size; return { v: 4, start, end: start + size - 1 }; }
  return { v: 6, text: `${addr}/${bits}` };
}
const rangeCovers = (outer, inner) => outer.any || (!inner.any && outer.v === inner.v && (outer.v === 4 ? outer.start <= inner.start && outer.end >= inner.end : outer.text === inner.text));
const setCovers = (outer, inner) => inner.every(i => outer.some(o => rangeCovers(cidrRange(o), cidrRange(i))));
const portRange = value => value === 'any' ? { lo: 0, hi: 65535 } : String(value).includes('-') ? { lo: Number(String(value).split('-')[0]), hi: Number(String(value).split('-')[1]) } : { lo: Number(value), hi: Number(value) };
const portsCover = (outer, inner) => inner.every(i => outer.some(o => portRange(o).lo <= portRange(i).lo && portRange(o).hi >= portRange(i).hi));
const protoCovers = (outer, inner) => outer === 'any' || outer === inner;
const appCovers = (outer, inner) => !outer || outer === inner;
const scopeCovers = (outer, inner) => (outer.scope_constraints || []).every(c => (inner.scope_constraints || []).includes(c));
// CG-097 traffic classes from private (internal) and public (external) address ranges.
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16'].map(cidrRange);
const isInternal = v => { if (v === 'any') return null; const addr = v.split('/')[0]; if (isIP(addr) === 6) return /^(fc|fd|fe8)/i.test(addr); const r = cidrRange(v); return PRIVATE.some(p => rangeCovers(p, r)); };
const isHostRange = v => v !== 'any' && (!v.includes('/') || /\/(32|128)$/.test(v));
export function trafficClass(r) {
  const src = r.src.map(isInternal), dst = r.dst.map(isInternal), allIn = xs => xs.length && xs.every(x => x === true), anyOut = xs => xs.some(x => x === false || x === null);
  if (allIn(src) && allIn(dst)) return 'east-west';
  if (allIn(dst) && anyOut(src)) return 'ingress';
  if (allIn(src) && anyOut(dst)) return 'egress';
  if (r.direction === 'in') return 'ingress'; if (r.direction === 'out') return 'egress'; return 'unclassified';
}
const rangesOverlap = (a, b) => a.any || b.any || (a.v === b.v && (a.v === 4 ? a.start <= b.end && b.start <= a.end : a.text === b.text));
const setsOverlap = (x, y) => x.some(a => y.some(b => rangesOverlap(cidrRange(a), cidrRange(b))));
const portsOverlap = (x, y) => x.some(a => y.some(b => portRange(a).lo <= portRange(b).hi && portRange(b).lo <= portRange(a).hi));
export function rulesOverlap(a, b) { return a.direction === b.direction && (a.protocol === 'any' || b.protocol === 'any' || a.protocol === b.protocol) && setsOverlap(a.src, b.src) && setsOverlap(a.dst, b.dst) && portsOverlap(a.dst_ports, b.dst_ports) && (!a.application || !b.application || a.application === b.application); }
// Decision for one flow: first-match uses rule order; deny-overrides blocks when any matching deny exists. Default deny.
export function evaluate(ruleset, flow) {
  const m = ruleset.rules.filter(r => r.enabled && r.filters_readable !== false).sort((a, b) => a.position - b.position).filter(r => (r.direction === flow.direction || r.direction === 'any') && (r.protocol === 'any' || r.protocol === flow.protocol) && setCovers(r.src, [flow.src]) && setCovers(r.dst, [flow.dst]) && portsCover(r.dst_ports, [String(flow.port)]) && !r.application);
  if (ruleset.evaluation === 'deny-overrides') { const d = m.find(r => r.action === 'deny'); if (d) return { action: 'deny', rule_id: d.rule_id }; const a = m.find(r => r.action === 'allow'); return a ? { action: 'allow', rule_id: a.rule_id } : { action: 'deny', rule_id: null }; }
  return m[0] ? { action: m[0].action, rule_id: m[0].rule_id } : { action: 'deny', rule_id: null };
}
const sample = v => v === 'any' ? '203.0.113.77' : (() => { const r = cidrRange(v); return r.v === 4 ? [r.start >>> 24 & 255, r.start >>> 16 & 255, r.start >>> 8 & 255, (r.start & 255) + (r.end > r.start ? 1 : 0)].join('.') : v.split('/')[0]; })();
// What-if: apply a proposed change in memory and report its impact before anything is changed on the device.
export function whatIf(ruleset, change, now = Date.now()) {
  const rules = ruleset.rules.map(r => ({ ...r })), find = id => rules.findIndex(r => r.rule_id === id);
  if (change.op === 'add') rules.push({ enabled: true, filters_readable: true, scope_constraints: [], application: null, profile: 'any', src_ports: ['any'], last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, ...change.rule });
  else { const i = find(change.rule_id); if (i < 0) throw new Error('rule_not_found');
    if (change.op === 'remove') rules.splice(i, 1); else if (change.op === 'disable') rules[i].enabled = false; else if (change.op === 'modify') rules[i] = { ...rules[i], ...change.rule, rule_id: rules[i].rule_id }; else if (change.op === 'move') rules[i].position = change.position; else throw new Error('invalid_change_op'); }
  const after = { ...ruleset, ruleset_id: `${ruleset.ruleset_id}:what-if`, rules }, a = analyseRuleset(ruleset, now), b = analyseRuleset(after, now, ruleset), key = f => `${f.type}|${f.rule_id}|${f.related_rule_id || ''}`;
  const beforeKeys = new Set(a.findings.map(key)), afterKeys = new Set(b.findings.map(key));
  const probes = new Map(); for (const r of [...ruleset.rules, ...rules]) for (const dir of [r.direction === 'any' ? 'in' : r.direction]) { const port = r.dst_ports[0] === 'any' ? 443 : portRange(r.dst_ports[0]).lo, proto = r.protocol === 'any' ? 'tcp' : r.protocol;
    for (const p of [port, ...[22, 3389, 445].filter(x => r.dst_ports.includes('any'))]) { const f = { direction: dir, protocol: proto, src: sample(r.src[0]), dst: sample(r.dst[0]), port: p }; probes.set(JSON.stringify(f), f); } }
  const decision_changes = [...probes.values()].map(f => ({ flow: f, before: evaluate(ruleset, f), after: evaluate(after, f) })).filter(x => x.before.action !== x.after.action).slice(0, 50);
  return { change, new_findings: b.findings.filter(f => !beforeKeys.has(key(f))), resolved_findings: a.findings.filter(f => !afterKeys.has(key(f))), decision_changes, opened: decision_changes.filter(x => x.after.action === 'allow').length, closed: decision_changes.filter(x => x.after.action === 'deny').length, exposure: b.change?.impact || null, traffic_classes_after: b.traffic_classes, applied: false };
}
export function ruleCovers(a, b) {
  return a.direction === b.direction && protoCovers(a.protocol, b.protocol) && setCovers(a.src, b.src) && setCovers(a.dst, b.dst) && portsCover(a.src_ports, b.src_ports) && portsCover(a.dst_ports, b.dst_ports) && appCovers(a.application, b.application) && scopeCovers(a, b) && (!a.profile || !b.profile || a.profile === b.profile || a.profile === 'any');
}
const signature = r => JSON.stringify([r.direction, r.protocol, [...r.src].sort(), [...r.dst].sort(), [...r.src_ports].sort(), [...r.dst_ports].sort(), r.application || null, r.profile || null, [...(r.scope_constraints || [])].sort(), r.action]);
const narrowed = r => !!r.application || (r.scope_constraints || []).some(c => /^(service|package|owner|port-keyword):/.test(c));
const touchesAdmin = r => ['tcp', 'udp', 'any'].includes(r.protocol) && r.dst_ports.some(p => p === 'any' ? !narrowed(r) : [...adminPorts].some(a => portRange(p).lo <= a && portRange(p).hi >= a));

export function analyseRuleset(ruleset, now = Date.now(), previous = null) {
  const rules = ruleset.rules.filter(r => r.enabled && r.filters_readable !== false).sort((a, b) => a.position - b.position), findings = [];
  const add = (type, severity, rule, detail, related = null) => findings.push({ type, severity, rule_id: rule.rule_id, rule_name: rule.name, related_rule_id: related?.rule_id || null, related_rule_name: related?.name || null, detail, detail_ar: detailAr(detail) });
  const seen = new Map();
  for (const r of rules) { const s = signature(r); if (seen.has(s)) add('duplicate', 'low', r, 'Same match fields and action as an earlier rule', seen.get(s)); else seen.set(s, r); }
  for (let i = 0; i < rules.length; i++) for (let j = 0; j < rules.length; j++) {
    if (i === j) continue; const a = rules[i], b = rules[j];
    if (ruleset.evaluation === 'first-match' && j > i && ruleCovers(a, b) && signature(a) !== signature(b)) add(a.action === b.action ? 'redundant' : 'shadowed', a.action === b.action ? 'low' : 'high', b, a.action === b.action ? 'Never matched: an earlier rule with the same action covers it' : `Never takes effect: earlier ${a.action} rule covers it`, a);
    if (ruleset.evaluation === 'deny-overrides' && a.action === 'deny' && b.action === 'allow' && ruleCovers(a, b)) add('conflict', 'medium', b, 'Allow rule is overridden by a covering block rule', a);
  }
  for (const r of rules.filter(r => r.action === 'allow')) {
    const anySrc = r.src.includes('any'), anyDst = r.dst.includes('any'), anyPort = r.dst_ports.includes('any');
    if (anySrc && anyDst && anyPort && r.protocol === 'any' && !r.application && !(r.scope_constraints || []).length) add('any-any-allow', 'critical', r, 'Allows any source to any destination on any port and protocol');
    else if (r.direction === 'in' && anySrc && touchesAdmin(r)) add('broad-admin-exposure', 'high', r, `Inbound from any address to administrative port(s) ${r.dst_ports.join(',')}`);
    else if (anySrc && anyPort && r.direction === 'in' && !r.application && !(r.scope_constraints || []).length) add('broad-inbound', 'medium', r, 'Inbound from any address on any port');
  }
  for (const r of rules) {
    if (r.last_hit_at && now - Date.parse(r.last_hit_at) > 90 * DAY) add('stale', 'low', r, `No hits for ${Math.floor((now - Date.parse(r.last_hit_at)) / DAY)} days`);
    else if (r.hit_count === 0 && r.created_at && now - Date.parse(r.created_at) > 90 * DAY) add('stale', 'low', r, 'Zero hits since creation more than 90 days ago');
    if (r.expires_at && Date.parse(r.expires_at) <= now) add('expired-exception', 'high', r, `Exception expired ${Math.floor((now - Date.parse(r.expires_at)) / DAY)} day(s) ago but is still enabled`);
    else if (r.expires_at && Date.parse(r.expires_at) - now <= 14 * DAY) add('exception-expiring', 'medium', r, `Exception expires in ${Math.ceil((Date.parse(r.expires_at) - now) / DAY)} day(s)`);
  }
  let change = null;
  if (previous) {
    const before = new Map(previous.rules.map(r => [r.rule_id, r])), after = new Map(ruleset.rules.map(r => [r.rule_id, r]));
    const added = ruleset.rules.filter(r => !before.has(r.rule_id)), removed = previous.rules.filter(r => !after.has(r.rule_id)), modified = ruleset.rules.filter(r => before.has(r.rule_id) && signature(before.get(r.rule_id)) + before.get(r.rule_id).enabled !== signature(r) + r.enabled);
    const exposing = r => r.enabled && r.filters_readable !== false && r.action === 'allow' && r.direction === 'in' && r.src.includes('any') && touchesAdmin(r);
    const newExposure = [...added, ...modified].filter(exposing).filter(r => !(before.get(r.rule_id) && exposing(before.get(r.rule_id))));
    change = { previous_ruleset_id: previous.ruleset_id, added: added.map(r => r.rule_id), removed: removed.map(r => r.rule_id), modified: modified.map(r => r.rule_id), new_admin_exposure: newExposure.map(r => ({ rule_id: r.rule_id, name: r.name, ports: r.dst_ports })), impact: newExposure.length ? 'increases-exposure' : added.length + removed.length + modified.length ? 'changed' : 'no-change' };
  }
  // CG-097 partial overlaps with a different action (order decides the overlapping traffic) and traffic class reviews.
  for (let i = 0; i < rules.length; i++) for (let j = i + 1; j < rules.length; j++) { const a = rules[i], b = rules[j];
    if (a.action !== b.action && rulesOverlap(a, b) && !ruleCovers(a, b) && !ruleCovers(b, a)) add('overlap', 'medium', b, `Partially overlaps an earlier ${a.action} rule; for the overlapping traffic the ${ruleset.evaluation === 'deny-overrides' ? 'block' : 'earlier'} rule wins`, a); }
  for (const r of rules.filter(r => r.action === 'allow')) { const c = trafficClass(r), anyPort = r.dst_ports.includes('any') && r.protocol === 'any' && !r.application && !(r.scope_constraints || []).length;
    if (c === 'east-west' && anyPort && r.src.some(s => !isHostRange(s)) && r.dst.some(s => !isHostRange(s))) add('east-west-broad', 'high', r, 'Allows any internal network to any internal network on any port: lateral movement is unrestricted');
    else if (c === 'east-west' && touchesAdmin(r) && r.src.some(s => !isHostRange(s))) add('east-west-admin', 'medium', r, `Allows internal networks to reach administrative port(s) ${r.dst_ports.join(',')}`);
    if (c === 'egress' && anyPort && r.dst.includes('any')) add('open-egress', 'medium', r, 'Allows internal hosts to reach any destination on any port: egress is not filtered'); }
  const traffic_classes = { ingress: 0, egress: 0, 'east-west': 0, unclassified: 0 }; for (const r of rules) traffic_classes[trafficClass(r)]++;
  const by_type = {}; for (const f of findings) by_type[f.type] = (by_type[f.type] || 0) + 1;
  return { findings, by_type, traffic_classes, rules_total: ruleset.rules.length, rules_enabled: ruleset.rules.filter(r => r.enabled).length, rules_analysed: rules.length, rules_unreadable: ruleset.rules.filter(r => r.filters_readable === false).length, change };
}
