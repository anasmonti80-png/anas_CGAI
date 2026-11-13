// CG-020 firewall rule analyser: duplicates, shadowed/conflicting rules, overly broad rules, stale rules,
// expired or expiring exceptions, and change impact between two rulesets of the same device.
import { isIP } from 'node:net';

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
export function ruleCovers(a, b) {
  return a.direction === b.direction && protoCovers(a.protocol, b.protocol) && setCovers(a.src, b.src) && setCovers(a.dst, b.dst) && portsCover(a.src_ports, b.src_ports) && portsCover(a.dst_ports, b.dst_ports) && appCovers(a.application, b.application) && scopeCovers(a, b) && (!a.profile || !b.profile || a.profile === b.profile || a.profile === 'any');
}
const signature = r => JSON.stringify([r.direction, r.protocol, [...r.src].sort(), [...r.dst].sort(), [...r.src_ports].sort(), [...r.dst_ports].sort(), r.application || null, r.profile || null, [...(r.scope_constraints || [])].sort(), r.action]);
const narrowed = r => !!r.application || (r.scope_constraints || []).some(c => /^(service|package|owner|port-keyword):/.test(c));
const touchesAdmin = r => ['tcp', 'udp', 'any'].includes(r.protocol) && r.dst_ports.some(p => p === 'any' ? !narrowed(r) : [...adminPorts].some(a => portRange(p).lo <= a && portRange(p).hi >= a));

export function analyseRuleset(ruleset, now = Date.now(), previous = null) {
  const rules = ruleset.rules.filter(r => r.enabled && r.filters_readable !== false).sort((a, b) => a.position - b.position), findings = [];
  const add = (type, severity, rule, detail, related = null) => findings.push({ type, severity, rule_id: rule.rule_id, rule_name: rule.name, related_rule_id: related?.rule_id || null, related_rule_name: related?.name || null, detail });
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
  const by_type = {}; for (const f of findings) by_type[f.type] = (by_type[f.type] || 0) + 1;
  return { findings, by_type, rules_total: ruleset.rules.length, rules_enabled: ruleset.rules.filter(r => r.enabled).length, rules_analysed: rules.length, rules_unreadable: ruleset.rules.filter(r => r.filters_readable === false).length, change };
}
