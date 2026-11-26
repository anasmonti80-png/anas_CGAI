import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { verdict, nextHop, analyse, ChangeSafety } from '../lib/change-safety.js';
import { registerView } from '../lib/research-register.js';
import { fileURLToPath } from 'node:url';

const rule = (rule_id, position, action, extra = {}) => ({ rule_id, name: rule_id, position, enabled: true, direction: 'in', action, protocol: 'tcp', src: ['10.0.0.0/24'], dst: ['10.0.1.0/24'], src_ports: ['any'], dst_ports: ['443'], application: null, profile: null, filters_readable: true, scope_constraints: [], ...extra });
const rs = rules => ({ ruleset_id: 'FW', device_ref: 'fw-1', vendor: 'pfsense', evaluation: 'first-match', rules });
const flow = { name: 'web to app', src_ip: '10.0.0.5', dst_ip: '10.0.1.9', protocol: 'tcp', port: 443, criticality: 'high', path: ['fw-1'] };

test('verdicts follow the ruleset, and rules the engine cannot model make the flow unknown (CG-131)', () => {
  assert.equal(verdict(rs([rule('allow-web', 1, 'allow')]), flow).action, 'allow');
  assert.equal(verdict(rs([rule('deny-all', 1, 'deny', { dst_ports: ['any'] }), rule('allow-web', 2, 'allow')]), flow).action, 'deny');
  const v = verdict(rs([rule('app-rule', 1, 'deny', { application: 'ssl' }), rule('allow-web', 2, 'allow')]), flow); assert.equal(v.action, 'unknown'); assert.deepEqual(v.unsupported_rules, ['app-rule']);
  assert.deepEqual(nextHop([{ destination: '10.0.0.0/8', gateway: '10.255.0.1' }, { destination: '10.0.1.0/24', gateway: '10.255.0.2' }, { destination: '2001:db8::/32', gateway: 'fe80::1' }], '10.0.1.9'), { next_hop: '10.255.0.2', route: '10.0.1.0/24', unsupported_routes: ['2001:db8::/32'] });
});

test('before/after analysis finds broken flows, opened flows, path changes and unverifiable flows (CG-131)', () => {
  const before = { 'fw-1': { ruleset: rs([rule('allow-web', 1, 'allow')]), routes: [{ destination: '10.0.1.0/24', gateway: '10.255.0.2' }] } };
  let r = analyse({ before, after: { 'fw-1': { ...before['fw-1'], ruleset: rs([{ ...rule('allow-web', 1, 'allow'), enabled: false }]) } }, flows: [flow] });
  assert.equal(r.results[0].effect, 'breaks'); assert.equal(r.decision, 'unsafe'); assert.match(r.disclaimer, /does not guarantee/);
  r = analyse({ before, after: { 'fw-1': { ...before['fw-1'], routes: [{ destination: '10.0.1.0/24', gateway: '10.255.0.9' }] } }, flows: [flow] }); assert.equal(r.results[0].effect, 'path-changes'); assert.equal(r.decision, 'safe');
  r = analyse({ before, after: { 'fw-1': { ...before['fw-1'], routes: [] } }, flows: [flow] }); assert.equal(r.results[0].effect, 'breaks', 'losing the only route breaks the flow');
  r = analyse({ before, after: { 'fw-1': { ...before['fw-1'], ruleset: rs([rule('app-rule', 0, 'deny', { application: 'ssl' }), rule('allow-web', 1, 'allow')]) } }, flows: [flow] });
  assert.equal(r.decision, 'cannot-verify'); assert.deepEqual(r.excluded_from_decision, ['app-rule'], 'unsupported features are excluded from the decision and named');
  const closed = { 'fw-1': { ruleset: rs([]), routes: before['fw-1'].routes } }; r = analyse({ before: closed, after: before, flows: [flow] }); assert.equal(r.results[0].effect, 'opens');
});

test('a proposed change is analysed against the stored snapshots and registered flows, and the research is recorded (CG-131)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), cs = new ChangeSafety(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Net', stale_seconds: 86400 }), fw = { external_id: 'fw-1', hostname: 'FW-1', os_family: 'network', device_type: 'firewall', addresses: ['10.0.0.1'] };
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [
    { event_id: 'rs', kind: 'firewall.ruleset', observed_at: new Date().toISOString(), asset: fw, details: { ruleset_id: 'FW', device_ref: 'fw-1', vendor: 'pfsense', evaluation: 'first-match', rules: [{ ...rule('allow-web', 1, 'allow'), last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null }].map(({ filters_readable, scope_constraints, ...r }) => r) } },
    { event_id: 'disc', kind: 'discovery.observed', observed_at: new Date().toISOString(), asset: fw, details: { authorization_ref: 'NET-131', acquisition: 'passive-import', availability: 'up', networks: ['10.0.0.0/24'], routes: [{ destination: '10.0.1.0/24', gateway: '10.255.0.2', interface: 'ge-0/0/1' }], vlans: [], interfaces: [], services: [] } }] });
  assert.throws(() => cs.analyseChange('a', { device_ref: 'fw-1', rule_change: { op: 'disable', rule_id: 'allow-web' } }), /no_required_flows_registered/);
  assert.throws(() => cs.addFlow('a', { ...flow, path: [] }), /flow_requires_a_device_path/);
  cs.addFlow('a', flow);
  let r = cs.analyseChange('a', { device_ref: 'fw-1', rule_change: { op: 'disable', rule_id: 'allow-web' } }); assert.equal(r.decision, 'unsafe'); assert.equal(r.summary.breaks, 1);
  r = cs.analyseChange('a', { device_ref: 'fw-1', route_changes: [{ op: 'add', destination: '10.0.1.0/25', gateway: '10.255.0.7' }] }); assert.equal(r.decision, 'safe'); assert.equal(r.summary.path_changes, 1);
  assert.throws(() => cs.analyseChange('a', { device_ref: 'fw-1', route_changes: [{ op: 'remove', destination: '192.0.2.0/24' }] }), /route_not_found/);
  assert.equal(cs.history().length, 2); assert.equal(s.all("SELECT 1 FROM audit WHERE action='change_safety.analysed'").length, 2);
  const reg = registerView(fileURLToPath(new URL('../', import.meta.url))); assert.equal(reg.valid, true); const bf = reg.entries.find(e => e.id === 'R-019');
  assert.equal(bf.decision, 'deferred'); assert.equal(bf.verification, 'verified-source'); assert.match(bf.summary, /Palo Alto/); assert.ok(reg.entries.some(e => e.id === 'R-021' && e.decision === 'accepted'));
});
