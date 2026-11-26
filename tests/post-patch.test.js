import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { PostPatchInvestigations } from '../lib/post-patch.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now() - 10 * 86400000; const d = new Domain(s, { clock: () => now }), at = () => new Date(now).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', at()); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  d.postPatch = new PostPatchInvestigations(s, { domain: d, clock: () => now });
  const web = { external_id: 'web-01', hostname: 'WEB-01', os_family: 'linux', device_type: 'server', addresses: ['10.70.0.10'] }, cat = { external_id: 'catalogs', hostname: 'CATALOGS', os_family: 'unknown', device_type: 'server', addresses: [] };
  const put = (id, kind, details, asset = web) => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(), asset, details }] });
  put('cat', 'vulnerability.catalog', { catalog_id: 'SYN-CAT', source: 'Synthetic advisory', published_at: at(), entries: [{ vuln_id: 'CVE-2099-0144', vendor: 'Synthetic', product: 'Synthetic Web Gateway', affected: { min_version: '1.0', max_version_exclusive: '1.5' }, fixed_version: '1.5', fixed_by_update: null, cvss: 9.8, kev: true, summary: 'Synthetic exploited vulnerability' }, { vuln_id: 'CVE-2099-0145', vendor: 'Synthetic', product: 'Synthetic Web Gateway', affected: { min_version: '1.0', max_version_exclusive: '1.5' }, fixed_version: '1.5', fixed_by_update: null, cvss: 5.0, kev: false, summary: 'Synthetic non-exploited vulnerability' }] }, cat);
  const inv = (id, version) => put(id, 'software.inventory', { inventory_id: 'INV-WEB', os: { name: 'Ubuntu', version: '24.04', build: null }, software: [{ name: 'Synthetic Web Gateway', vendor: 'Synthetic', version, install_date: null, source: 'package-manager' }], updates: [], evidence_ref: 'SYN' });
  const flow = (id, src_ip) => put(id, 'log.batch', { batch_id: id, source_name: 'flows', format: 'goflow-json', lines: [JSON.stringify({ TimeFlowStart: Math.floor(now / 1000), SrcAddr: src_ip, DstAddr: '10.70.0.10', SrcPort: 51000, DstPort: 443, Proto: 6, Bytes: 4000, Packets: 8 })] });
  return { s, d, inv, flow, put, advance: days => { now += days * 86400000; } };
}

test('a patched KEV vulnerability on an exposed asset opens an investigation that blocks case closure until every item is concluded (CG-144)', t => {
  const { s, d, inv, flow, put, advance } = fixture(t);
  inv('inv-1', '1.2'); advance(2); flow('f1', '198.51.100.144');
  advance(1); put('proc', 'endpoint.process_causality', { causality_id: 'C', collector: { type: 'edr', name: 'Synthetic EDR', trust: 'high', evidence_ref: 'SYN' }, window: { starts_at: new Date(Date.now() - 7 * 86400000 - 60000).toISOString(), ends_at: new Date(Date.now() - 7 * 86400000 + 3600000).toISOString() }, processes: [{ process_id: 'p', parent_process_id: null, image_path: '/usr/bin/curl', command_line: 'curl', user_ref: 'www-data', started_at: new Date(Date.now() - 7 * 86400000).toISOString(), signer: { status: 'unsigned', publisher: null }, integrity: 'medium', evidence_ref: 'edr:1' }], service_changes: [], scheduled_task_changes: [], connections: [] });
  advance(3); inv('inv-2', '1.5');
  const [inv1] = d.postPatch.list(); assert.equal(d.postPatch.list().length, 1, 'only the KEV vulnerability opens an investigation');
  assert.equal(inv1.vuln_id, 'CVE-2099-0144'); assert.equal(inv1.status, 'open'); assert.equal(inv1.exposure[0].source, '198.51.100.144');
  assert.deepEqual(inv1.items.map(i => i.id), ['processes', 'accounts', 'persistence', 'network']); assert.equal(inv1.items.find(i => i.id === 'network').evidence.records, 0, 'inbound traffic is exposure, not an outbound connection');
  const alert = s.get("SELECT id,severity,title FROM alerts WHERE rule_id='CG-PATCH-INVESTIGATE-144'"); assert.equal(alert.severity, 'high'); assert.match(alert.title, /investigate before closing/);
  const c = d.createCase('a', { title: 'Patched web gateway', alert_ids: [alert.id] });
  assert.throws(() => d.updateCase('a', c.id, { note: 'patched', status: 'closed' }), /post_patch_investigation_open/);
  assert.throws(() => d.postPatch.close('a', inv1.id), /post_patch_items_need_conclusions/);
  for (const item of ['processes', 'accounts', 'persistence']) d.postPatch.conclude('a', inv1.id, { item, conclusion: 'clean', note: `Reviewed ${item} for the window` });
  d.postPatch.conclude('a', inv1.id, { item: 'network', conclusion: 'insufficient-evidence', note: 'No outbound flow logs for the window' });
  assert.throws(() => d.postPatch.close('a', inv1.id), /post_patch_gaps_reason/, 'gaps need an explicit reason');
  const closed = d.postPatch.close('a', inv1.id, { gaps_reason: 'Outbound flow logging starts next month; accepted by the owner' }); assert.equal(closed.status, 'closed-with-gaps');
  assert.equal(d.updateCase('a', c.id, { note: 'patched and investigated', status: 'closed' }).status, 'closed');
  assert.equal(s.all("SELECT 1 FROM audit WHERE action LIKE 'post_patch.%'").length, 6);
});

test('no investigation without exposure while vulnerable, and a suspicious finding escalates (CG-144)', t => {
  const { d, inv, flow, advance } = fixture(t);
  inv('a1', '1.2'); advance(1); flow('internal', '10.70.0.99'); advance(1); inv('a2', '1.6');
  assert.equal(d.postPatch.list().length, 0, 'internal traffic only is not internet exposure');
  advance(1); inv('a3', '1.3'); advance(1); flow('ext', '203.0.113.144'); advance(1); inv('a4', '1.5');
  const [x] = d.postPatch.list(); assert.equal(x.status, 'open');
  for (const item of ['processes', 'accounts', 'persistence', 'network']) d.postPatch.conclude('a', x.id, { item, conclusion: item === 'accounts' ? 'suspicious' : 'clean', note: 'reviewed' });
  assert.equal(d.postPatch.close('a', x.id).status, 'escalated');
  assert.throws(() => d.postPatch.conclude('a', x.id, { item: 'processes', conclusion: 'clean', note: 'late' }), /post_patch_investigation_closed/);
});
