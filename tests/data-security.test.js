import test from 'node:test';
import assert from 'node:assert/strict';
import { storeFindings, egressAnomalies } from '../lib/data-security.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const store = o => ({ store_id: 'hr-share', store_type: 'file-share', classification: 'restricted', owner: 'HR lead', location: 'sa-central', encryption_at_rest: 'enabled', public_access: false, contains_personal_data: true, legal_basis: 'employment contract', retention_days: 2555, content_inspection: null, evidence_ref: 'data-inventory-2026', ...o });

test('data store posture: exposure, encryption, owner, legal basis, retention and region (CG-109)', () => {
  assert.deepEqual(storeFindings(store()), []);
  assert.deepEqual(storeFindings(store({ public_access: true, encryption_at_rest: 'unknown', owner: null, legal_basis: null, retention_days: null, location: 'us-east' }), { allowedRegions: ['sa-central'] }).map(f => [f.id, f.severity]),
    [['sensitive-public', 'critical'], ['unencrypted-sensitive', 'high'], ['no-owner', 'medium'], ['no-legal-basis', 'medium'], ['no-retention', 'low'], ['outside-allowed-region', 'high']]);
  assert.deepEqual(storeFindings(store({ classification: 'public', public_access: true, contains_personal_data: false, encryption_at_rest: 'disabled' })), [], 'public data that is public is fine');
});

test('unusual egress is measured per host against its own daily median, internal traffic is ignored (CG-109)', () => {
  const now = Date.parse('2026-11-20T12:00:00Z'), MB = 1048576, at = h => new Date(now - h * 3600000).toISOString(), recs = [];
  for (let day = 2; day <= 8; day++) recs.push({ category: 'flow', time: at(day * 24), src_ip: '10.0.5.20', dst_ip: '203.0.113.10', bytes: 40 * MB }, { category: 'flow', time: at(day * 24), src_ip: '10.0.5.21', dst_ip: '203.0.113.10', bytes: 400 * MB });
  recs.push({ category: 'flow', time: at(2), src_ip: '10.0.5.20', dst_ip: '198.51.100.7', bytes: 900 * MB }, { category: 'flow', time: at(3), src_ip: '10.0.5.21', dst_ip: '203.0.113.10', bytes: 700 * MB }, { category: 'flow', time: at(1), src_ip: '10.0.5.22', dst_ip: '10.0.9.9', bytes: 5000 * MB });
  const a = egressAnomalies(recs, now);
  assert.deepEqual(a.map(x => [x.host_ip, x.ratio, x.top_destinations[0].dst]), [['10.0.5.20', 22.5, '198.51.100.7']], 'normal heavy uploader and internal copies are not flagged');
});

test('declared stores and flow logs feed alerts; content inspection needs legal approval (CG-109)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Data inventory', stale_seconds: 86400 }), asset = { external_id: 'fs01', hostname: 'FS01', os_family: 'windows', device_type: 'server', addresses: ['10.0.5.20'] }, now = new Date().toISOString();
  const ev = (id, kind, details) => ({ schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: now, asset, details }] });
  assert.throws(() => d.ingest('admin-a', src.id, ev('s0', 'data.store', store({ content_inspection: { approved: true, legal_ref: null, privacy_reviewer: 'DPO', scope: 'all files' } }))), /content_inspection_requires_legal_ref_reviewer_and_scope/);
  d.ingest('admin-a', src.id, ev('s1', 'data.store', store({ content_inspection: { approved: true, legal_ref: 'LEGAL-2026-14', privacy_reviewer: 'DPO', scope: 'HR contracts folder only', approved_at: now } })));
  d.ingest('admin-a', src.id, ev('s2', 'data.store', store({ store_id: 'finance-bucket', store_type: 'object-storage', classification: 'confidential', public_access: true, encryption_at_rest: 'disabled', contains_personal_data: false })));
  const sec = Math.floor(Date.now() / 1000), lines = [];
  for (let day = 2; day <= 6; day++) lines.push(JSON.stringify({ TimeFlowStart: sec - day * 86400, SrcAddr: '10.0.5.20', DstAddr: '203.0.113.10', SrcPort: 50000, DstPort: 443, Proto: 6, Bytes: 30 * 1048576, Packets: 1000 }));
  lines.push(JSON.stringify({ TimeFlowStart: sec - 3600, SrcAddr: '10.0.5.20', DstAddr: '198.51.100.7', SrcPort: 50001, DstPort: 443, Proto: 6, Bytes: 2048 * 1048576, Packets: 90000 }));
  d.ingest('admin-a', src.id, ev('f1', 'log.batch', { batch_id: 'flows-1', source_name: 'goflow', format: 'goflow-json', lines }));
  const v = d.dataSecurity();
  assert.equal(v.summary.stores, 2); assert.equal(v.summary.approved_for_content_inspection, 1); assert.equal(v.egress_anomalies[0].host_ip, '10.0.5.20');
  const rules = s.all("SELECT rule_id,severity,asset_id FROM alerts WHERE rule_id LIKE 'CG-DATA%' ORDER BY rule_id,severity");
  assert.deepEqual(rules.map(r => [r.rule_id, r.severity]), [['CG-DATA-109', 'critical'], ['CG-DATA-109', 'high'], ['CG-DATA-EGRESS-109', 'high']]);
  assert.ok(rules.find(r => r.rule_id === 'CG-DATA-EGRESS-109').asset_id, 'the egress alert is tied to the asset owning the address');
  d.dataSecurity(); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-DATA-EGRESS-109'").length, 1, 'repeated views do not duplicate the alert');
  assert.ok(v.privacy_ar.includes('لا يُفحص المحتوى'));
});
