import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { CATALOG, preview, CollectionControl } from '../lib/collection-preview.js';

test('a cloud source preview shows volume from a measured sample, billed components with free allowances, permissions and regions, and computes cost only from entered prices (CG-160)', () => {
  for (const id of ['aws-cloudtrail-management', 'aws-vpc-flow', 'aws-guardduty', 'azure-activity-log', 'azure-vnet-flow', 'gcp-admin-activity', 'gcp-data-access', 'gcp-vpc-flow']) assert.ok(CATALOG.find(c => c.id === id), id);
  // One hour sample: 12,000 events, 18 MB -> 288,000 events/day.
  let p = preview({ source: 'aws-cloudtrail-data', sample_events: 12000, sample_bytes: 18000000, sample_hours: 1, regions: 2, retention_days: 90 });
  assert.equal(p.basis, 'measured-sample'); assert.deepEqual([p.volume.events_per_day, p.volume.avg_event_bytes, p.volume.events_per_month], [288000, 1500, 8640000]);
  assert.equal(p.total, null, 'no prices entered, no cost invented'); assert.ok(p.warnings.some(w => w.code === 'no-prices'));
  assert.deepEqual(p.permissions.enable, ['cloudtrail:PutEventSelectors']); assert.ok(p.permissions.read.includes('s3:GetObject'));
  p = preview({ source: 'aws-cloudtrail-data', sample_events: 12000, sample_bytes: 18000000, sample_hours: 1, regions: 2, retention_days: 90, prices: { ingest: 0.1, egress: 0.09 } });
  const line = c => p.lines.find(l => l.component === c);
  assert.deepEqual([line('ingest').quantity, line('ingest').cost], [86.4, 8.64], '8.64M events = 86.4 x 100k');
  assert.equal(line('egress').free_allowance, Math.min(100, line('egress').quantity), 'AWS gives 100 GB of internet egress per month');
  assert.equal(p.total_complete, false, 'storage and API prices were not entered');
  // The first trail copy of management events is free; a single-Region trail is warned about.
  p = preview({ source: 'aws-cloudtrail-management', events_per_day: 500000, avg_event_bytes: 1200, regions: 4, trail_multi_region: false, prices: { ingest: 2 } });
  assert.deepEqual([p.lines[0].component, p.lines[0].billed_quantity, p.lines[0].cost], ['ingest', 0, 0]); assert.ok(p.warnings.some(w => w.code === 'single-region-trail'));
  // Azure Activity log: ingestion free, only retention past 90 days is billed.
  p = preview({ source: 'azure-activity-log', events_per_day: 10000, avg_event_bytes: 2000, retention_days: 90 }); assert.equal(p.lines.find(l => l.component === 'storage').quantity, 0);
  // Google Data Access: the first 50 GiB per project per month are free.
  p = preview({ source: 'gcp-data-access', events_per_day: 3000000, avg_event_bytes: 1000, prices: { ingest: 0.5 } });
  const ing = p.lines.find(l => l.component === 'ingest'); assert.equal(ing.free_allowance, 50); assert.equal(ing.cost, Math.round((ing.quantity - 50) * 0.5 * 100) / 100); assert.ok(p.warnings.some(w => w.code === 'high-volume'));
  assert.throws(() => preview({ source: 'nope', events_per_day: 1, avg_event_bytes: 100 }), /unknown_collection_source/);
});

test('stopping a source revokes it, deletes no event, keeps evidence of open alerts protected and requires the incident owner when a case is open (CG-160)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = dom.createSource('a', { name: 'CloudTrail', stale_seconds: 86400 }), now = new Date().toISOString();
  dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'e1', kind: 'asset.observed', observed_at: now, asset: { external_id: 'h1', hostname: 'h1', os_family: 'linux', device_type: 'server', addresses: [] }, details: {} }] });
  const ev = s.get('SELECT id,asset_id FROM events LIMIT 1');
  s.run("INSERT INTO alerts(id,dedup_key,asset_id,source_id,rule_id,rule_version,severity,title,status,first_seen,last_seen,evidence_ids) VALUES ('al1','k1',?,?,'R','1','high','t','open',?,?,?)", ev.asset_id, src.id, now, now, JSON.stringify([ev.id]));
  s.run("INSERT INTO cases VALUES ('c1','Incident','investigating','a',?,?,?,'[]')", now, now, JSON.stringify(['al1']));
  const cc = new CollectionControl(s, { retentionDays: () => 365 });
  const pre = cc.stopPreview(src.id); assert.deepEqual([pre.events_total, pre.protected_events, pre.open_alerts, pre.open_cases.length, pre.blocked], [1, 1, 1, 1, true]);
  assert.throws(() => cc.stop('a', src.id, { reason: 'cost', authorization_ref: 'CHG-160', confirm_no_deletion: true }), /open_incident_from_source_requires_incident_owner/);
  assert.throws(() => cc.stop('a', src.id, { reason: 'cost', authorization_ref: 'CHG-160', incident_owner_ref: 'IR-lead' }), /confirm_no_deletion_required/);
  const r = cc.stop('a', src.id, { reason: 'cost', authorization_ref: 'CHG-160', incident_owner_ref: 'IR-lead', confirm_no_deletion: true });
  assert.deepEqual([r.deleted_events, r.source.revoked, s.get('SELECT COUNT(*) n FROM events').n, s.get('SELECT revoked FROM sources WHERE id=?', src.id).revoked], [0, true, 1, 1]);
  assert.ok(s.get("SELECT 1 x FROM audit WHERE action='source.collection-stopped'"));
  assert.throws(() => dom.sourceToken(src.token, src.id), /invalid_source_token/, 'the source can no longer send');
  assert.throws(() => cc.stop('a', src.id, { reason: 'x', authorization_ref: 'y', incident_owner_ref: 'z', confirm_no_deletion: true }), /source_already_stopped/);
  assert.equal(cc.view().stops.length, 1);
});
