import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { reliability } from '../lib/event-reliability.js';

const asset = { external_id: 'srv', hostname: 'srv', os_family: 'linux', device_type: 'server', addresses: [] };

test('volume, refusals, duplicates, late events, processing time, queue lag and detection time are measured per hour, and a degraded last hour raises an operational alert (CG-168)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const base = Date.now() - 3 * 3600000; let now = base; const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin', { name: 'Auth', stale_seconds: 86400 }); let n = 0;
  const fail5 = (ip, observedAgoSec = 0) => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: Array.from({ length: 5 }, () => ({ event_id: `e${n++}`, kind: 'auth.failed', observed_at: new Date(now - observedAgoSec * 1000).toISOString(), asset, details: { account: 'root', source_ip: ip, protocol: 'ssh' } })) });
  // Hour 1: quiet, on time.
  now = base + 10 * 60000; fail5('198.51.100.1');
  // Hour 2: busy, one duplicate batch, one refused batch and late events (observed 20 minutes before receipt).
  now = base + 70 * 60000; for (let i = 2; i < 6; i++) fail5(`198.51.100.${i}`, 1200);
  const dup = { schema_version: 'cg.telemetry/1', events: [{ event_id: 'e0', kind: 'auth.failed', observed_at: new Date(base + 10 * 60000).toISOString(), asset, details: { account: 'root', source_ip: '198.51.100.1', protocol: 'ssh' } }] };
  d.ingest('admin', src.id, dup);
  assert.throws(() => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'bad', kind: 'auth.failed', observed_at: new Date(now + 3600000).toISOString(), asset, details: { account: 'x', source_ip: null, protocol: 'ssh' } }] }), /invalid_observed_at/);
  d.recordDelivery(src.id, { depth: 12, oldest: new Date(now - 30 * 60000).toISOString(), attempt: 2 });
  now = base + 2.5 * 3600000;
  const r = reliability(s, { clock: () => now, hours: 3 });
  const [h1, h2] = r.hours;
  assert.deepEqual([h1.input, h1.processed, h1.late, h1.alerts], [5, 5, 0, 1]);
  assert.deepEqual([h2.input, h2.processed, h2.duplicates, h2.rejected, h2.late, h2.alerts], [22, 20, 1, 1, 20, 4]);
  assert.equal(h2.eps.input, Math.round(22 / 3600 * 1000) / 1000); assert.ok(h2.processing_ms_p95 >= 0);
  assert.deepEqual([h1.detection_s_p50, h2.detection_s_p50], [0, 1200], 'late evidence shows as detection time from observation');
  assert.equal(h2.pipeline_s_p95, 0, 'from receipt the pipeline itself was immediate');
  assert.equal(r.rate_effect.verdict, 'stable');
  assert.deepEqual([r.queues[0].queue_depth, r.queues[0].lag_minutes], [12, 110]);
  assert.deepEqual(r.parser.refused.map(x => [x.code, x.events]), [['invalid_observed_at', 1]]);
  // A last hour with more than 5% refused raises CG-PIPELINE-168 (operational, never a security incident).
  now = base + 2.6 * 3600000; fail5('198.51.100.9');
  for (let i = 0; i < 2; i++) assert.throws(() => d.ingest('admin', src.id, { schema_version: 'cg.telemetry/0', events: [{ event_id: `old${i}` }] }), /unsupported_schema/);
  const p = d.checkPipeline(); assert.deepEqual(p.last_hour_issues, ['rejected-over-5-percent']);
  assert.equal(s.get("SELECT severity FROM alerts WHERE rule_id='CG-PIPELINE-168'").severity, 'medium');
});
