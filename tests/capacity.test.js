import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { runBenchmark } from '../scripts/capacity-benchmark.js';
import { plan, live, loadProfile } from '../lib/capacity-model.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const profile = { measured_at: '2026-11-26T00:00:00.000Z', machine: { cpus: 8 }, eps: 40000, eps_per_cpu_core: 50000, bytes_per_event: 350, rss_mb: 100, detection_under_load: { injected: 10, detected: 10, reliability: 1 } };

test('the benchmark measures real throughput and every hidden attack is still detected under load (CG-129)', () => {
  const r = runBenchmark(4000);
  assert.ok(r.eps > 0 && r.bytes_per_event > 0 && r.eps_per_cpu_core > 0); assert.equal(r.detection_under_load.injected, 2); assert.equal(r.detection_under_load.reliability, 1);
  const saved = loadProfile(new URL('../artifacts/capacity-profile.json', import.meta.url)); assert.ok(saved && saved.detection_under_load.reliability === 1 && saved.workload.events >= 20000, 'a measured profile ships with the release');
  assert.ok(!JSON.stringify(saved).match(/DESKTOP-|192\.168\.100\./), 'no host identity in the profile');
});

test('the plan turns a rate and retention into GB per day, storage, CPU and memory from the measured profile (CG-129)', () => {
  const p = plan({ eps: 2000, retention_days: 90 }, profile);
  assert.equal(p.volume.events_per_day, 172800000); assert.equal(p.volume.gb_per_day, 60.48); assert.equal(p.volume.storage_gb_for_retention, 5443.2);
  assert.equal(p.compute.cpu_cores, 1); assert.equal(p.compute.fits_one_measured_node, true); assert.match(p.compute.gpu, /not required/);
  assert.equal(p.cost_monthly.total, null, 'no invented prices'); assert.match(p.reliability_guard, /within half of the measured maximum/);
  const priced = plan({ eps: 2000, retention_days: 90, price_storage_gb_month: 0.02, api_calls_per_day: 10000, price_api_call: 0.000001, ai_analyses_per_day: 50, price_ai_1k_tokens: 0.003 }, profile);
  assert.equal(priced.cost_monthly.storage, 108.86); assert.equal(priced.cost_monthly.api, 0.3); assert.equal(priced.cost_monthly.ai, 2.7); assert.equal(priced.cost_monthly.total, 111.86);
  const big = plan({ eps: 30000, retention_days: 30 }, profile); assert.equal(big.compute.fits_one_measured_node, false); assert.match(big.reliability_guard, /split sources/); assert.equal(big.compute.cpu_cores, 2);
  assert.throws(() => plan({ eps: 0, retention_days: 30 }, profile), /invalid_eps/); assert.throws(() => plan({ eps: 10, retention_days: 30 }, null), /capacity_profile_missing/);
  assert.match(plan({ eps: 10, retention_days: 30 }, { ...profile, detection_under_load: { injected: 4, detected: 3, reliability: 0.75 } }).reliability_guard, /missed detections/);
});

test('the live view measures what this installation receives and when storage runs out (CG-129)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'S', stale_seconds: 86400 });
  const lines = Array.from({ length: 30 }, (_, i) => JSON.stringify({ TimeFlowStart: Math.floor(Date.now() / 1000) - 60, SrcAddr: '10.0.0.1', DstAddr: `10.0.1.${i}`, SrcPort: 5000, DstPort: 443, Proto: 6, Bytes: 10, Packets: 1 }));
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'b', kind: 'log.batch', observed_at: new Date().toISOString(), asset: { external_id: 's', hostname: 'S', os_family: 'linux', device_type: 'server', addresses: [] }, details: { batch_id: 'B', source_name: 'f', format: 'goflow-json', lines } }] });
  const l = live(s, { maxDbMb: 100, dbBytes: 10 * 1048576, retentionDays: 365 }); assert.equal(l.events_last_24h, 30); assert.ok(l.days_until_storage_limit > 0); assert.equal(l.retention_days, 365);
});
