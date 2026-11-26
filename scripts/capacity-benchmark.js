// CG-129 Capacity benchmark. Measures on this machine: log ingestion rate (events per second), stored bytes per event,
// CPU time and memory, and detection reliability under load: known attack patterns are hidden in background traffic at
// rising batch sizes and every expected alert must still fire. Synthetic documentation-range data only.
//   node scripts/capacity-benchmark.js [--events 20000] [--write]   (--write saves artifacts/capacity-profile.json)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const total = Number(flag('--events') || 20000); if (!Number.isInteger(total) || total < 1000 || total > 500000) throw new Error('--events must be 1000-500000');
export function runBenchmark(total) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-capacity-')), dbFile = path.join(dir, 'capacity.sqlite'), s = new Store(dbFile), d = new Domain(s);
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'bench', 'bench', 'benchmark-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('bench', { name: 'SYNTHETIC CAPACITY BENCHMARK', stale_seconds: 86400 }), asset = { external_id: 'bench-sensor', hostname: 'BENCH-SENSOR', os_family: 'linux', device_type: 'server', addresses: [] };
  const now = Math.floor(Date.now() / 1000) - 60, flow = (src, dst, port) => JSON.stringify({ TimeFlowStart: now, SrcAddr: src, DstAddr: dst, SrcPort: 40000 + (port % 20000), DstPort: port, Proto: 6, Bytes: 1200, Packets: 4 });
  const sizeBefore = fs.statSync(dbFile).size, cpu0 = process.cpuUsage(), t0 = performance.now(), batchSize = 500; let injected = 0, sent = 0, batch = 0;
  const stages = [];
  while (sent < total) {
    const n = Math.min(batchSize, total - sent), lines = [];
    for (let i = 0; i < n; i++) { const k = sent + i; lines.push(flow(`10.20.${(k >> 8) & 255}.${k & 255}`, `10.30.${(k >> 6) & 255}.${(k * 7) & 255}`, [443, 80, 53, 8443][k % 4])); }
    // Every fourth batch hides one lateral-movement pattern (one host reaching five hosts on SMB) in the noise.
    if (batch % 4 === 0) { const h = `10.99.${(batch >> 8) & 255}.${batch & 255}`; for (let j = 1; j <= 5; j++) lines[j] = flow(h, `10.98.${batch & 255}.${j}`, 445); injected++; }
    const tb = performance.now(); d.ingest('bench', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `cap-${batch}`, kind: 'log.batch', observed_at: new Date().toISOString(), asset, details: { batch_id: `CAP-${batch}`, source_name: 'synthetic flows', format: 'goflow-json', lines } }] });
    stages.push({ batch, ms: performance.now() - tb }); sent += n; batch++;
  }
  const seconds = (performance.now() - t0) / 1000, cpu = process.cpuUsage(cpu0); s.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const detected = s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-NET-LATERAL-015'").n, sizeAfter = fs.statSync(dbFile).size, records = s.get("SELECT COUNT(*) n FROM events WHERE kind='log.batch'").n;
  const ms = stages.map(x => x.ms).sort((a, b) => a - b), p95 = ms[Math.floor(ms.length * 0.95)];
  s.close(); fs.rmSync(dir, { recursive: true, force: true });
  return { schema_version: 'cg.capacity-profile/1', measured_at: new Date().toISOString(), machine: { platform: process.platform, arch: process.arch, cpus: os.cpus().length, cpu_model: os.cpus()[0]?.model || null, total_memory_gb: Math.round(os.totalmem() / 1073741824), node: process.version },
    workload: { events: total, batch_size: batchSize, batches: batch, format: 'goflow-json' }, eps: Math.round(total / seconds), cpu_seconds: Math.round((cpu.user + cpu.system) / 1e4) / 100, eps_per_cpu_core: Math.round(total / ((cpu.user + cpu.system) / 1e6)),
    bytes_per_event: Math.round((sizeAfter - sizeBefore) / total), rss_mb: Math.round(process.memoryUsage().rss / 1048576), batch_latency_ms: { p50: Math.round(ms[Math.floor(ms.length / 2)]), p95: Math.round(p95) }, stored_batches: records,
    detection_under_load: { injected, detected, reliability: injected ? detected / injected : 1 } };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const r = runBenchmark(total); if (args.includes('--write')) fs.writeFileSync(path.join(ROOT, 'artifacts', 'capacity-profile.json'), JSON.stringify(r, null, 2) + '\n');
  console.log(JSON.stringify(r, null, 2)); process.exit(r.detection_under_load.reliability === 1 ? 0 : 1);
}
