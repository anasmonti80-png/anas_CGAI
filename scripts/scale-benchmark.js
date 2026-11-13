// CG-009 scale benchmark: ingests N synthetic devices (default 20,000) into a disposable store
// and measures ingest throughput and the latency of the views an analyst opens most.
// Usage: node scripts/scale-benchmark.js [devices] [--write]
// Synthetic documentation-range data only; nothing leaves this machine.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const devices = Number(process.argv[2] || 20000);
const write = process.argv.includes('--write');
if (!Number.isInteger(devices) || devices < 100 || devices > 100000) throw new Error('devices must be an integer between 100 and 100000');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-scale-'));
const store = new Store(path.join(dir, 'scale.sqlite'));
const domain = new Domain(store);
store.run('INSERT INTO users VALUES (?,?,?,?,?)', 'bench-admin', 'bench-admin', 'benchmark-not-a-password-hash', 'admin', new Date().toISOString());
const source = domain.createSource('bench-admin', { name: 'SYNTHETIC SCALE BENCHMARK', stale_seconds: 86400 });
const families = ['windows', 'linux', 'macos', 'network'], types = ['workstation', 'server', 'switch', 'printer'];
const address = i => `10.${Math.floor(i / 65536) % 256}.${Math.floor(i / 256) % 256}.${i % 256}`;
const now = new Date().toISOString();

const t0 = performance.now();
for (let start = 0; start < devices; start += 250) {
  const events = [];
  for (let i = start; i < Math.min(start + 250, devices); i++) events.push({ event_id: `scale-${i}`, kind: 'asset.observed', observed_at: now, asset: { external_id: `SCALE-${String(i).padStart(6, '0')}`, hostname: `SCALE-HOST-${i}`, os_family: families[i % 4], device_type: types[i % 4], addresses: [address(i + 1)] }, details: {} });
  domain.ingest('bench-admin', source.id, { schema_version: 'cg.telemetry/1', events });
}
const ingestMs = performance.now() - t0;

const time = (name, fn, runs = 5) => { fn(); const samples = []; for (let r = 0; r < runs; r++) { const s = performance.now(); fn(); samples.push(performance.now() - s); } samples.sort((a, b) => a - b); return { name, median_ms: Math.round(samples[Math.floor(runs / 2)] * 10) / 10, max_ms: Math.round(samples[runs - 1] * 10) / 10 }; };
const checks = [
  time('assets first page', () => domain.list('assets', { limit: 25, offset: 0 })),
  time('assets last page', () => domain.list('assets', { limit: 25, offset: devices - 25 })),
  time('assets search by hostname', () => domain.list('assets', { limit: 25, offset: 0, q: `SCALE-HOST-${devices - 7}` })),
  time('dashboard', () => domain.dashboard()),
  time('summary', () => domain.summary()),
  time('evidence readiness', () => domain.evidenceReadiness()),
  time('discovery sequences registry', () => domain.discoverySequences()),
];
const total = domain.list('assets', { limit: 1, offset: 0 }).total;
const report = {
  requirement: 'CG-009', at: new Date().toISOString(), devices_requested: devices, devices_stored: total,
  environment: { platform: process.platform, arch: process.arch, node: process.version, cpus: os.cpus().length, memory_gb: Math.round(os.totalmem() / 2 ** 30) },
  ingest: { batches: Math.ceil(devices / 250), batch_size: 250, total_ms: Math.round(ingestMs), devices_per_second: Math.round(devices / (ingestMs / 1000)) },
  views: checks, budget_ms: 500, within_budget: checks.every(c => c.median_ms <= 500),
  scope: 'Single-node engineering benchmark with synthetic devices. It measures this PC; distributed collector capacity is planned separately in the collector capacity registry.',
};
store.close(); fs.rmSync(dir, { recursive: true, force: true });
if (write) fs.writeFileSync(new URL('../artifacts/scale-benchmark.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));
if (total !== devices || !report.within_budget) process.exitCode = 1;
