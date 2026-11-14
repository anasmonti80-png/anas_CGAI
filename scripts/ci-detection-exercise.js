// CG-027 detection exercise in a disposable lab (the CI runner): ingest an approved lab emulation plan for
// T1110.001 (password guessing), the real Windows Security export taken after the emulation, and the run record,
// then print whether CyberGuard detected it or which detection gap it found. Gaps are findings, not CI failures.
// Usage: node scripts/ci-detection-exercise.js --computer <name> --start <iso> --end <iso> --events <windows-export.json>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { normalizeWindowsExport } from '../lib/windows-events.js';

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, i, all) => (value.startsWith('--') ? [...pairs, [value.slice(2), all[i + 1]]] : pairs), []));
for (const key of ['computer', 'start', 'end', 'events']) if (!args[key]) { console.error(`Missing --${key}`); process.exit(2); }
const target = `windows:${args.computer.toLowerCase()}`, registry = { external_id: 'validation-registry', hostname: null, os_family: 'unknown', device_type: 'server', addresses: [] };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-detection-')), store = new Store(path.join(dir, 'd.sqlite')), domain = new Domain(store);
store.run('INSERT INTO users VALUES (?,?,?,?,?)', 'ci', 'ci', 'ci-not-a-password-hash', 'admin', new Date().toISOString());
const source = domain.createSource('ci', { name: 'CI DETECTION EXERCISE', stale_seconds: 86400 });
const plan = { event_id: `plan-ci-${Date.now()}`, kind: 'validation.test_plan', observed_at: new Date(Date.parse(args.start) - 60000).toISOString(), asset: registry, details: {
  plan_id: 'CI-LAB-T1110', tier: 'adversary-emulation', title: 'Password guessing against the disposable CI runner', authorization_ref: 'repository-ci-lab', approved_by: 'repository owner', second_approver: 'ci workflow review',
  window_start: new Date(Date.parse(args.start) - 60000).toISOString(), window_end: new Date(Date.parse(args.end) + 3600000).toISOString(), environment: 'lab', targets: { asset_refs: [target], networks: [] },
  techniques: [{ id: 'T1110.001', name: 'Brute Force: Password Guessing', expected_detection: 'alert', detection_rules: ['CG-AUTH-FAILURES-5-IN-5M'] }],
  safeguards: { rate_limit_per_minute: null, stop_conditions: ['runner not ephemeral'], rollback: 'GitHub-hosted runner is destroyed after the job', isolation_evidence_ref: 'GitHub-hosted ephemeral runner' }, status: 'approved' } };
const run = { event_id: `run-ci-${Date.now()}`, kind: 'validation.test_run', observed_at: args.end, asset: registry, details: {
  run_id: `ci-t1110-${Date.parse(args.start)}`, plan_id: 'CI-LAB-T1110', started_at: args.start, ended_at: args.end, executed_by: 'github-actions',
  results: [{ technique_id: 'T1110.001', target_ref: target, outcome: 'pass', observation: '6 failed network logons for a non-existent account', evidence_ref: 'ci-detection-exercise' }] } };
domain.ingest('ci', source.id, { schema_version: 'cg.telemetry/1', events: [plan] });
const exported = JSON.parse(fs.readFileSync(args.events, 'utf8').replace(/^﻿/, ''));
const failed = exported.events.filter(e => e.event_id === 4625 && e.time_created >= args.start).length;
let normalized = 0;
try { const parsed = normalizeWindowsExport(exported); normalized = parsed.batch.events.length; domain.ingest('ci', source.id, parsed.batch); } catch (error) { console.log(`Windows export: ${error.code || error.message}`); }
domain.ingest('ci', source.id, { schema_version: 'cg.telemetry/1', events: [run] });
// The exercise ends after the run; evaluate as if the 15-minute settling window has passed.
const clockDomain = new Domain(store, { clock: () => Date.parse(args.end) + 16 * 60000 });
const coverage = clockDomain.detectionCoverage(), x = coverage.items[0];
console.log(`Failed logons (4625) exported since start: ${failed}; telemetry events normalized: ${normalized}`);
console.log(`T1110.001 on ${target}: detection=${x?.detection} gap=${x?.gap || 'none'} alerts=${JSON.stringify(x?.alerts?.map(a => a.rule_id) || [])}`);
console.log('Summary', JSON.stringify(coverage.summary));
store.close(); fs.rmSync(dir, { recursive: true, force: true });
if (!x) process.exit(1);
