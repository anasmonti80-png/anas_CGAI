import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { normalizeLogLines } from '../lib/log-normalizer.js';
import { nsgFlowMigration, nsgFlowLines, nsgFlowLogsRetirement } from '../lib/connectors/azure.js';

const dir = fileURLToPath(new URL('./fixtures/azure/', import.meta.url)), fx = n => fs.readFileSync(path.join(dir, n), 'utf8');

test('every NSG flow log is matched to its VNets: migrate, covered (disable to avoid double charges) or NIC-only (CG-051)', () => {
  assert.equal(nsgFlowLogsRetirement, '2027-09-30T00:00:00.000Z');
  const plan = nsgFlowMigration(JSON.parse(fx('resource-graph.json')).data, Date.parse('2026-11-18T00:00:00Z'));
  assert.deepEqual(plan.map(x => [x.nsg, x.status, x.vnets, x.vnets_without_flow_log]), [
    ['web-nsg', 'covered-disable-nsg-log', ['hub-vnet'], []],
    ['app-nic-nsg', 'nic-only-attachment', [], []],
    ['dev-nsg', 'migrate', ['dev-vnet'], ['dev-vnet']]]);
  assert.equal(plan[0].days_to_retirement, 316); assert.equal(plan[2].subscription, '22222222-2222-4222-8222-222222222222');
  assert.equal(nsgFlowMigration([], Date.now()).length, 0, 'no NSG flow logs, nothing to migrate');
});

test('existing NSG flow log files stay readable in the common flow model until retirement (CG-051)', () => {
  const r = normalizeLogLines('azure-nsg-flow-json', nsgFlowLines(fx('nsg-flow.json'))).records;
  assert.deepEqual(r.map(x => [x.action, x.dst_port, x.protocol, x.outcome]), [['blocked', 3389, 'tcp', 'begin'], ['allowed', 443, 'tcp', 'end']]);
  assert.equal(r[1].bytes, 5020); assert.equal(r[0].host, 'DEV-NSG'); assert.match(r[0].message, /retiring 2027-09-30/);
});

test('uncovered NSG flow logs raise alerts that become high in the last 90 days, and the plan is served with live days left (CG-051)', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg051-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const out = path.join(tmp, 'inv.json'), script = fileURLToPath(new URL('../scripts/azure-connector.js', import.meta.url));
  execFileSync(process.execPath, [script, 'inventory', '--input', path.join(dir, 'subscriptions.json'), '--graph', path.join(dir, 'resource-graph.json'), '--access', path.join(dir, 'access.json'), '--output', out]);
  const file = JSON.parse(fs.readFileSync(out, 'utf8')), mig = file.events.find(e => e.kind === 'cloud.nsg_flow_migration');
  assert.ok(mig && mig.details.items.length === 3 && !('days_to_retirement' in mig.details.items[0]), 'the plan stores facts; days left are computed when read');
  for (const [clock, severity] of [['2026-11-18T08:00:00.000Z', 'medium'], ['2027-08-01T08:00:00.000Z', 'high']]) {
    const s = new Store(':memory:'); t.after(() => s.close());
    const now = Date.parse(clock), d = new Domain(s, { clock: () => now });
    s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', clock);
    const src = d.createSource('admin-a', { name: 'Azure', stale_seconds: 86400, source_type: 'generic' });
    d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: file.events.map(e => ({ ...e, observed_at: clock })) });
    const alerts = d.list('alerts', { limit: 100 }).items.filter(a => a.rule_id === 'CG-AZURE-NSGFLOW-051');
    assert.deepEqual(alerts.map(a => a.severity), [severity, severity], 'dev-nsg (migrate) and app-nic-nsg (NIC only); the covered one only needs disabling');
    const p = d.nsgFlowMigration(); assert.deepEqual(p.counts, { nsg_flow_logs: 3, migrate: 1, covered: 1, nic_only: 1, not_attached: 0 }); assert.equal(p.days_to_retirement, Math.ceil((Date.parse('2027-09-30T00:00:00Z') - now) / 86400000));
    assert.ok(alerts.some(a => /dev-nsg \(enable on dev-vnet\)/.test(a.title)));
  }
});
