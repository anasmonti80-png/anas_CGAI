import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { contractView, validateContract } from '../lib/data-contract.js';
import { normalizeWindowsExport } from '../lib/windows-events.js';

const asset = { external_id: 'h1', hostname: 'h1', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.5'] };
const contract = { connector: 'lab-agent', connector_version: '2.1.0', event_source: 'auth log', time_zone: 'Asia/Riyadh', clock_source: 'ntp' };

test('each connector shows its declared contract, schema and parser versions, raw hash coverage, field completeness and delay (CG-162)', t => {
  assert.deepEqual(validateContract(contract), contract);
  assert.equal(validateContract({ ...contract, time_zone: '+03:00' }).time_zone, '+03:00');
  assert.throws(() => validateContract({ ...contract, time_zone: 'Mars/Olympus' }), /invalid_contract_time_zone/);
  assert.throws(() => validateContract({ ...contract, clock_source: 'sundial' }), /invalid_contract_clock_source/);
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const agent = dom.createSource('a', { name: 'Lab agent', stale_seconds: 86400 }), bare = dom.createSource('a', { name: 'Bare', stale_seconds: 86400 });
  const at = new Date(Date.now() - 120000).toISOString();
  dom.ingest('a', agent.id, { schema_version: 'cg.telemetry/1', contract, events: [
    { event_id: 'x1', kind: 'auth.failed', observed_at: at, asset, details: { account: 'svc', source_ip: '198.51.100.1', protocol: 'ssh' } },
    { event_id: 'x2', kind: 'auth.failed', observed_at: at, asset: { ...asset, addresses: [] }, details: { account: 'svc', source_ip: null, protocol: 'ssh' } }] });
  dom.ingest('a', bare.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'y1', kind: 'asset.observed', observed_at: at, asset, details: {} }] });
  const v = contractView(s), a = v.sources.find(x => x.name === 'Lab agent'), b = v.sources.find(x => x.name === 'Bare');
  assert.deepEqual([a.contract.time_zone, a.contract.clock_source, a.schema_versions, a.parser_versions, a.raw_hash_pct], ['Asia/Riyadh', 'ntp', ['cg.telemetry/1'], ['cg-json/1'], 100]);
  assert.deepEqual(a.completeness[0], { kind: 'auth.failed', events: 2, field_completeness: 83.3, asset_completeness: 75, most_missing: [{ field: 'source_ip', missing_pct: 50 }] });
  assert.ok(a.delay_seconds.median >= 119); assert.deepEqual(a.issues, []);
  assert.deepEqual(b.issues, ['no-declared-contract']);
  // The Windows converter declares its parser contract; its events keep the raw record hash.
  const w = normalizeWindowsExport({ schema_version: 'cg.windows-export/1', computer: 'WS1', boot_time: '2026-11-01T00:00:00.000Z', events: [{ event_id: 4625, record_id: 1, time_created: at, provider: 'Microsoft-Windows-Security-Auditing', channel: 'Security', data: { LogonType: '10', TargetUserName: 'u', TargetDomainName: 'LAB', IpAddress: '198.51.100.2' } }] }, Date.now());
  assert.equal(w.batch.contract.connector_version, 'windows-security/1');
});

test('batches refused by validation are recorded per connector with their code and give the parse failure rate (CG-162)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = dom.createSource('a', { name: 'Flaky parser', stale_seconds: 86400 }), now = new Date(Date.now() - 1000).toISOString();
  dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', contract: { ...contract, clock_source: 'host-unsynced' }, events: [{ event_id: 'ok1', kind: 'asset.observed', observed_at: now, asset, details: {} }] });
  assert.throws(() => dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'f1', kind: 'asset.observed', observed_at: new Date(Date.now() + 3600000).toISOString(), asset, details: {} }, { event_id: 'f2', kind: 'asset.observed', observed_at: now, asset, details: {} }] }), /invalid_observed_at/);
  assert.throws(() => dom.ingest('a', src.id, { schema_version: 'cg.telemetry/0', events: [] }), /unsupported_schema/);
  assert.throws(() => dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', contract: { ...contract, time_zone: 'Nowhere/Here' }, events: [{ event_id: 'f3', kind: 'asset.observed', observed_at: now, asset, details: {} }] }), /invalid_contract_time_zone/);
  const x = contractView(s).sources[0];
  assert.deepEqual([x.accepted_events, x.rejected_events, x.rejected_batches, x.parse_failure_pct], [1, 3, 3, 75]);
  assert.deepEqual(x.rejections.map(r => r.code).sort(), ['invalid_contract_time_zone', 'invalid_observed_at', 'unsupported_schema']);
  assert.deepEqual(x.issues, ['clock-source-unverified', 'parse-failures', 'clock-ahead-or-invalid-time']);
  assert.equal(s.get('SELECT COUNT(*) n FROM events').n, 1, 'a refused batch stores no event');
});
