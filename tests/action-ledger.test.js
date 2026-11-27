import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { ledger, verifyLedger, scrub } from '../lib/action-ledger.js';
import { grantDeclaredCapabilities } from './helpers/write-grant.js';

test('every command is one hash-chained ledger entry with who, why, ticket, evidence, preflight, API result, outcome and rollback, and no password reaches it (CG-173)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'admin-b']) { s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', `${id}-mfa`, id, `fixture-session-${id}`, 'totp', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString(), digest({ id, now })); }
  const sensors = d.createSource('admin-a', { name: 'Sensors', stale_seconds: 86400 }), responder = d.createSource('admin-a', { name: 'EDR', stale_seconds: 86400, source_type: 'response-connector' });
  const host = { external_id: 'ws-173', hostname: 'WS-173', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.73'] }, target = { device_ref: 'ws-173' };
  const ev = (id, kind, details) => ({ event_id: id, kind, observed_at: new Date(now).toISOString(), asset: host, details }), put = (src, ...e) => { const r = d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: e }); grantDeclaredCapabilities(s, { clock: () => now }); return r; };
  put(sensors, ev('seen', 'asset.observed', {}));
  put(responder, ev('cap', 'response.capability', { connector_id: 'EDR-173', owner_system: 'cyberguard-connector', capabilities: ['endpoint.isolate-device'], target_asset_refs: ['ws-173'], tested_at: new Date(now - 3600000).toISOString(), evidence_ref: 'EDR-TEST-173', status: 'active' }),
    ev('mgmt', 'response.management_preflight', { connector_id: 'EDR-173', action_type: 'endpoint.isolate-device', target_hash: digest(target), protected_role: 'none', management_channel_impact: 'none', alternate_management: { status: 'not-applicable', evidence_ref: null }, captured_at: new Date(now - 60000).toISOString(), evidence_ref: 'MGMT-173' }));
  const assetId = s.get("SELECT a.id FROM assets a JOIN sources s ON s.id=a.source_id WHERE a.external_id='ws-173' AND s.name='Sensors'").id;
  const a = d.previewAction('admin-a', { type: 'endpoint.isolate-device', asset_id: assetId, target, connector_id: 'EDR-173', authorization_ref: 'IR-173', reason: 'Contain WS-173; local admin password=Hunter2! pin: QZ-4411 reset later', ttl_seconds: 600 });
  d.approveAction('admin-b', a.id); d.executeAction('admin-a', a.id);
  d.completeResponseJob(responder.id, a.id, { phase: 'execute', outcome: 'succeeded', observed_state: 'contained', evidence_ref: 'EDR-exec-173', rollback_supported: true });
  now += 30000; put(sensors, ev('probe', 'response.outcome_check', { action_id: a.id, check_type: 'connectivity-probe', expected_state: 'isolated', observed_state: 'isolated', checked_at: new Date(now).toISOString(), method: 'probe', evidence_ref: 'PROBE-173' }));
  now += 30000; s.run('UPDATE mfa_assertions SET verified_at=?,expires_at=?', new Date(now).toISOString(), new Date(now + 5 * 60000).toISOString()); // the rollback happens after the probe, never at the same instant
  d.rollbackAction('admin-a', a.id); d.completeResponseJob(responder.id, a.id, { phase: 'rollback', outcome: 'succeeded', observed_state: 'reconnected', evidence_ref: 'EDR-rollback-173', rollback_supported: true });
  const l = ledger(s, d, { clock: () => now }), e = l.entries[0];
  assert.deepEqual(e.rollback.map(r => r.action), ['action.rollback.requested', 'action.rollback.executed', 'action.rollback.verified'], 'the rollback is part of the entry');
  assert.deepEqual([e.who.requested_by, e.who.approved_by, e.who.dispatched_by, e.who.executed_by, e.ticket, e.why.trigger.kind], ['admin-a', 'admin-b', 'admin-a', 'connector EDR', 'IR-173', 'manual-request']);
  assert.equal(JSON.stringify(l).includes('Hunter2'), false, 'the password never reaches the ledger'); assert.equal(JSON.stringify(l).includes('QZ-4411'), false, 'a value that cannot occur in random hex ids');
  assert.match(e.why.reason, /password=\[REDACTED\]/);
  assert.deepEqual([e.api.status, e.api.result.outcome, e.outcome.state], ['succeeded', 'succeeded', 'verified-effective']);
  assert.ok(e.preflight.dry_run_hash && e.timeline.length >= 3 && e.timeline.every(x => /^[a-f0-9]{64}$/.test(x.audit_hash)));
  assert.deepEqual(verifyLedger(l), { valid: true, broken_at: null });
  const tampered = structuredClone(l); tampered.entries[0].who.approved_by = 'someone-else'; assert.deepEqual(verifyLedger(tampered), { valid: false, broken_at: 0 });
  assert.equal(scrub({ note: 'token=abc123 and passwd: x' }).note, 'token=[REDACTED] and passwd=[REDACTED]');
});
