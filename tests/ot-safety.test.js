import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';
import { collect } from '../lib/easm.js';

const profile = over => ({ ot_class: 'plc', vendor: 'Synthetic', model: 'PLC-5000', firmware: '2.1.0', purdue_level: 1, protocols: ['modbus', 's7'], process_impact: 'production', reachable_from_it: true, remote_access: 'direct', passive_monitoring: false, logic_backup: 'none', evidence_ref: 'OT-SURVEY-2026-11', ...over });

test('OT safety mode: passive first, no active scanning or validation of OT, separate safety approval, safety systems never changed (CG-100)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg100-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'ot-safety-setup-token-01', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'OtSafety-Local-Test-2026!x', seeds = {};
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password, ...(seeds[u] ? { mfa_code: totpCode(seeds[u], now) } : {}) }) }); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'ot-safety-setup-token-01', username: 'admin', password } });
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id; await app.auth.createUser(adminId, { username: 'safety', password, role: 'analyst' });
  const mfa = async u => { const s = await login(u); seeds[u] = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: s })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seeds[u], now) }, user: s }); return s; };
  const admin = await mfa('admin'), safety = await mfa('safety'), safetyId = app.store.get("SELECT id FROM users WHERE username='safety'").id;
  const src = app.domain.createSource(adminId, { name: 'OT passive monitoring', stale_seconds: 86400 });
  const at = () => new Date(now).toISOString(), plc = { external_id: 'plc-line-3', hostname: 'PLC-LINE-3', os_family: 'unknown', device_type: 'iot', addresses: ['192.0.2.120'] }, sis = { external_id: 'sis-boiler', hostname: 'SIS-BOILER', os_family: 'unknown', device_type: 'iot', addresses: ['192.0.2.121'] };
  const ingest = events => app.domain.ingest(adminId, src.id, { schema_version: 'cg.telemetry/1', events });
  ingest([{ event_id: 'ot-plc', kind: 'ot.asset_profile', observed_at: at(), asset: plc, details: profile({}) }, { event_id: 'ot-sis', kind: 'ot.asset_profile', observed_at: at(), asset: sis, details: profile({ ot_class: 'safety-system', process_impact: 'safety', reachable_from_it: false, remote_access: 'none', passive_monitoring: true, logic_backup: 'offline' }) }]);
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-OT-SAFETY-100'").n, 2, 'IT-reachable controller and direct remote access');
  const ov = (await req('/api/ot-safety', { user: admin })).data; assert.equal(ov.mode, 'passive-first'); assert.deepEqual(ov.exclusions.sort(), ['192.0.2.120', '192.0.2.121']); assert.match(ov.guidance.reference, /SP 800-82 Rev\. 3/);
  assert.deepEqual(ov.profiles.find(p => p.ot_class === 'plc').findings.map(f => f.id), ['it-reaches-control', 'direct-remote-access', 'no-passive-monitoring', 'no-logic-backup', 'cleartext-control-protocol']);
  // Active validation of OT in production is refused; passive or lab plans are allowed.
  const plan = (id, tier, environment) => ({ event_id: `plan-${id}`, kind: 'validation.test_plan', observed_at: at(), asset: plc, details: { plan_id: id, tier, title: 'OT check', authorization_ref: 'CHG-OT-100', approved_by: 'plant-manager', second_approver: tier === 'adversary-emulation' ? 'ciso' : null, window_start: at(), window_end: new Date(now + 3600000).toISOString(), environment, targets: { asset_refs: [], networks: ['192.0.2.112/28'] }, techniques: tier === 'passive' ? [{ id: 'log-analysis', name: null }] : [{ id: 'safe-port-reachability', name: 'Port reachability' }], safeguards: { rate_limit_per_minute: tier === 'passive' ? null : 6, stop_conditions: tier === 'passive' ? [] : ['process alarm'], rollback: null, isolation_evidence_ref: null }, status: 'approved' } });
  assert.throws(() => ingest([plan('OT-ACTIVE', 'low-impact-validation', 'production')]), /ot_active_validation_blocked/);
  assert.equal(ingest([plan('OT-PASSIVE', 'passive', 'production')]).accepted, 1);
  // Active scanning: OT addresses are never contacted even inside the authorized range.
  const contacted = []; const r = await collect({ authorization_ref: 'CHG-EASM-100', owner: 'OT', window_end: new Date(Date.now() + 3600000).toISOString(), networks: ['192.0.2.120/31'], ports: [502], exclusions: ov.exclusions }, { connect: async ip => { contacted.push(ip); return 'closed'; } });
  assert.deepEqual(contacted, []); assert.deepEqual(r.observations.map(o => o.not_probed[0].reason), ['ot-safety-exclusion', 'ot-safety-exclusion']);
  // Response: a safety system never takes a disruptive action; other OT actions need a separate safety approval.
  const sisId = app.store.get("SELECT id FROM assets WHERE external_id='sis-boiler'").id, plcId = app.store.get("SELECT id FROM assets WHERE external_id='plc-line-3'").id;
  assert.equal((await req('/api/actions/preview', { method: 'POST', data: { type: 'endpoint.isolate-device', asset_id: sisId, target: { device_ref: 'sis-boiler' }, connector_id: 'SYNTHETIC-OT', authorization_ref: 'IR-100', reason: 'Contain', ttl_seconds: 600 }, user: admin })).data.error, 'ot_safety_system_action_blocked');
  const actionId = crypto.randomUUID(), ts = at(); app.store.run('INSERT INTO actions(id,type,asset_id,requested_by,approved_by,reason,requested_at,expires_at,preflight_hash,before_value,after_value,status,result,executed_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', actionId, 'network.block-ip', plcId, adminId, adminId, 'Block attacker reaching PLC', ts, new Date(now + 600000).toISOString(), 'x', '{}', '{}', 'approved', null, null);
  assert.throws(() => app.domain.dispatchResponseAction(adminId, actionId), /ot_safety_approval_required/);
  const approval = { action_id: actionId, decision: 'approved', operator_on_site: true, manual_fallback_confirmed: true, process_state: 'maintenance-window', note: 'Line 3 stopped for maintenance' };
  assert.equal((await req('/api/ot-safety/approvals', { method: 'POST', data: approval, user: safety })).data.error, 'not_a_designated_ot_safety_approver');
  assert.equal((await req('/api/ot-safety/approvers', { method: 'POST', data: { user_id: safetyId, qualification_ref: 'ISA/IEC 62443 certified engineer' }, user: safety })).status, 403);
  assert.equal((await req('/api/ot-safety/approvers', { method: 'POST', data: { user_id: safetyId, qualification_ref: 'ISA/IEC 62443 certified engineer' }, user: admin })).status, 201);
  assert.equal((await req('/api/ot-safety/approvers', { method: 'POST', data: { user_id: adminId, qualification_ref: 'Site engineer' }, user: admin })).status, 201);
  assert.equal((await req('/api/ot-safety/approvals', { method: 'POST', data: approval, user: admin })).data.error, 'independent_ot_safety_approver_required');
  assert.equal((await req('/api/ot-safety/approvals', { method: 'POST', data: { ...approval, process_state: 'running-production' }, user: safety })).data.error, 'ot_process_not_in_safe_state');
  assert.equal((await req('/api/ot-safety/approvals', { method: 'POST', data: { ...approval, operator_on_site: false }, user: safety })).data.error, 'ot_approval_requires_operator_and_manual_fallback');
  assert.equal((await req('/api/ot-safety/approvals', { method: 'POST', data: approval, user: safety })).data.decision, 'approved');
  assert.throws(() => app.domain.dispatchResponseAction(adminId, actionId), e => e.code !== 'ot_safety_approval_required', 'after the safety approval the normal response checks apply');
  assert.ok(app.store.all("SELECT action FROM audit WHERE action LIKE 'ot.%'").map(r => r.action).includes('ot.safety_approved'));
  assert.ok(ov.claim_ar.includes('قراءة سلبية أولًا'));
});
