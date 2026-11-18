import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { remediationAdvice, families } from '../lib/remediation.js';
import { responseActionCatalog } from '../lib/response-actions.js';

const server = { device_type: 'server', os_family: 'linux' };
const known = { service_criticality: 'medium', owner: { owner_id: 'it-ops' }, maintenance_windows: ['Sun 02:00-04:00'] };

test('remediation picks the best fix for the issue, asset type and environment and states why other options do not apply (CG-067)', () => {
  for (const [id, f] of Object.entries(families)) { for (const k of ['title', 'root', 'mitigate', 'compensate', 'verify']) assert.ok(f[k].en && f[k].ar, `${id}.${k} bilingual`); if (f.action) assert.ok(responseActionCatalog[f.action], `${id} action exists`); }
  const kev = { id: 'a1', rule_id: 'CG-VULN-KEV-024' };
  let r = remediationAdvice({ alert: kev, asset: server, context: known, lifecycle: { vendor_support: { status: 'supported' } }, evidenceAgeDays: 1 });
  assert.deepEqual([r.family, r.recommended, r.uncertainty.confidence], ['vulnerability', 'fix-root-cause', 'high']); assert.ok(r.environment_notes.some(n => n.en.startsWith('Server:')));
  // Vendor support ended: patching is not possible; upgrade or replace is recommended and the reason is shown.
  r = remediationAdvice({ alert: kev, asset: server, context: known, lifecycle: { vendor_support: { status: 'ended' } }, evidenceAgeDays: 1 });
  const root = r.options.find(o => o.id === 'fix-root-cause'); assert.equal(root.applies, false); assert.match(root.reason_not_applicable.en, /no longer ships security updates/);
  assert.equal(r.recommended, 'upgrade-or-replace'); assert.ok(r.environment_notes.some(n => /Vendor support has ended/.test(n.en)));
  // Critical endpoint with malware: isolation would stop the service, so containment moves to the network edge.
  r = remediationAdvice({ alert: { id: 'a2', rule_id: 'CG-MAL-LOLBIN-001' }, asset: server, context: { ...known, service_criticality: 'critical', maintenance_windows: [] }, lifecycle: { vendor_support: { status: 'supported' } }, evidenceAgeDays: 0 });
  const contain = r.options.find(o => o.id === 'contain'); assert.equal(contain.applies, false); assert.match(contain.reason_not_applicable.ar, /حافة الشبكة/);
  assert.ok(r.environment_notes.some(n => /no recorded maintenance window/.test(n.en)));
  // Network device and legacy profile notes; unknown facts lower the confidence and are listed, never guessed.
  r = remediationAdvice({ alert: { id: 'a3', rule_id: 'CG-FW-EXPOSE-020' }, asset: { device_type: 'firewall', os_family: 'network' }, context: {}, compatibility: { profile: 'legacy-network-device', support_state: 'unknown' }, evidenceAgeDays: 30 });
  assert.equal(r.asset_type, 'network-device'); assert.ok(r.environment_notes.some(n => /management plane/.test(n.en)) && r.environment_notes.some(n => /Legacy profile/.test(n.en)));
  assert.equal(r.uncertainty.confidence, 'low'); assert.ok(r.uncertainty.unknowns.some(u => /30 days old/.test(u.en)) && r.uncertainty.unknowns.some(u => /owner/.test(u.en)));
  // Rollout stage and an unknown rule family are handled honestly.
  r = remediationAdvice({ alert: { id: 'a4', rule_id: 'CG-HYP-0007' }, asset: null, rolloutStage: 'limited-pilot' });
  assert.equal(r.family, 'hypothesis'); assert.equal(r.asset_type, 'unknown'); assert.ok(r.environment_notes.some(n => /limited-pilot/.test(n.en))); assert.equal(r.uncertainty.confidence, 'low');
  assert.ok(r.limitations.every(l => l.en && l.ar));
});

test('the alert API returns remediation built from the recorded asset context and evidence age (CG-067)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg067-')); const now = Date.now();
  const app = createApp({ dataDir, setupToken: 'remediation-setup-token1', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Remediation-Local-2026!x';
  await fetch(`${base}/api/auth/setup`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ setup_token: 'remediation-setup-token1', username: 'admin', password }) });
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: 'admin', password }) }), cookie = login.headers.get('set-cookie').split(';')[0];
  const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id, source = app.domain.createSource(adminId, { name: 'Server logs', stale_seconds: 86400 });
  const asset = { external_id: 'erp-db-01', hostname: 'ERP-DB-01', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.80'] }, at = new Date(now).toISOString();
  app.domain.ingest(adminId, source.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'ctx', kind: 'asset.context', observed_at: at, asset, details: { owner: { owner_id: 'erp-team', display_name: 'ERP team', contact: null }, business_service: 'ERP', service_name: 'Database', site: 'HQ', data_sensitivity: 'confidential', maintenance_windows: ['Fri 23:00-01:00'], service_criticality: 'critical' } },
    ...Array.from({ length: 5 }, (_, i) => ({ event_id: `f-${i}`, kind: 'auth.failed', observed_at: at, asset, details: { account: 'postgres', source_ip: '198.51.100.81', protocol: 'ssh' } }))] });
  const alert = app.store.get("SELECT id FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'");
  const r = await (await fetch(`${base}/api/alerts/${alert.id}/remediation`, { headers: { Cookie: cookie } })).json();
  assert.deepEqual([r.family, r.asset_type, r.critical_service, r.recommended], ['identity', 'server', true, 'fix-root-cause']);
  assert.equal(r.asset.hostname, 'ERP-DB-01'); assert.ok(r.environment_notes.some(n => /maintenance window \(1 defined\)/.test(n.en)));
  assert.deepEqual(r.uncertainty.unknowns.map(u => u.en), ['Vendor support status is not known']); assert.equal(r.uncertainty.confidence, 'medium');
  assert.equal(r.options.find(o => o.id === 'contain').response_action, 'network.block-ip');
  assert.equal((await fetch(`${base}/api/alerts/00000000-0000-0000-0000-000000000000/remediation`, { headers: { Cookie: cookie } })).status, 404);
});
