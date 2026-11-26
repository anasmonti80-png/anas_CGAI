import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseWorkloadExports, assessWorkloads, workloadView } from '../lib/workload-identity.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), F = n => path.join(ROOT, 'tests/fixtures/azure/workload', n), read = n => JSON.parse(fs.readFileSync(F(n), 'utf8'));
const TENANT = '00000000-0000-0000-0000-000000000149', PAYROLL = '11111111-0000-4000-8000-000000000001', MI = '11111111-0000-4000-8000-000000000003';
const signIns = now => { const at = h => new Date(now - h * 3600000).toISOString(), ok = { errorCode: 0 };
  return { value: [
    ...[200, 150, 100, 60, 30].map(h => ({ createdDateTime: at(h), appId: PAYROLL, ipAddress: '198.51.100.10', location: { countryOrRegion: 'SA' }, status: ok })),
    { createdDateTime: at(2), appId: PAYROLL, ipAddress: '203.0.113.77', location: { countryOrRegion: 'NL' }, status: ok },
    { createdDateTime: at(3), appId: PAYROLL, ipAddress: '203.0.113.99', location: { countryOrRegion: 'NL' }, status: { errorCode: 7000215 } },
    ...[100, 50].map(h => ({ createdDateTime: at(h), appId: MI, ipAddress: '198.51.100.20', location: { countryOrRegion: 'SA' }, status: ok })),
    { createdDateTime: at(1), appId: MI, ipAddress: '198.51.100.21', location: { countryOrRegion: 'SA' }, status: ok },
  ] }; };

test('service principals are classed by Conditional Access coverage and credential, consent and app role changes raise alerts (CG-149)', t => {
  const now = Date.parse('2026-11-26T12:00:00Z');
  const d = parseWorkloadExports({ tenantId: TENANT, servicePrincipals: read('service-principals.json'), applications: read('applications.json'), audits: read('audits.json'), policies: read('ca-policies.json'), signIns: { value: [] } });
  assert.deepEqual(d.service_principals.map(s => s.kind), ['single-tenant', 'single-tenant', 'managed-identity', 'multitenant-or-third-party'], 'kind comes from the type and the owner tenant');
  assert.equal(d.ca_policies.length, 1, 'only policies with client application conditions target workload identities');
  assert.equal(d.audits.length, 2, 'only application management activities that change capability are kept');
  const a = assessWorkloads(d, now), ca = Object.fromEntries(a.service_principals.map(s => [s.name, s.ca.state]));
  assert.deepEqual(ca, { 'payroll-sync': 'covered', 'backup-runner': 'not-covered', 'vm-automation-identity': 'not-coverable', 'Example SaaS Connector': 'not-coverable' }, 'an excluded single-tenant app is not covered; managed and multitenant identities are never coverable');
  assert.deepEqual(a.ca_scope, [{ policy: 'Block workload identities outside trusted ranges', all_in_tenant: true, managed_identities_outside: 1, multitenant_outside: 1 }]);
  assert.deepEqual(a.credentials.map(c => c.finding).sort(), ['client-secret-in-use', 'expired', 'long-lived-secret']);
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = dom.createSource('a', { name: 'Entra', stale_seconds: 86400 });
  const ev = { schema_version: 'cg.telemetry/1', events: [{ event_id: 'wl-1', kind: 'identity.workload_identities', observed_at: new Date(now).toISOString(), asset: { external_id: `entra:${TENANT}`, hostname: 'Entra', os_family: 'unknown', device_type: 'unknown', addresses: [] }, details: { authorization_ref: 'SEC-149', ...d } }] };
  dom.ingest('a', src.id, ev); dom.ingest('a', src.id, { ...ev, events: [{ ...ev.events[0], event_id: 'wl-2' }] });
  const rules = s.all("SELECT rule_id,severity FROM alerts WHERE rule_id LIKE 'CG-WORKLOAD-%' ORDER BY rule_id");
  assert.deepEqual(rules.map(r => `${r.rule_id}:${r.severity}`), ['CG-WORKLOAD-CA-SCOPE-149:medium', 'CG-WORKLOAD-CONSENT-149:high', 'CG-WORKLOAD-CREDENTIAL-149:high'], 'a repeated export does not duplicate alerts');
});

test('a service principal sign-in from a new country or address after its own history raises an alert, and managed identities and multitenant apps are never shown as covered (CG-149)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg149-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Entra', stale_seconds: 86400 });
  const si = path.join(dir, 'signins.json'); fs.writeFileSync(si, JSON.stringify(signIns(Date.now())));
  const run = extra => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/entra-workload-identity.js'), '--tenant-id', TENANT, '--authorization-ref', 'SEC-149', ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  const r = run(['--service-principals', F('service-principals.json'), '--applications', F('applications.json'), '--signins', si, '--audits', F('audits.json'), '--ca-policies', F('ca-policies.json')]);
  assert.equal(r.status, 0, r.stderr);
  const v = workloadView(s).tenants[0];
  assert.deepEqual(v.deviations.map(x => [x.name, x.reason, x.severity]), [['payroll-sync', 'new-country', 'high'], ['vm-automation-identity', 'new-address', 'medium']], 'failed sign-ins are not deviations');
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-WORKLOAD-SIGNIN-149' ORDER BY severity").map(x => x.severity), ['high', 'medium']);
  assert.ok(v.service_principals.filter(x => x.kind !== 'single-tenant').every(x => x.ca.state === 'not-coverable'));
  assert.equal(run(['--service-principals', F('service-principals.json')]).status, 0, 'only the service principal export is required');
  assert.equal(run(['--service-principals', F('applications.json')]).status, 2, 'an applications file is not a service principal export');
});
