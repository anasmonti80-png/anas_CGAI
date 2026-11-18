import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { awsRoleGrant, awsRootGrant, azureRoleGrants, entraDirectoryRoleGrants, gcpMemberGrants, reviewGrant, privilegeOf } from '../lib/cloud-access.js';

const dir = fileURLToPath(new URL('./fixtures/cloud-access/', import.meta.url)), fx = n => fs.readFileSync(path.join(dir, n), 'utf8');
const SA = 'serviceAccount:cyberguard-reader@example-prod-1234.iam.gserviceaccount.com', now = Date.parse('2026-11-18T12:00:00Z');
const status = g => { const r = reviewGrant(g, now); return [r.status, ...r.reasons].join(':'); };

test('cloud access review flags root keys, standing administrators and standing or organisation-wide write access (CG-049)', () => {
  assert.deepEqual([privilegeOf(['SecurityAudit']), privilegeOf(['Contributor']), privilegeOf(['Owner']), privilegeOf(['roles/viewer', 'roles/iam.securityReviewer'])], ['read', 'write', 'admin', 'read']);
  const ro = awsRoleGrant(fx('aws-get-role-readonly.json'), fx('aws-attached-readonly.json'), '444455556666');
  assert.equal(status(ro), 'compliant'); assert.deepEqual(ro.conditions, ['external id required']);
  assert.equal(status(awsRoleGrant(fx('aws-get-role-admin.json'), fx('aws-attached-admin.json'), '444455556666')), 'violation:admin-not-time-bound:session-too-long');
  assert.equal(status(awsRootGrant(fx('aws-account-summary.json'), '444455556666')), 'violation:root-credentials:standing-admin');
  assert.equal(awsRootGrant(JSON.stringify({ SummaryMap: { AccountAccessKeysPresent: 0 } }), '1'), null, 'no root access keys, nothing to review');
  const az = Object.fromEntries(azureRoleGrants(fx('azure-active.json'), fx('azure-eligible.json')).map(g => [`${g.roles[0]}:${g.mechanism}`, status(g)]));
  assert.deepEqual(az, { 'Reader:standing-assignment': 'warning:standing-read', 'Owner:pim-activation': 'compliant', 'Contributor:standing-assignment': 'violation:standing-write:broad-write-scope', 'Owner:pim-eligible': 'compliant' });
  const entra = entraDirectoryRoleGrants(fx('entra-active.json'), fx('entra-eligible.json'), 'contoso');
  assert.deepEqual(entra.map(g => [g.principal_ref, status(g)]), [['breakglass-old@contoso.example', 'violation:standing-admin'], ['cyberguard-reader@contoso.example', 'warning:broad-read-scope:standing-read'], ['admin@contoso.example', 'compliant']]);
  const gcp = gcpMemberGrants(fx('gcp-policy.json'), SA, 'projects/example-prod-1234');
  assert.deepEqual(gcp.map(g => [g.roles[0], g.mechanism, status(g)]), [['roles/viewer', 'standing-assignment', 'warning:standing-read'], ['roles/iam.securityReviewer', 'conditional-binding', 'compliant'], ['roles/owner', 'standing-assignment', 'violation:standing-admin'], ['roles/securitycenter.findingsViewer', 'conditional-binding', 'expired:expired']]);
  assert.equal(status(gcpMemberGrants(fx('gcp-policy.json'), SA, 'projects/example-prod-1234', { impersonated: true })[0]), 'compliant', 'a short-lived impersonated token is temporary access');
});

test('cloud access reviews raise alerts for violations and the API orders violations first (CG-049)', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cg049-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const script = fileURLToPath(new URL('../scripts/cloud-access-review.js', import.meta.url)), F = n => path.join(dir, n);
  const run = (mode, extra) => { const out = path.join(tmp, `${mode}.json`); execFileSync(process.execPath, [script, mode, ...extra, '--output', out]); return JSON.parse(fs.readFileSync(out, 'utf8')); };
  const s = new Store(':memory:'); t.after(() => s.close());
  const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Cloud access review', stale_seconds: 86400, source_type: 'generic' }), ingest = f => d.ingest('admin-a', src.id, f);
  ingest(run('aws-role', ['--role', F('aws-get-role-readonly.json'), '--attached', F('aws-attached-readonly.json'), '--account', '444455556666']));
  ingest(run('aws-root', ['--summary', F('aws-account-summary.json'), '--account', '444455556666']));
  ingest(run('azure-rbac', ['--active', F('azure-active.json'), '--eligible', F('azure-eligible.json')]));
  ingest(run('entra-roles', ['--active', F('entra-active.json'), '--eligible', F('entra-eligible.json'), '--tenant', 'contoso']));
  ingest(run('gcp-bindings', ['--policy', F('gcp-policy.json'), '--member', SA, '--scope', 'projects/example-prod-1234']));
  const r = d.cloudAccessReview();
  assert.deepEqual(r.counts, { total: 13, violation: 4, warning: 3, compliant: 5, expired: 1, temporary: 5 });
  assert.equal(r.items[0].status, 'violation'); assert.equal(r.items.at(-1).status, 'expired');
  const alerts = d.list('alerts', { limit: 100 }).items.filter(a => a.rule_id === 'CG-CLOUD-ACCESS-049');
  assert.equal(alerts.length, 4); assert.equal(alerts.filter(a => a.severity === 'critical').length, 3, 'root keys and standing administrators are critical');
  assert.ok(alerts.some(a => /Contributor for legacy-deploy on \/providers\/Microsoft.Management\/managementGroups\/root-mg/.test(a.title)));
  assert.throws(() => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'bad', kind: 'cloud.access_grant', observed_at: new Date().toISOString(), asset: { external_id: 'x', hostname: 'x', os_family: 'unknown', device_type: 'unknown', addresses: [] }, details: { review_id: 'r', grants: [{ grant_id: 'g', provider: 'aws', scope_type: 'account', scope_ref: '1', principal_ref: 'p', roles: ['x'], privilege: 'root', mechanism: 'assume-role', max_session_seconds: 900, expires_at: null, conditions: [], evidence_ref: null }] } }] }), /cloud_grant_0_privilege/);
});

test('connector templates and live modes keep CyberGuard on temporary read-only access (CG-049)', () => {
  const yaml = fs.readFileSync(new URL('../deploy/aws/cyberguard-readonly-role.yaml', import.meta.url), 'utf8'), aws = fs.readFileSync(new URL('../scripts/aws-connector.js', import.meta.url), 'utf8');
  assert.match(yaml, /MaxSessionDuration: 3600/); assert.match(aws, /Math\.min\(Number\(args\['session-seconds'\]\) \|\| 900, 3600\)/, 'live sessions default to 15 minutes and never exceed one hour');
  assert.match(fs.readFileSync(new URL('../scripts/gcp-connector.js', import.meta.url), 'utf8'), /--impersonate-service-account/);
  assert.match(fs.readFileSync(new URL('../scripts/azure-connector.js', import.meta.url), 'utf8'), /roleEligibilityScheduleInstances/);
  const roles = JSON.parse(fs.readFileSync(new URL('../deploy/gcp/cyberguard-viewer-roles.json', import.meta.url), 'utf8'));
  for (const r of roles.roles) assert.equal(privilegeOf([r.role]), 'read', r.role);
  const azureRole = JSON.parse(fs.readFileSync(new URL('../deploy/azure/cyberguard-reader-role.json', import.meta.url), 'utf8'));
  assert.ok(azureRole.AssignableScopes.every(s => /subscriptions\//.test(s)), 'the Azure reader role is assigned per subscription');
});
