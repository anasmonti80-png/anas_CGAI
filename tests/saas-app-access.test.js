import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseEntra, parseGoogle, consentPolicy, countFileExposure, assessAppAccess, appAccessView } from '../lib/saas-app-access.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), F = n => path.join(ROOT, 'tests/fixtures/saas', n), read = n => JSON.parse(fs.readFileSync(F(n), 'utf8'));
const TENANT = '00000000-0000-4000-8000-000000000159';
const ev = (id, details) => ({ event_id: id, kind: 'identity.saas_app_access', observed_at: new Date().toISOString(), asset: { external_id: `${details.provider}:${details.tenant_ref}`, hostname: details.tenant_ref, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details });

test('Entra and Google app access is inventoried with consent policy, verified or reviewed apps, high-risk scopes and user counts only, and risky access raises alerts (CG-159)', t => {
  assert.equal(consentPolicy({ defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ['ManagePermissionGrantsForOwnedResource.DeveloperConsent'] } }), 'disabled', 'only owned-resource policies means user consent is off');
  assert.equal(consentPolicy({ defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ['managePermissionGrantsForSelf.microsoft-user-default-low'] } }), 'verified-low');
  const e = parseEntra({ authorizationPolicy: read('entra/authorization-policy.json'), servicePrincipals: read('entra/service-principals.json'), grants: read('entra/grants.json'), tenantId: TENANT });
  assert.equal(e.consent_policy, 'all-apps');
  const app = n => e.apps.find(a => a.name === n);
  assert.deepEqual([app('Contoso Mail Sync').users, app('Contoso Mail Sync').scopes], [2, ['Mail.Read', 'offline_access', 'openid']]);
  assert.equal(JSON.stringify(e).includes('user-a'), false, 'user identifiers are reduced to counts');
  assert.deepEqual([app('Fabrikam Analytics').admin_consent, app('Fabrikam Analytics').publisher_verified, app('Internal HR Portal').internal], [true, true, true]);
  const ea = assessAppAccess({ provider: 'entra', tenant_ref: 'lab', consent_policy: e.consent_policy, sharing: { level: 'anyone', anyone_link_expiration_days: null }, file_exposure: null, apps: e.apps });
  const af = n => ea.apps.find(a => a.name === n).findings;
  assert.deepEqual([af('Contoso Mail Sync'), af('Fabrikam Analytics'), af('Internal HR Portal'), af('Quick Notes Add-in')], [['unverified-high-risk'], ['tenant-wide-high-risk'], [], ['unverified-publisher']]);
  assert.deepEqual(ea.findings.map(f => [f.type, f.severity]).slice(0, 2), [['user-consent-any-app', 'high'], ['unverified-high-risk', 'high']]);
  assert.ok(ea.findings.some(f => f.type === 'anyone-links-no-expiry'));

  const g = parseGoogle({ tokens: read('google/tokens.json'), appAccess: read('google/app-access.json'), unconfigured: 'allow-all' });
  const ga = assessAppAccess({ provider: 'google', tenant_ref: 'lab', consent_policy: g.consent_policy, sharing: null, file_exposure: null, apps: g.apps }), gf = n => ga.apps.find(a => a.name === n);
  assert.deepEqual([gf('Mail Merge Helper').users, gf('Mail Merge Helper').findings], [2, ['unreviewed-high-risk']], 'an unconfigured app with full mail access is shadow IT');
  assert.deepEqual([gf('Calendar Scheduler').findings, gf('Calendar Scheduler').reviewed], [[], true]);
  assert.deepEqual(gf('Old Drive Tool').findings, ['blocked-app-holds-tokens']);
  assert.deepEqual(gf('Quiz Sign-in').findings, ['unreviewed-app', 'anonymous-client']);
  assert.equal(ga.summary.unreviewed, 2);

  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = dom.createSource('a', { name: 'SaaS', stale_seconds: 86400 });
  dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [ev('saas-e', { provider: 'entra', tenant_ref: 'lab-m365', authorization_ref: 'SEC-159', privacy_policy_ref: null, consent_policy: e.consent_policy, sharing: { level: 'anyone', anyone_link_expiration_days: null }, file_exposure: null, apps: e.apps })] });
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-SAAS-APP-ACCESS-159' ORDER BY severity").map(x => x.severity), ['high', 'high', 'medium', 'medium'], 'open consent, the unverified mail app, tenant-wide file access and anyone links; low findings are shown, not alerted');
  assert.throws(() => dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [ev('saas-x', { provider: 'google', tenant_ref: 'lab', authorization_ref: 'SEC-159', privacy_policy_ref: null, consent_policy: 'allow-all', sharing: null, file_exposure: { files_reviewed: 1, anyone_discoverable: 1, anyone_with_link: 0, domain_discoverable: 0, shared_externally: 0, external_domains: 0 }, apps: [] })] }), /file_sharing_requires_privacy_policy/);
  const v = appAccessView(s); assert.equal(v.tenants.length, 1); assert.equal(v.tenants[0].summary.apps, 4);
});

test('file sharing is counted without names and only under a privacy policy, and content is never imported (CG-159)', t => {
  const c = countFileExposure(read('google/file-permissions.json'), ['example.com']);
  assert.deepEqual(c, { files_reviewed: 4, anyone_discoverable: 1, anyone_with_link: 1, domain_discoverable: 1, shared_externally: 1, external_domains: 1 });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg159-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const run = (extra, out) => spawnSync(process.execPath, [path.join(ROOT, 'scripts/saas-app-access.js'), '--provider', 'google', '--tenant-ref', 'lab', '--authorization-ref', 'SEC-159', '--tokens', F('google/tokens.json'), '--app-access', F('google/app-access.json'), '--unconfigured', 'allow-all', ...extra, '--output', path.join(dir, out)], { encoding: 'utf8' });
  let r = run(['--file-permissions', F('google/file-permissions.json'), '--internal-domains', 'example.com'], 'a.json');
  assert.equal(r.status, 2); assert.match(r.stderr, /privacy policy/);
  r = run(['--mail'], 'b.json'); assert.equal(r.status, 2); assert.match(r.stderr, /never imported/);
  r = run(['--file-permissions', F('google/file-permissions.json'), '--internal-domains', 'example.com', '--privacy-policy-ref', 'HR-PRIV-7'], 'c.json');
  assert.equal(r.status, 0, r.stderr); const out = JSON.parse(r.stdout.trim()); assert.deepEqual([out.apps, out.unreviewed, out.file_exposure], [4, 2, true]);
  const written = fs.readFileSync(path.join(dir, 'c.json'), 'utf8'); assert.equal(written.includes('ignored-by-cyberguard') || written.includes('109000000000000000001') || written.includes('partner.example'), false, 'no file names, user keys or external addresses are written');
});
