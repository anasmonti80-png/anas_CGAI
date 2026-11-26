import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { parseAuthPosture, assessAuthPosture, methodTier, authPostureView } from '../lib/phishing-resistant.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), F = n => path.join(ROOT, 'tests/fixtures/azure/auth', n), read = n => JSON.parse(fs.readFileSync(F(n), 'utf8'));
const TENANT = '00000000-0000-0000-0000-000000000150';

test('generic MFA is not phishing-resistant: methods are ranked by CISA tiers, unknown methods stay unclassified and registration is not enforcement (CG-150)', () => {
  assert.deepEqual(['passKeyDeviceBound', 'fido2', 'windowsHelloForBusiness', 'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'mobilePhone', 'email', 'futureMethodX'].map(methodTier),
    ['phishing-resistant', 'phishing-resistant', 'phishing-resistant', 'app-or-otp', 'app-or-otp', 'sms-voice', 'not-mfa', 'unclassified']);
  const d = parseAuthPosture({ tenantId: TENANT, registrations: read('registrations.json'), policies: read('ca-policies.json'), signIns: read('signins.json'), exceptions: read('exceptions.json') });
  const a = assessAuthPosture(d, Date.parse('2026-11-26T00:00:00Z'));
  assert.deepEqual(a.users, { total: 7, 'phishing-resistant': 2, 'app-or-otp': 2, 'sms-voice': 1, 'not-mfa': 1, none: 1 });
  assert.deepEqual(a.admins_without_phishing_resistant, [{ upn: 'admin2@lab.example', tier: 'app-or-otp' }], 'push MFA is MFA, not phishing-resistant');
  assert.deepEqual(a.unclassified_methods, ['futureMethodX']);
  assert.deepEqual(d.policies.map(p => [p.strength, p.scope]), [['phishing-resistant', 'roles'], ['mfa', 'all'], ['none', 'all']]);
  assert.equal(a.enforcement, 'some-users', 'the phishing-resistant strength is required only for admin roles');
  assert.equal(a.legacy_blocked, false, 'a report-only legacy block is not a block');
  assert.deepEqual(a.legacy.by_client, { IMAP4: 1, 'Authenticated SMTP': 1 }, 'failed legacy attempts and modern clients are not counted');
  assert.deepEqual(a.exceptions.map(x => x.review_overdue), [true, false]);
  assert.throws(() => parseAuthPosture({ tenantId: TENANT, registrations: { value: [{ id: 'x' }] } }), /not_user_registration_details_export/);
  assert.throws(() => parseAuthPosture({ tenantId: TENANT, registrations: read('registrations.json'), exceptions: [{ app: 'x' }] }), /invalid_auth_exception/, 'an exception needs a reason and an owner');
});

test('administrators without phishing-resistant methods, missing enforcement and successful legacy protocol sign-ins raise alerts while declared app exceptions are tracked (CG-150)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg150-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Entra', stale_seconds: 86400 });
  const run = extra => { const out = path.join(dir, `o-${Math.random()}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/auth-strength-posture.js'), '--tenant-id', TENANT, '--authorization-ref', 'SEC-150', ...extra, '--output', out], { encoding: 'utf8' }); if (r.status === 0) d.ingest('a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); return r; };
  assert.equal(run(['--registrations', F('registrations.json'), '--ca-policies', F('ca-policies.json'), '--signins', F('signins.json'), '--exceptions', F('exceptions.json')]).status, 0);
  const rules = s.all("SELECT rule_id FROM alerts WHERE rule_id LIKE 'CG-%-150' ORDER BY rule_id").map(x => x.rule_id);
  assert.deepEqual(rules, ['CG-LEGACY-AUTH-150', 'CG-LEGACY-AUTH-150', 'CG-PHISHRES-ADMIN-150'], 'admin policy exists, so enforcement is partial and raises nothing');
  const noPolicies = { value: read('ca-policies.json').value.filter(p => p.id !== 'p1') }, f2 = path.join(dir, 'ca2.json'); fs.writeFileSync(f2, JSON.stringify(noPolicies));
  assert.equal(run(['--registrations', F('registrations.json'), '--ca-policies', f2]).status, 0);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-PHISHRES-ENFORCE-150'").length, 1, 'generic MFA for all users is not phishing-resistant enforcement');
  assert.equal(authPostureView(s).tenants[0].enforcement, 'not-enforced');
  assert.equal(run(['--registrations', F('ca-policies.json')]).status, 2, 'a policy file is not a registration report');
});
