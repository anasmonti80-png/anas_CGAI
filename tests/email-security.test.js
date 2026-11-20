import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { domainPosture, analyseEml, forwardingChanges } from '../lib/email-security.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = n => path.join(ROOT, 'tests/fixtures/email', n);
const resolverFor = records => ({ resolveTxt: async n => { if (!records[n]) { const e = new Error('ENODATA'); e.code = 'ENODATA'; throw e; } return records[n].map(r => [r]); } });

test('SPF, DMARC and DKIM posture is assessed from DNS TXT records (CG-108)', async () => {
  const good = await domainPosture('example.org', resolverFor({ 'example.org': ['v=spf1 include:spf.protection.outlook.com -all'], '_dmarc.example.org': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.org'], 'selector1._domainkey.example.org': ['v=DKIM1; k=rsa; p=MIIB'] }), ['selector1']);
  assert.deepEqual(good.findings, []); assert.equal(good.dmarc_policy, 'reject');
  const weak = await domainPosture('weak.test', resolverFor({ 'weak.test': ['v=spf1 +all'], '_dmarc.weak.test': ['v=DMARC1; p=none'] }), ['s1']);
  assert.deepEqual(weak.findings.map(f => [f.id, f.severity]), [['spf-pass-all', 'critical'], ['dmarc-none', 'medium'], ['dmarc-no-reports', 'low'], ['no-dkim', 'high']]);
  assert.deepEqual((await domainPosture('none.test', resolverFor({}))).findings.map(f => f.id), ['no-spf', 'no-dmarc']);
});

test('messages are analysed from their headers and parts without keeping bodies (CG-108)', () => {
  const p = analyseEml(fs.readFileSync(FX('phish.eml'), 'latin1'), { internalDomains: ['example.org'] });
  assert.deepEqual(p.auth, { spf: 'fail', dkim: 'none', dmarc: 'fail' });
  assert.deepEqual(p.findings.map(f => f.id).sort(), ['deceptive-link:login-example-org.payout-desk.test', 'display-name-spoof', 'dmarc-fail', 'ip-link:203.0.113.66', 'reply-to-mismatch', 'risky-attachment:invoice.pdf.exe']);
  assert.equal(p.attachments[0].name, 'invoice.pdf.exe'); assert.match(p.attachments[0].sha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(p).includes('Please review') && !JSON.stringify(p).includes('overdue'), 'no body or subject text is kept');
  const ok = analyseEml(fs.readFileSync(FX('legit.eml'), 'latin1'), { internalDomains: ['example.org'] }); assert.deepEqual(ok.findings, []); assert.deepEqual(ok.link_domains, ['portal.partner.test']);
});

test('forwarding outside the organisation and hiding rules from the Microsoft 365 audit log raise alerts (CG-108)', t => {
  const changes = forwardingChanges(JSON.parse(fs.readFileSync(FX('m365-audit.json'), 'utf8')), ['example.org']);
  assert.deepEqual(changes.map(c => [c.user, c.operation, c.external_domains.join(','), c.hides_messages]), [['finance@example.org', 'New-InboxRule', 'payout-desk.test', true], ['ceo@example.org', 'Set-Mailbox', 'mail.test', false]], 'internal redirects are not reported');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg108-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Mail', stale_seconds: 86400 });
  for (const [mode, extra] of [['eml', ['--input', FX('phish.eml'), '--input', FX('legit.eml')]], ['audit', ['--input', FX('m365-audit.json')]]]) { const out = path.join(dir, `${mode}.json`), r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/email-security.js'), mode, ...extra, '--internal-domains', 'example.org', '--output', out], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); }
  const alerts = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-EMAIL-108'"); assert.equal(alerts.length, 3, 'one phishing message and two forwarding changes'); assert.ok(alerts.some(a => /payout-desk/.test(a.title)));
  const v = d.emailSecurity(); assert.equal(v.messages.length, 2); assert.equal(v.forwarding.length, 2); assert.ok(v.claim_ar.includes('لا يُخزن محتوى الرسائل'));
});
