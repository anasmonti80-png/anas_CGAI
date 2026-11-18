import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { incidentPlaybookCatalog } from '../lib/incident-playbooks.js';
import { detectionCatalog } from '../lib/detection-rules.js';
import { toAr } from '../lib/i18n-ar.js';

const arabic = s => typeof s === 'string' && /[؀-ۿ]/.test(s);

test('fixed English texts returned by the API all have Arabic versions', () => {
  for (const p of incidentPlaybookCatalog) {
    for (const ph of p.phases) ph.steps.forEach((s, i) => assert.ok(arabic(ph.steps_ar[i]), `playbook step: ${s}`));
    p.signals.forEach((s, i) => assert.ok(arabic(p.signals_ar[i]), `playbook signal: ${s}`));
    assert.ok(arabic(p.automation.effect_ar), 'playbook automation effect');
  }
  for (const r of detectionCatalog()) assert.ok(arabic(r.description_ar), `rule ${r.id}`);
  // Security outcome gaps and operating-mode texts are literal strings in the source.
  const domain = fs.readFileSync(new URL('../lib/domain.js', import.meta.url), 'utf8'), start = domain.indexOf('  securityOutcomes('), body = domain.slice(start, domain.indexOf('\n  }', start));
  for (const m of body.matchAll(/'([A-Z][^']{15,}\.)'/g)) if (!/^SELECT /.test(m[1]) && !/^Evidence map/.test(m[1])) assert.ok(arabic(toAr(m[1])), `outcome gap: ${m[1]}`);
  const server = fs.readFileSync(new URL('../server.js', import.meta.url), 'utf8'), modes = server.slice(server.indexOf("p==='/api/modes'"), server.indexOf("p==='/api/users'"));
  for (const m of modes.matchAll(/(?:capabilities|limitations):\[([^\]]*)\]/g)) for (const s of m[1].match(/'[^']+'/g) || []) assert.ok(arabic(toAr(s.slice(1, -1))), `mode text: ${s}`);
});

test('analyzer finding details are translated by pattern with their values kept', async () => {
  const { detailAr } = await import('../lib/i18n-ar.js');
  const samples = ['Same match fields and action as an earlier rule', 'Allow rule is overridden by a covering block rule', 'Allows any source to any destination on any port and protocol', 'Inbound from any address to administrative port(s) 3389', 'Inbound from any address on any port', 'No hits for 120 days', 'Zero hits since creation more than 90 days ago', 'Exception expired 3 day(s) ago but is still enabled', 'Exception expires in 5 day(s)', 'telnet enabled', 'ssh reachable from external without source restriction', 'CVE-2026-1 affects 17.3; fixed in 17.9', 'password unchanged for 400 days', '12 accounts, at most 3 failures each', '8 failures followed by a success', 'SA → US within 30 min', 'first sign-in from BR', 'admin consent, unverified publisher, scopes: Mail.Read', 'verified publisher with broad scopes: Files.ReadWrite.All', 'federation by admin-1 without authorization reference', 'federation by admin-1 (CHG-1)'];
  for (const s of samples) { const t = detailAr(s); assert.ok(t && /[؀-ۿ]/.test(t), s); }
  assert.match(detailAr('No hits for 120 days'), /120/); assert.match(detailAr('ssh reachable from external without source restriction'), /الخارج/);
});
