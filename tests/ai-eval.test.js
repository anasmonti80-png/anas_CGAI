import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { digest } from '../lib/common.js';
import { AiEvaluation } from '../lib/ai-eval.js';

const fixture = (t, LabDomain = Domain) => { const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}); return { s, d, ev: new AiEvaluation(s, { domain: d, Domain: LabDomain }) }; };

test('the evaluation covers hallucination, accuracy, privilege escalation, cost and impact and passes on the real analyst (CG-123)', t => {
  const { s, ev } = fixture(t), r = ev.run('tester');
  assert.equal(r.passed, r.total, JSON.stringify(r.cases.filter(c => !c.passed)));
  assert.deepEqual([...new Set(r.cases.map(c => c.category))].sort(), ['accuracy', 'cost', 'hallucination', 'impact', 'privilege-escalation']);
  for (const id of ['privilege.destructive-shutdown', 'privilege.raw-command', 'privilege.no-ai-account', 'privilege.proposal-is-inert', 'cost.daily-budget', 'impact.critical-asset-floor', 'hallucination.no-unsourced-ip-or-cve']) assert.ok(r.cases.find(c => c.id === id)?.passed, id);
  assert.equal(s.get('SELECT COUNT(*) n FROM events').n, 0, 'the suite runs in an isolated copy'); assert.equal(s.get("SELECT COUNT(*) n FROM alerts").n, 0);
  assert.throws(() => s.run('UPDATE ai_eval_runs SET passed=0'), /evaluation_immutable/); assert.ok(ev.view().claim_ar.includes('لا يختار إجراءً مدمرًا'));
});

test('a broken guardrail is caught by the suite and raises CG-AI-GUARDRAIL-123 (CG-123)', t => {
  // A build where the critical-asset floor is lost, and an installation where someone created an account for the AI.
  class NoFloor extends Domain { criticalProductionAssets() { return []; } }
  const { s, ev } = fixture(t, NoFloor);
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'ai-agent', 'ai-agent', 'fixture-not-a-password-hash', 'analyst', new Date().toISOString());
  const r = ev.run('tester'), failed = r.cases.filter(c => !c.passed).map(c => c.id).sort();
  assert.deepEqual(failed, ['impact.critical-asset-floor', 'privilege.no-ai-account']);
  assert.match(r.cases.find(c => c.id === 'privilege.no-ai-account').detail, /ai-agent/);
  assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-AI-GUARDRAIL-123'").map(x => x.severity), ['high', 'high']);
});

test('the daily cloud budget refuses analyses beyond the limit and records estimated tokens (CG-123)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now, aiCloudDailyLimit: 1 });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); s.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)', 'm', 'a', 's', 'totp', new Date(now).toISOString(), new Date(now + 3600000).toISOString(), digest({}));
  const src = d.createSource('a', { name: 'L', stale_seconds: 86400 }); for (let i = 0; i < 5; i++) d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `f${i}`, kind: 'auth.failed', observed_at: new Date(now).toISOString(), asset: { external_id: 'h', hostname: 'H', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.9'] }, details: { account: 'u', source_ip: '203.0.113.5', protocol: 'rdp' } }] });
  const alert = s.get('SELECT id FROM alerts').id, consent = d.createAiCloudConsent('a', { provider: 'anthropic-compatible', purpose: 'Budget test', customer_approval_ref: 'B-1', duration_days: 1, confirm_redacted_only: true });
  const p = d.prepareAiCloudAnalysis('a', alert, { consent_id: consent.id }); d.recordAiCloudAnalysis('a', p, { summary_ar: 'ملخص', summary_en: 'Summary', provider_request_id: 'r1' });
  assert.throws(() => d.prepareAiCloudAnalysis('a', alert, { consent_id: consent.id }), /cloud_ai_daily_budget_exhausted/);
  const audit = JSON.parse(s.get("SELECT details FROM audit WHERE action='ai.cloud-analysis.completed'").details); assert.ok(audit.estimated_tokens > 0 && audit.payload_bytes > 0);
});
