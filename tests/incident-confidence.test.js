import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { IncidentConfidence, enforceConfidence } from '../lib/incident-confidence.js';

test('observed events, suspicious indicators, verified incidents and confirmed compromises stay separate, and only people move a case up (CG-166)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), ic = new IncidentConfidence(s);
  for (const [u, role] of [['analyst', 'analyst'], ['admin1', 'admin'], ['admin2', 'admin']]) s.run('INSERT INTO users VALUES (?,?,?,?,?)', u, u, 'fixture-not-a-password-hash', role, new Date().toISOString());
  const src = d.createSource('admin1', { name: 'Auth', stale_seconds: 86400 }), asset = { external_id: 'srv', hostname: 'srv', os_family: 'linux', device_type: 'server', addresses: [] }, at = new Date().toISOString();
  d.ingest('admin1', src.id, { schema_version: 'cg.telemetry/1', events: Array.from({ length: 5 }, (_, i) => ({ event_id: `f${i}`, kind: 'auth.failed', observed_at: at, asset, details: { account: 'root', source_ip: '198.51.100.8', protocol: 'ssh' } })) });
  const alert = s.get("SELECT id,evidence_ids FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'"), ev = JSON.parse(alert.evidence_ids);
  let v = ic.view(); assert.deepEqual(v.levels.map(l => [l.id, l.count]), [['observed-event', 5], ['suspicious-indicator', 1], ['verified-security-incident', 0], ['confirmed-compromise', 0]]);
  assert.equal(ic.levelOfAlert(alert.id), 'suspicious-indicator', 'an alert alone is a suspicious indicator');
  const c = d.createCase('analyst', { title: 'Root SSH guessing', alert_ids: [alert.id] });
  assert.throws(() => ic.verify('analyst', c.id, { rationale: 'Reviewed logs', evidence_event_ids: ev }), /verification_requires_true_positive_alert/);
  d.dispositionAlert('analyst', alert.id, { disposition: 'true-positive', note: 'Not a scanner' });
  assert.throws(() => ic.verify('analyst', c.id, { rationale: 'x', evidence_event_ids: ['not-an-event-of-the-case'] }), /verification_evidence_must_belong_to_case_alerts/);
  assert.throws(() => ic.verify('ai-analyst', c.id, { rationale: 'x', evidence_event_ids: ev }), /confidence_requires_a_person/, 'AI cannot raise the level');
  assert.equal(ic.verify('analyst', c.id, { rationale: 'Five failures from an unknown address on a server with no SSH users', evidence_event_ids: ev.slice(0, 1) }).level, 'verified-security-incident');
  assert.throws(() => ic.confirm('analyst', c.id, { compromise_type: 'attacker-access', evidence_refs: ['EVD-1'], rationale: 'x' }), /compromise_confirmation_requires_admin/);
  s.run("UPDATE case_confidence SET verified_by='admin1' WHERE case_id=?", c.id);
  assert.throws(() => ic.confirm('admin1', c.id, { compromise_type: 'attacker-access', evidence_refs: ['EVD-1'], rationale: 'x' }), /compromise_needs_second_person/);
  s.run("UPDATE case_confidence SET verified_by='analyst' WHERE case_id=?", c.id);
  assert.throws(() => ic.confirm('admin2', c.id, { compromise_type: 'attacker-access', evidence_refs: [], rationale: 'x' }), /compromise_requires_forensic_evidence/);
  // Before confirmation, AI certainty wording is withheld; negations stay.
  const ai = d.aiAnalysis(alert.id); assert.equal(ai.incident_confidence.level, 'verified-security-incident'); assert.equal(ai.incident_confidence.ai_may_raise_level, false);
  const g = enforceConfidence({ summary: 'The server was compromised; this is confirmed. Lateral movement is not confirmed.', ar: 'تم اختراق الخادم بالتأكيد، والانتشار غير مؤكد' }, 'verified-security-incident');
  assert.equal(g.value.summary, 'The server [withheld: verified-security-incident]; this is [withheld: verified-security-incident]. Lateral movement is not confirmed.');
  assert.equal(g.value.ar, '[withheld: verified-security-incident] الخادم [withheld: verified-security-incident]، والانتشار غير مؤكد');
  const conf = ic.confirm('admin2', c.id, { compromise_type: 'attacker-access', evidence_refs: ['EVD-2026-166-disk-image', 'EVD-2026-166-auth-log'], rationale: 'Attacker shell found on the disk image' });
  assert.deepEqual([conf.level, conf.compromise_type, conf.confirmed_by], ['confirmed-compromise', 'attacker-access', 'admin2']);
  assert.equal(enforceConfidence('The server was compromised.', 'confirmed-compromise').value, 'The server was compromised.', 'once a person confirmed it, the wording may say so');
  v = ic.view(); assert.deepEqual(v.levels.map(l => l.count).slice(2), [0, 1]);
  assert.equal(ic.downgrade('admin1', c.id, { level: 'verified-security-incident', reason: 'Disk image was from another host' }).level, 'verified-security-incident');
  assert.deepEqual(s.all("SELECT action FROM audit WHERE action LIKE 'incident.%' ORDER BY seq").map(r => r.action), ['incident.verified', 'incident.compromise_confirmed', 'incident.confidence_downgraded']);
});
