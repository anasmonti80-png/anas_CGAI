// CG-145 Attack technique coverage by evidence. A technique is not covered because a rule exists. It is covered only
// when a detection rule for it has (1) telemetry that actually arrived in the last 7 days (or needs none), (2) a passing
// detection test here — the latest validation lab run that expected the rule, or a recorded purple-team or replay test
// within 90 days — and (3) documented performance limits. Posture and operational rules never count as detection
// coverage. Everything else is partial (with the missing evidence named) or not covered.
import { randomUUID } from 'node:crypto';
import { fail, text, choice } from './common.js';
import { MAPPINGS, TECHNIQUES } from './attack-mapping.js';

// Documented performance limits of detection rules: what they need and where they stop working.
export const LIMITS = {
  'CG-AUTH-FAILURES-5-IN-5M': 'Five failures from one source within five minutes on one host; slower spraying across hosts or sources is not seen.',
  'CG-NET-LATERAL-015': 'Needs internal flow logs; fan-out below the host threshold within the window is not seen.',
  'CG-NET-EXPOSE-016': 'Needs flow or firewall logs from the edge; exposure without logged traffic is not seen.',
  'CG-NET-DNS-017': 'Needs resolver query logs; encrypted DNS (DoH/DoT) bypassing the resolver is not seen.',
  'CG-NETDEV-VPN-024': 'Compares successive configuration snapshots; changes between snapshots are seen only at the next one.',
  'CG-FILE-SUSPICIOUS-092': 'Static YARA and file triage only; files never submitted or packed beyond the rules are not seen.',
  'CG-TOOLSHELL-139': 'Signals over 30 days; IIS module changes and machine-key theft are not observable from current sources.',
  'CG-REMOTE-CORRELATION-141': 'Behaviour tied by time within two hours on the same device, not by process lineage.',
  'CG-IDENTITY-CHAIN-142': 'New country or address against the account\'s own 30 days; impossible travel speed is not modelled.',
  'CG-L2-ROGUE-DHCP-134': 'Evaluated at each layer-2 export; a single source is low severity until corroborated.',
  'CG-WIFI-ROGUE-136': 'Only around scanning managed APs; channels or sites without scanning are blind.',
  'CG-TELECOM-TTP-140': 'Changes made and reverted between two configuration exports are not seen.',
};

export class CoverageEvidence {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  recordTest(actor, input) {
    const rule = text(input?.rule, 'coverage_rule', 120); fail(MAPPINGS.some(m => m.rule === rule && m.category === 'detection'), 400, 'coverage_rule_not_a_detection_rule');
    const row = { id: randomUUID(), rule, result: choice(input.result, ['pass', 'fail'], 'coverage_test_result'), method: choice(input.method, ['purple-team', 'replay', 'atomic-test'], 'coverage_test_method'), evidence_ref: text(input.evidence_ref, 'coverage_evidence_ref', 300), notes: text(input.notes, 'coverage_notes', 1000, true) || null, tested_at: this.now(), recorded_by: actor };
    this.s.transaction(() => { this.s.run('INSERT INTO detection_tests(id,rule,result,method,evidence_ref,notes,tested_at,recorded_by) VALUES (?,?,?,?,?,?,?,?)', row.id, row.rule, row.result, row.method, row.evidence_ref, row.notes, row.tested_at, actor); this.s.audit(actor, 'coverage.detection_test_recorded', row.id, { rule, result: row.result, method: row.method }, row.tested_at); });
    return row;
  }
  ruleEvidence(m, now) {
    const since7 = new Date(now - 7 * 86400000).toISOString(), since90 = new Date(now - 90 * 86400000).toISOString();
    const last = m.sensor_kinds.length ? this.s.get(`SELECT MAX(observed_at) t FROM events WHERE kind IN (${m.sensor_kinds.map(() => '?').join(',')})`, ...m.sensor_kinds).t : null;
    const telemetry = !m.sensor_kinds.length ? { state: 'not-needed', last_event_at: null } : !last ? { state: 'none', last_event_at: null } : last < since7 ? { state: 'stale', last_event_at: last } : { state: 'ok', last_event_at: last };
    const lab = this.s.all('SELECT at,expected,missing,ref FROM validation_lab_runs WHERE at>=? ORDER BY at DESC', since90).map(r => ({ ...r, expected: JSON.parse(r.expected), missing: JSON.parse(r.missing) })).find(r => r.expected.includes(m.rule));
    const manual = this.s.get('SELECT result,method,evidence_ref,tested_at FROM detection_tests WHERE rule=? AND tested_at>=? ORDER BY tested_at DESC LIMIT 1', m.rule, since90);
    const candidates = [lab && { state: lab.missing.includes(m.rule) ? 'fail' : 'pass', method: 'validation-lab', ref: lab.ref, at: lab.at }, manual && { state: manual.result, method: manual.method, ref: manual.evidence_ref, at: manual.tested_at }].filter(Boolean).sort((a, b) => b.at.localeCompare(a.at));
    const test = candidates[0] || { state: 'none', method: null, ref: null, at: null };
    const limits = LIMITS[m.rule] ? { documented: true, text: LIMITS[m.rule] } : { documented: false, text: null };
    const missing = [telemetry.state === 'none' || telemetry.state === 'stale' ? 'telemetry' : null, test.state !== 'pass' ? 'detection-test' : null, !limits.documented ? 'performance-limits' : null].filter(Boolean);
    return { rule: m.rule, use_case: m.use_case, use_case_ar: m.use_case_ar, category: m.category, techniques: m.techniques, telemetry, test, limits, covered: m.category === 'detection' && !missing.length, missing };
  }
  view() {
    const now = this.clock(), rules = MAPPINGS.filter(m => !m.rule.endsWith('*')).map(m => this.ruleEvidence(m, now)), techniques = new Map();
    for (const r of rules) for (const t of r.techniques) { const x = techniques.get(t) || { technique: t, name: TECHNIQUES[t] || t, detection_rules: [], other_rules: [] }; (r.category === 'detection' ? x.detection_rules : x.other_rules).push(r); techniques.set(t, x); }
    const rows = [...techniques.values()].map(x => { const covered = x.detection_rules.filter(r => r.covered);
      const state = covered.length ? 'covered' : x.detection_rules.length ? 'partial' : 'posture-only';
      return { technique: x.technique, name: x.name, state, covered_by: covered.map(r => r.rule), detection_rules: x.detection_rules.map(r => ({ rule: r.rule, missing: r.missing })), other_rules: x.other_rules.map(r => r.rule), missing: state === 'partial' ? [...new Set(x.detection_rules.flatMap(r => r.missing))] : [] }; }).sort((a, b) => a.technique.localeCompare(b.technique));
    const count = st => rows.filter(r => r.state === st).length;
    return { techniques: rows, rules, summary: { techniques: rows.length, covered: count('covered'), partial: count('partial'), posture_only: count('posture-only'), rules_existing: rules.filter(r => r.category === 'detection').length, rules_covered: rules.filter(r => r.covered).length },
      claim: 'A technique counts as covered only when one of its detection rules has arriving telemetry, a passing detection test here and documented performance limits. Rule existence alone, and posture or operational rules, never count.',
      claim_ar: 'لا تُعد التقنية مغطاة إلا إذا كان لإحدى قواعد كشفها قياس يصل فعلًا، واختبار كشف ناجح هنا، وقيود أداء موثقة. ولا يُحتسب وجود القاعدة وحده، ولا قواعد الوضع أو التشغيل.' };
  }
  layer() { const v = this.view(); return { name: 'CyberGuard coverage by evidence', versions: { attack: '16', navigator: '5.1.0', layer: '4.5' }, domain: 'enterprise-attack', description: 'Score 100 = covered by evidence (telemetry, passing detection test, documented limits); 50 = partial; techniques with posture rules only are not scored.',
    techniques: v.techniques.filter(t => /^T\d{4}(\.\d{3})?$/.test(t.technique) && t.state !== 'posture-only').map(t => ({ techniqueID: t.technique, score: t.state === 'covered' ? 100 : 50, enabled: true, comment: t.state === 'covered' ? `covered by ${t.covered_by.join(', ')}` : `partial: missing ${t.missing.join(', ')}` })) }; }
}
