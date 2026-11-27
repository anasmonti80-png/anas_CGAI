// CG-170 Isolation connectivity survival. Isolating a host whose management path runs through a full-tunnel VPN, a proxy
// or a hypervisor host can cut the very channel used to manage, verify and release it. For each such host the analyst
// records the management path and either a survival test (the management channel was tested while isolated and survived,
// within 30 days) or an out-of-band recovery method with its owner and evidence (iLO/iDRAC, hypervisor console, MDM,
// physical access). An isolation action on a risky path is refused until one of the two is in place. An unknown path is
// treated as risky. Results are never shown as success before isolation is proven: an executed isolation stays
// "not proven" until an independent outcome check confirms it (CG-118).
import { fail, object, text, choice } from './common.js';
import { ControlOutcomes } from './control-outcome.js';

export const ISOLATION_ACTIONS = ['endpoint.isolate-device', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint'];
export const PATHS = ['direct', 'full-tunnel-vpn', 'proxy', 'hypervisor-host', 'unknown'];
export const RISKY = ['full-tunnel-vpn', 'proxy', 'hypervisor-host', 'unknown'];
export const OOB = ['ilo-idrac-ipmi', 'hypervisor-console', 'mdm', 'physical-access', 'none'];
const DAYS_30 = 30 * 86400000;

export class IsolationSurvival {
  constructor(store, { clock, domain } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  record(actor, assetId, input) {
    object(input, ['path_type', 'management_channel', 'survival', 'tested_at', 'test_evidence_ref', 'oob_method', 'oob_owner', 'oob_evidence_ref'], 'isolation_path');
    this.s.require('SELECT id FROM assets WHERE id=?', [assetId]);
    const path_type = choice(input.path_type, PATHS, 'isolation_path_type'), survival = choice(input.survival || 'untested', ['tested-survives', 'tested-lost', 'untested'], 'isolation_survival'), oob_method = choice(input.oob_method || 'none', OOB, 'oob_method');
    const tested_at = input.tested_at ? text(input.tested_at, 'isolation_tested_at', 40) : null; fail(survival === 'untested' || (tested_at && !Number.isNaN(Date.parse(tested_at)) && input.test_evidence_ref), 400, 'survival_test_requires_time_and_evidence');
    fail(oob_method === 'none' || (input.oob_owner && input.oob_evidence_ref), 400, 'oob_recovery_requires_owner_and_evidence');
    const at = this.now(), row = [assetId, path_type, text(input.management_channel, 'management_channel', 200), survival, tested_at ? new Date(tested_at).toISOString() : null, text(input.test_evidence_ref, 'test_evidence_ref', 300, true) || null, oob_method, text(input.oob_owner, 'oob_owner', 200, true) || null, text(input.oob_evidence_ref, 'oob_evidence_ref', 300, true) || null, actor, at];
    this.s.transaction(() => { this.s.run('INSERT INTO isolation_paths(asset_id,path_type,management_channel,survival,tested_at,test_evidence_ref,oob_method,oob_owner,oob_evidence_ref,recorded_by,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET path_type=excluded.path_type,management_channel=excluded.management_channel,survival=excluded.survival,tested_at=excluded.tested_at,test_evidence_ref=excluded.test_evidence_ref,oob_method=excluded.oob_method,oob_owner=excluded.oob_owner,oob_evidence_ref=excluded.oob_evidence_ref,recorded_by=excluded.recorded_by,recorded_at=excluded.recorded_at', ...row);
      this.s.audit(actor, 'isolation.path_recorded', assetId, { path_type, survival, oob_method }, at); });
    return this.state(assetId);
  }
  state(assetId) {
    const r = this.s.get('SELECT * FROM isolation_paths WHERE asset_id=?', assetId);
    if (!r) return { asset_id: assetId, path_type: null, gate: 'not-assessed', ready: true };
    const fresh = r.survival === 'tested-survives' && r.tested_at && Date.parse(r.tested_at) >= this.clock() - DAYS_30, oob = r.oob_method !== 'none';
    const gate = !RISKY.includes(r.path_type) ? 'direct-path' : fresh ? 'survival-tested' : oob ? 'out-of-band-recovery' : r.survival === 'tested-survives' ? 'survival-test-expired' : r.survival === 'tested-lost' ? 'channel-lost-no-recovery' : 'untested-no-recovery';
    return { ...r, gate, ready: ['direct-path', 'survival-tested', 'out-of-band-recovery'].includes(gate) };
  }
  // Called before an isolation action is requested or executed.
  require(assetId, type) { if (!ISOLATION_ACTIONS.includes(type)) return null; const st = this.state(assetId); fail(st.ready, 409, `isolation_survival_not_proven:${st.gate}`); return st; }
  view() {
    const assets = this.s.all('SELECT p.*,a.hostname,a.external_id FROM isolation_paths p JOIN assets a ON a.id=p.asset_id ORDER BY p.recorded_at DESC').map(r => ({ ...this.state(r.asset_id), hostname: r.hostname, external_id: r.external_id }));
    const co = new ControlOutcomes(this.s, { domain: this.domain, clock: this.clock });
    const actions = this.s.all(`SELECT id FROM actions WHERE type IN (${ISOLATION_ACTIONS.map(() => '?').join(',')}) ORDER BY requested_at DESC LIMIT 100`, ...ISOLATION_ACTIONS).map(r => co.outcome(r.id)).filter(Boolean)
      .map(o => ({ action_id: o.action_id, type: o.type, asset: o.asset, outcome: o.state, shown_as: o.state === 'verified-effective' ? 'isolation-proven' : o.state === 'connector-reported-only' ? 'executed-not-proven' : o.state }));
    return { assets, actions, risky_paths: RISKY, oob_methods: OOB,
      claim: 'Before a host behind a full-tunnel VPN, a proxy or a hypervisor host is isolated, its management channel must have survived an isolation test within 30 days or an out-of-band recovery method must be recorded with its owner and evidence; otherwise the isolation is refused. An executed isolation is shown as not proven until an independent check confirms it.',
      claim_ar: 'قبل عزل جهاز خلف VPN بنفق كامل أو بروكسي أو مضيف افتراضي، يجب أن تكون قناة إدارته قد صمدت في اختبار عزل خلال 30 يومًا، أو أن تُسجل طريقة استعادة خارج النطاق مع مالكها ودليلها؛ وإلا يُرفض العزل. ويُعرض العزل المنفذ «غير مثبت» حتى يؤكده فحص مستقل.' };
  }
}
