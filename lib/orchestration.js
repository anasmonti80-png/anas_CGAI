// CG-120 Cross-provider playbooks. A playbook is a sequence of intents (isolate the host, block the address, disable
// the cloud key), never command text. For each step the provider is chosen from what the target is and what is actually
// available: an endpoint agent (Windows, Linux), Cisco ISE NAC quarantine, a Cisco or Huawei access switch through the
// scoped network API, or the AWS/Azure/Google Cloud connector. Every step is an ordinary governed action (preview,
// independent approval, safety tier, connector job). Runs are idempotent (one open run per playbook, target and
// parameters; one open action per step), failed steps are retried a bounded number of times, and if a required step
// still fails the completed steps are rolled back in reverse order.
import { randomUUID } from 'node:crypto';
import { fail, text, choice, digest } from './common.js';
import { verifyPath } from './port-map.js';

const parse = s => JSON.parse(s);
const ENDPOINT_OS = ['windows', 'linux', 'macos'];
// Each intent lists provider candidates in order of preference; the first one whose connector can act on the target wins.
export const INTENTS = {
  'isolate-host': [
    { provider: 'endpoint-agent', type: 'endpoint.isolate-device', when: c => ENDPOINT_OS.includes(c.asset.os_family) && !['virtual-machine'].includes(c.asset.device_type) || (c.asset.device_type === 'virtual-machine' && !c.cloud), target: c => ({ asset: c.asset, target: { device_ref: c.asset.external_id } }) },
    { provider: 'cloud', type: 'cloud.isolate-instance', when: c => Boolean(c.cloud), target: c => ({ asset: c.asset, target: { provider: c.cloud.provider, resource_id: c.cloud.resource_id } }) },
    { provider: 'cisco-ise', type: 'network.nac-quarantine-endpoint', when: c => Boolean(c.path?.safe_to_isolate && c.mac), target: c => ({ asset: c.asset, target: { mac: c.mac.toUpperCase(), policy_name: 'ANC_Quarantine' } }) },
    { provider: 'access-switch', type: 'network.switch-port-admin-down', when: c => Boolean(c.path?.safe_to_isolate && c.switchAsset), target: c => ({ asset: c.switchAsset, target: { device_ref: c.path.switch_ref, interface_ref: c.path.interface, port_role: 'edge', provenance_ref: `port-map:${c.path.switch_ref}:${c.path.interface}` } }) },
  ],
  'block-ip': [
    { provider: 'host-firewall', type: 'network.block-ip', when: c => Boolean(c.params.ip), target: c => ({ asset: c.asset, target: { ip: c.params.ip } }) },
  ],
  'disable-cloud-key': [
    { provider: 'cloud', type: 'cloud.disable-access-key', when: c => Boolean(c.params.principal_ref && c.params.key_ref && (c.cloud || c.params.provider)), target: c => ({ asset: c.asset, target: { provider: c.cloud?.provider || c.params.provider, principal_ref: c.params.principal_ref, key_ref: c.params.key_ref } }) },
  ],
};
export const PLAYBOOKS = [
  { id: 'contain-compromised-host', title: ['Contain a compromised host', 'احتواء جهاز مخترق'], steps: [{ intent: 'isolate-host', required: true }, { intent: 'block-ip', required: false }] },
  { id: 'contain-host-and-c2', title: ['Contain a host and block its command-and-control address', 'احتواء جهاز وحظر عنوان القيادة والتحكم'], steps: [{ intent: 'isolate-host', required: true }, { intent: 'block-ip', required: true }] },
  { id: 'cloud-credential-compromise', title: ['Contain a compromised cloud credential', 'احتواء بيانات اعتماد سحابية مخترقة'], steps: [{ intent: 'disable-cloud-key', required: true }, { intent: 'isolate-host', required: false }] },
];
const MAX_ATTEMPTS = 3, TERMINAL = ['completed', 'rolled-back', 'rollback-failed', 'failed-not-rolled-back'];

export class Orchestrator {
  constructor(store, { domain, clock }) { Object.assign(this, { s: store, d: domain, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  context(assetId, params) {
    const asset = this.s.get('SELECT * FROM assets WHERE id=?', assetId); fail(asset, 404, 'asset_not_found'); asset.addresses = parse(asset.addresses);
    const res = this.s.all("SELECT payload FROM events WHERE kind='cloud.resource_inventory' ORDER BY observed_at DESC LIMIT 50").flatMap(r => { const d = parse(r.payload).details; return d.resources.map(x => ({ ...x, provider: d.provider })); }).find(x => x.resource_id === asset.external_id) || null;
    const maps = this.d.portMaps(), ip = asset.addresses[0], path = ip && maps.length ? verifyPath({ ip, maps, asset }) : null, mac = path ? (maps.flatMap(m => m.arp).find(a => a.ip === ip)?.mac || null) : null;
    const switchAsset = path?.switch_ref ? this.s.get('SELECT * FROM assets WHERE external_id=? ORDER BY last_seen DESC LIMIT 1', path.switch_ref) : null;
    return { asset, cloud: res ? { provider: res.provider, resource_id: res.resource_id } : null, path, mac, switchAsset, params };
  }
  // Provider choice per step, with the reason each candidate was or was not used.
  plan(playbookId, assetId, params = {}) {
    const pb = PLAYBOOKS.find(p => p.id === playbookId); fail(pb, 404, 'playbook_not_found'); const c = this.context(assetId, params), connectors = this.d.responseConnectors().filter(x => !x.source_revoked && x.status === 'active');
    const steps = pb.steps.map((st, i) => {
      const considered = INTENTS[st.intent].map(cand => { if (!cand.when(c)) return { provider: cand.provider, type: cand.type, usable: false, reason: 'does not apply to this target', reason_ar: 'لا ينطبق على هذا الهدف' }; const t = cand.target(c), conn = connectors.find(x => x.capabilities.includes(cand.type) && x.target_asset_refs.includes(t.asset.external_id));
        return conn ? { provider: cand.provider, type: cand.type, usable: true, reason: `connector ${conn.connector_id}`, reason_ar: `الموصل ${conn.connector_id}`, connector_id: conn.connector_id, asset_id: t.asset.id, target: t.target } : { provider: cand.provider, type: cand.type, usable: false, reason: `no active connector can run ${cand.type} on ${t.asset.external_id}`, reason_ar: `لا يوجد موصل فعال ينفذ ${cand.type} على ${t.asset.external_id}` }; });
      const chosen = considered.find(x => x.usable) || null;
      return { index: i, intent: st.intent, required: st.required, provider: chosen?.provider || null, action_type: chosen?.type || null, connector_id: chosen?.connector_id || null, asset_id: chosen?.asset_id || null, target: chosen?.target || null, considered, status: chosen ? 'pending' : st.required ? 'unavailable' : 'skipped', attempts: 0, action_ids: [] };
    });
    return { playbook: pb, steps, executable: steps.every(s => s.status !== 'unavailable') };
  }
  start(actor, input) {
    const playbook_id = text(input.playbook_id, 'playbook_id', 100), asset_id = text(input.asset_id, 'asset_id', 64), authorization_ref = text(input.authorization_ref, 'authorization_ref', 200), reason = text(input.reason, 'reason', 1000);
    const params = {}; for (const k of ['ip', 'principal_ref', 'key_ref', 'provider']) if (input.params?.[k]) params[k] = text(String(input.params[k]), `param_${k}`, 300); if (params.provider) choice(params.provider, ['aws', 'azure', 'gcp'], 'param_provider');
    const key = digest({ playbook_id, asset_id, params }), open = this.s.get(`SELECT id FROM orchestrations WHERE idempotency_key=? AND status NOT IN (${TERMINAL.map(() => '?').join(',')})`, key, ...TERMINAL);
    if (open) return { ...this.get(open.id), idempotent_replay: true };
    const p = this.plan(playbook_id, asset_id, params); fail(p.executable, 409, `playbook_step_unavailable:${p.steps.find(s => s.status === 'unavailable')?.intent}`);
    const id = randomUUID(), at = this.now(); this.s.run('INSERT INTO orchestrations(id,playbook_id,idempotency_key,asset_id,params,authorization_ref,reason,status,steps,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', id, playbook_id, key, asset_id, JSON.stringify(params), authorization_ref, reason, 'running', JSON.stringify(p.steps), actor, at, at);
    this.s.audit(actor, 'orchestration.started', id, { playbook_id, steps: p.steps.map(s => `${s.intent}:${s.provider || s.status}`) }, at); return this.advance(actor, id);
  }
  preview(actor, o, st) {
    const a = this.d.previewAction(actor, { type: st.action_type, asset_id: st.asset_id, target: st.target, connector_id: st.connector_id, authorization_ref: o.authorization_ref, reason: `${o.reason} [playbook ${o.playbook_id} step ${st.index + 1}, attempt ${st.attempts + 1}]`, ttl_seconds: 3600 });
    st.attempts++; st.action_ids.push(a.id); st.status = 'awaiting-approval'; return a;
  }
  // Moves the run forward as far as the current action states allow. Safe to call repeatedly.
  advance(actor, id) {
    const o = this.s.get('SELECT * FROM orchestrations WHERE id=?', id); fail(o, 404, 'orchestration_not_found'); if (TERMINAL.includes(o.status)) return this.get(id);
    const steps = parse(o.steps), act = st => st.action_ids.length ? this.s.get('SELECT id,status,result FROM actions WHERE id=?', st.action_ids.at(-1)) : null; let status = o.status;
    if (status === 'running') {
      for (const st of steps) {
        if (['done', 'skipped'].includes(st.status)) continue;
        const a = act(st);
        if (!a) { this.preview(actor, o, st); break; }
        if (a.status === 'verified') { st.status = 'done'; continue; }
        if (['failed', 'expired', 'denied'].includes(a.status)) {
          st.last_error = a.result || a.status;
          if (st.attempts < MAX_ATTEMPTS) { this.preview(actor, o, st); st.status = 'retrying'; break; }
          if (!st.required) { st.status = 'failed-skipped'; continue; }
          st.status = 'failed'; status = 'compensating'; break;
        }
        st.status = a.status === 'pending-approval' ? 'awaiting-approval' : 'in-progress'; break;
      }
      if (status === 'running' && steps.every(s => ['done', 'skipped', 'failed-skipped'].includes(s.status))) status = 'completed';
    }
    if (status === 'compensating') {
      // Roll back completed steps in reverse order; one at a time so each rollback is verified before the next.
      for (const st of [...steps].reverse().filter(s => ['done', 'rolling-back'].includes(s.status))) {
        const a = act(st);
        if (a.status === 'verified') { this.d.rollbackAction(actor, a.id); st.status = 'rolling-back'; break; }
        if (a.status === 'rolled-back') { st.status = 'rolled-back'; continue; }
        if (a.status === 'rollback-failed') { st.status = 'rollback-failed'; status = 'rollback-failed'; break; }
        st.status = 'rolling-back'; break;
      }
      if (status === 'compensating' && steps.every(s => !['done', 'rolling-back'].includes(s.status))) status = steps.some(s => s.status === 'rolled-back') ? 'rolled-back' : 'failed-not-rolled-back';
    }
    const at = this.now(); this.s.run('UPDATE orchestrations SET steps=?,status=?,updated_at=? WHERE id=?', JSON.stringify(steps), status, at, id);
    if (status !== o.status) this.s.audit(actor, `orchestration.${status}`, id, { steps: steps.map(s => `${s.intent}:${s.status}`) }, at);
    return this.get(id);
  }
  get(id) { const o = this.s.get('SELECT * FROM orchestrations WHERE id=?', id); fail(o, 404, 'orchestration_not_found'); return { ...o, params: parse(o.params), steps: parse(o.steps) }; }
  list() { return this.s.all('SELECT id FROM orchestrations ORDER BY created_at DESC LIMIT 100').map(r => this.get(r.id)); }
  view() { return { playbooks: PLAYBOOKS.map(p => ({ id: p.id, title: p.title[0], title_ar: p.title[1], steps: p.steps.map(s => ({ ...s, providers: INTENTS[s.intent].map(c => ({ provider: c.provider, type: c.type })) })) })), runs: this.list(), max_attempts: MAX_ATTEMPTS,
    claim: 'Playbooks are sequences of intents; each step uses the provider that fits the target and has an active connector (endpoint agent, Cisco ISE, Cisco or Huawei access switch, AWS, Azure or Google Cloud). Every step is a governed action; runs are idempotent, failed steps are retried up to three attempts, and completed steps are rolled back in reverse order when a required step fails.',
    claim_ar: 'خطط الاستجابة سلسلة نوايا؛ كل خطوة تستخدم المزود المناسب للهدف الذي لديه موصل فعال (وكيل الجهاز، Cisco ISE، محول Cisco أو Huawei، AWS أو Azure أو Google Cloud). كل خطوة إجراء محكوم؛ والتشغيل لا يتكرر عند إعادة الطلب، وتُعاد الخطوة الفاشلة حتى ثلاث محاولات، ويُتراجع عن الخطوات المكتملة بترتيب عكسي إذا فشلت خطوة مطلوبة.' }; }
}
