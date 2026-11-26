// CG-156 Azure just-in-time VM access review from read-only exports by the owner (nothing is opened or requested):
//   az security pricing list --subscription <sub> > pricing-<sub>.json      (one per subscription)
//   az security jit-policy list > jit.json
//   az vm list --query "[].{id:id,name:name}" > vms.json
//   node scripts/azure-jit.js --authorization-ref <ref> --pricings <sub>=pricing.json [...] --jit-policies jit.json --vms vms.json --output jit-event.json
import fs from 'node:fs';
import { planStatus, parseJitPolicies, assessJit } from '../lib/azure-jit.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []);
const auth = flag('--authorization-ref'), out = flag('--output');
if (!auth || !out || !flag('--jit-policies') || !flag('--vms')) { console.error('usage: azure-jit.js --authorization-ref <ref> --pricings <sub>=pricing.json [...] --jit-policies jit.json --vms vms.json --output f'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
let plans, policies, vms;
try {
  plans = all('--pricings').map(spec => { const [sub, file] = spec.split('='); if (!/^[0-9a-f-]{36}$/i.test(sub)) throw Object.assign(new Error('sub'), { code: 'invalid_subscription' }); return { subscription: sub.toLowerCase(), status: planStatus(read(file)) }; });
  policies = parseJitPolicies(read(flag('--jit-policies')));
  const v = read(flag('--vms')); if (!Array.isArray(v)) throw Object.assign(new Error('vms'), { code: 'not_vm_list' });
  vms = v.filter(x => x.id).slice(0, 20000).map(x => ({ resource_id: String(x.id), name: String(x.name || x.id), account_id: ((String(x.id).match(/\/subscriptions\/([^/]+)/i) || [])[1] || '').toLowerCase() }));
} catch (e) { console.error(`Invalid export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { authorization_ref: auth, plans, policies, vms };
const event = { event_id: `azure-jit:${at}`, kind: 'cloud.azure_jit', observed_at: at, asset: { external_id: 'azure-jit', hostname: 'Azure JIT VM access', os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ ...assessJit(details).summary, output: out }));
