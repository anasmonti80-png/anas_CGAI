// CG-148 AWS IAM Access Analyzer import from read-only exports made by the account owner (no write API is called):
//   aws accessanalyzer list-analyzers --region <r> > analyzers-<r>.json            (one per region)
//   aws accessanalyzer list-findings-v2 --analyzer-arn <arn> --region <r> > findings-<name>.json
//   node scripts/aws-access-analyzer.js --account-id <id> --authorization-ref <ref> --regions us-east-1,eu-west-1
//        --analyzers analyzers-us-east-1.json [--analyzers analyzers-eu-west-1.json] --findings <name>=findings.json ... --output aa.json
// IAM permissions needed: access-analyzer:ListAnalyzers and access-analyzer:ListFindings (also used by ListFindingsV2).
import fs from 'node:fs';
import { parseAnalyzers, parseFindings, assessAnalyzer } from '../lib/access-analyzer.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []);
const account = flag('--account-id'), auth = flag('--authorization-ref'), out = flag('--output'), regions = (flag('--regions') || '').split(',').map(x => x.trim()).filter(Boolean);
if (!account || !/^\d{12}$/.test(account) || !auth || !out || !all('--analyzers').length) { console.error('usage: aws-access-analyzer.js --account-id <12 digits> --authorization-ref <ref> --regions r1,r2 --analyzers list-analyzers.json [...] [--findings name=file ...] --output aa.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
let analyzers = [], findings = [];
try {
  for (const f of all('--analyzers')) analyzers.push(...parseAnalyzers(read(f)));
  for (const spec of all('--findings')) { const [name, file] = spec.split('='); if (!analyzers.some(a => a.name === name)) { console.error(`No analyzer named ${name} in the analyzer exports.`); process.exit(2); } findings.push(...parseFindings(read(file), name)); }
} catch (e) { console.error(`Not an Access Analyzer export: ${e.code || e.message}`); process.exit(2); }
analyzers = [...new Map(analyzers.map(a => [a.arn, a])).values()];
if (findings.length > 5000) { console.error('More than 5000 findings: export per analyzer with filters.'); process.exit(2); }
const at = new Date().toISOString(), details = { account_id: account, authorization_ref: auth, regions, analyzers, findings };
const event = { event_id: `access-analyzer:${account}:${at}`, kind: 'cloud.access_analyzer', observed_at: at, asset: { external_id: `aws:${account}`, hostname: `AWS ${account}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const a = assessAnalyzer(details);
console.log(JSON.stringify({ account, analyses: Object.fromEntries(a.analyses.map(x => [x.analysis, x.state])), counts: a.counts, output: out }));
