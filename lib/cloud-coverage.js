// CG-104 Cloud detection coverage: for AWS, Azure and Google Cloud, which detection domains (identity, compute,
// storage, keys, network, logging) are visible from the sources actually received (audit logs, sign-ins, provider
// threat findings, flow logs) and covered by CyberGuard rules, measured from the last 30 days.
import { riskyCloudtrailCalls } from './connectors/aws.js';
import { riskyAzureOperations } from './connectors/azure.js';
import { riskyGcpMethods } from './connectors/gcp.js';

export const DOMAINS = ['identity', 'compute', 'storage', 'keys', 'network', 'logging'];
export function domainOf(op) {
  const v = String(op || '').toLowerCase();
  if (/cloudtrail|guardduty|securityhub|config:|logging|diagnosticsettings|insights|securityinsights|operationalinsights|sink|security\/pricings|events:/.test(v)) return 'logging';
  if (/kms|keyvault|cryptokey|cloudkms|secretsmanager|secrets/.test(v)) return 'keys';
  if (/s3|storage|blob|bucket|object/.test(v)) return 'storage';
  if (/\biam|authorization\/role|serviceaccount|setiampolicy|organizations|sts:|signin|login|user/.test(v)) return 'identity';
  if (/network|firewall|securitygroup|flowlog|subnetwork|securitypolic|vpc|ec2:(authorize|revoke|create|delete)securitygroup/.test(v)) return 'network';
  if (/ec2|compute|virtualmachines|instances|lambda|functions|container|kubernetes/.test(v)) return 'compute';
  return null;
}
const PROVIDER_FORMAT = { aws: 'aws-cloudtrail-json', azure: 'azure-activity-json', gcp: 'gcp-audit-json' };
const FLOW_FORMAT = { aws: 'aws-vpc-flow', azure: 'azure-vnet-flow-json', gcp: 'gcp-vpc-flow-json' };
const FINDING_PRODUCTS = { aws: ['guardduty', 'security-hub', 'inspector', 'macie', 'access-analyzer', 'config'], azure: ['defender-for-cloud', 'sentinel'], gcp: ['scc'] };
const RISKY = { aws: riskyCloudtrailCalls, azure: riskyAzureOperations, gcp: riskyGcpMethods };
// Visibility that audit logs alone do not give, stated rather than implied.
const DATA_PLANE = { aws: 'S3 object access needs CloudTrail data events; GuardDuty S3 protection adds threat findings.', azure: 'Blob reads need storage diagnostic logs; Activity log covers control-plane changes only.', gcp: 'Object reads need Data Access audit logs, which are off by default.' };

export function cloudCoverage({ records, findings, signins }) {
  const out = {};
  for (const p of ['aws', 'azure', 'gcp']) {
    const audit = records.filter(r => r._format === PROVIDER_FORMAT[p]), flows = records.filter(r => r._format === FLOW_FORMAT[p]), f = findings.filter(x => x.provider === p && FINDING_PRODUCTS[p].includes(x.product));
    const ops = {}; for (const r of audit) { const d = domainOf(r.signature); if (d) ops[d] = (ops[d] || 0) + 1; }
    const rules = {}; for (const op of RISKY[p]) { const d = domainOf(op); if (d) rules[d] = (rules[d] || 0) + 1; }
    const fd = {}; for (const x of f) { const d = domainOf(`${x.resource_type || ''} ${(x.types || []).join(' ')} ${x.title || ''}`) || 'compute'; fd[d] = (fd[d] || 0) + 1; }
    const identitySignins = p === 'azure' ? signins : 0;
    out[p] = { sources: { audit_log: audit.length, flow_logs: flows.length, threat_findings: f.length, sign_ins: identitySignins },
      domains: DOMAINS.map(d => { const visible = audit.length > 0 && (ops[d] > 0 || d !== 'network' || flows.length > 0), detection = (rules[d] || 0) + (fd[d] ? 1 : 0);
        const state = !audit.length ? 'blind' : detection === 0 ? 'visible-no-detection' : d === 'storage' ? 'control-plane-only' : 'covered';
        return { domain: d, state, audit_operations: ops[d] || 0, cyberguard_rules: rules[d] || 0, provider_findings: fd[d] || 0, flow_logs: d === 'network' ? flows.length : null, note: d === 'storage' ? DATA_PLANE[p] : !audit.length ? `No ${PROVIDER_FORMAT[p]} received in 30 days` : null, visible }; }) };
  }
  return out;
}
