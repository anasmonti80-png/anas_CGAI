// CG-046 AWS read-only converters. Inputs are the documented read outputs of the AWS APIs / CLI:
//   organizations list-accounts, securityhub get-findings (ASFF: Security Hub CSPM, GuardDuty, Inspector, Config, ...),
//   guardduty get-findings, ec2 describe-security-groups, CloudTrail log files, VPC Flow Logs, AWS Network Firewall logs
//   and EventBridge event envelopes. Nothing here writes to AWS; values missing from the input are never guessed.
import { isIP } from 'node:net';

export const awsServices = ['cloudtrail', 'guardduty', 'security-hub', 'inspector', 'config', 'vpc-flow-logs', 'network-firewall', 'security-groups', 'eventbridge'];
const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const isoZ = v => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const accountId = v => (/^\d{12}$/.test(String(v || '')) ? String(v) : null);
const obj = v => (typeof v === 'string' ? JSON.parse(v) : v);

// organizations list-accounts  →  accounts[]
export function organizationsAccounts(json) {
  const v = obj(json); if (!v || !Array.isArray(v.Accounts)) throw new Error('not an Organizations ListAccounts response (Accounts[] missing)');
  return v.Accounts.slice(0, 5000).filter(a => accountId(a.Id)).map(a => ({ account_id: a.Id, name: short(a.Name, 200), status: { ACTIVE: 'active', SUSPENDED: 'suspended', PENDING_CLOSURE: 'pending-closure' }[a.State || a.Status] || 'unknown', access: 'not-attempted' }));
}

const sevLabel = label => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFORMATIONAL: 'info' })[String(label || '').toUpperCase()] || null;
const productOf = (name, arn = '') => { const n = `${name || ''} ${arn}`.toLowerCase(); return n.includes('guardduty') ? 'guardduty' : n.includes('inspector') ? 'inspector' : n.includes('config') ? 'config' : n.includes('macie') ? 'macie' : n.includes('access analyzer') || n.includes('access-analyzer') ? 'access-analyzer' : n.includes('security hub') || n.includes('securityhub') ? 'security-hub' : 'other'; };

// securityhub get-findings  →  cloud.finding details[]   (AWS Security Finding Format)
export function asffFindings(json) {
  const v = obj(json), list = Array.isArray(v) ? v : v?.Findings;
  if (!Array.isArray(list)) throw new Error('not an ASFF response (Findings[] missing)');
  return list.slice(0, 5000).map(f => {
    const res = (f.Resources || [])[0] || {}, wf = String(f.Workflow?.Status || f.WorkflowState || 'NEW').toUpperCase(), state = String(f.RecordState || 'ACTIVE').toUpperCase();
    const severity = sevLabel(f.Severity?.Label) || (Number.isFinite(f.Severity?.Normalized) ? (f.Severity.Normalized >= 90 ? 'critical' : f.Severity.Normalized >= 70 ? 'high' : f.Severity.Normalized >= 40 ? 'medium' : f.Severity.Normalized >= 1 ? 'low' : 'info') : 'info');
    const compliance = f.Compliance?.Status ? ({ PASSED: 'passed', FAILED: 'failed', WARNING: 'warning', NOT_AVAILABLE: 'not-available' })[f.Compliance.Status] || null : null;
    return { finding_id: short(f.Id, 300), provider: 'aws', account_id: accountId(f.AwsAccountId), region: short(f.Region || res.Region, 40), product: productOf(f.ProductName, f.ProductArn), title: short(f.Title, 300) || 'Untitled finding', severity, resource_type: short(res.Type, 200), resource_id: short(res.Id, 500), status: state === 'ARCHIVED' || wf === 'RESOLVED' || compliance === 'passed' ? 'resolved' : wf === 'SUPPRESSED' ? 'suppressed' : 'active', compliance, types: (f.Types || []).slice(0, 10).map(t => short(t, 200)).filter(Boolean), first_seen: isoZ(f.FirstObservedAt || f.CreatedAt), updated_at: isoZ(f.UpdatedAt) };
  }).filter(f => f.finding_id && f.account_id);
}

// guardduty get-findings  →  cloud.finding details[]   (GuardDuty severity: 1-3.9 low, 4-6.9 medium, 7-8.9 high, 9-10 critical)
export function guarddutyFindings(json) {
  const v = obj(json), list = Array.isArray(v) ? v : v?.Findings;
  if (!Array.isArray(list)) throw new Error('not a GuardDuty GetFindings response (Findings[] missing)');
  return list.slice(0, 5000).map(f => {
    const s = Number(f.Severity), r = f.Resource || {}, rid = r.InstanceDetails?.InstanceId || r.AccessKeyDetails?.AccessKeyId && `access-key:${r.AccessKeyDetails.UserName || ''}` || r.S3BucketDetails?.[0]?.Name || r.EksClusterDetails?.Name || null;
    return { finding_id: short(f.Id, 300), provider: 'aws', account_id: accountId(f.AccountId), region: short(f.Region, 40), product: 'guardduty', title: short(f.Title, 300) || short(f.Type, 300) || 'GuardDuty finding', severity: s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s >= 1 ? 'low' : 'info', resource_type: short(r.ResourceType, 200), resource_id: short(rid, 500), status: f.Service?.Archived ? 'resolved' : 'active', compliance: null, types: [short(f.Type, 200)].filter(Boolean), first_seen: isoZ(f.Service?.EventFirstSeen || f.CreatedAt), updated_at: isoZ(f.UpdatedAt) };
  }).filter(f => f.finding_id && f.account_id);
}

// ec2 describe-security-groups  →  firewall.ruleset rules (security groups are stateful allow lists with an implicit deny)
export function securityGroupRules(json, groupId) {
  const v = obj(json); if (!v || !Array.isArray(v.SecurityGroups)) throw new Error('not an EC2 DescribeSecurityGroups response (SecurityGroups[] missing)');
  const groups = groupId ? v.SecurityGroups.filter(g => g.GroupId === groupId) : v.SecurityGroups, rules = [];
  for (const g of groups.slice(0, 500)) for (const [direction, perms] of [['in', g.IpPermissions || []], ['out', g.IpPermissionsEgress || []]]) perms.forEach((p, pi) => {
    const proto = String(p.IpProtocol), protocol = proto === '-1' ? 'any' : ({ 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' })[proto] || proto.toLowerCase();
    const ports = proto === '-1' || !['tcp', 'udp'].includes(protocol) || p.FromPort === undefined || (p.FromPort === 0 && p.ToPort === 65535) ? ['any'] : [p.FromPort === p.ToPort ? String(p.FromPort) : `${p.FromPort}-${p.ToPort}`];
    const peers = [...(p.IpRanges || []).map(r => ({ cidr: r.CidrIp, d: r.Description })), ...(p.Ipv6Ranges || []).map(r => ({ cidr: r.CidrIpv6, d: r.Description }))];
    const named = [...(p.UserIdGroupPairs || []).map(x => `sg:${x.GroupId}`), ...(p.PrefixListIds || []).map(x => `pl:${x.PrefixListId}`)];
    const entries = [...peers.map(x => ({ cidr: ['0.0.0.0/0', '::/0'].includes(x.cidr) ? 'any' : x.cidr, desc: x.d, readable: true })).filter((x, i, all) => all.findIndex(y => y.cidr === x.cidr) === i), ...named.map(n => ({ cidr: 'any', desc: n, readable: false }))];
    entries.forEach((e, ei) => { if (e.cidr !== 'any' && isIP(String(e.cidr).split('/')[0]) === 0) return; const peer = [e.cidr], local = ['any'];
      rules.push({ rule_id: `${g.GroupId}:${direction}:${pi}:${ei}`.slice(0, 300), name: short(`${g.GroupName || g.GroupId} ${direction === 'in' ? 'ingress' : 'egress'} ${e.desc || e.cidr}`, 300), position: rules.length + 1, enabled: true, direction, action: 'allow', protocol, src: direction === 'in' ? peer : local, dst: direction === 'in' ? local : peer, src_ports: ['any'], dst_ports: ports, application: null, profile: short(g.VpcId, 50), last_hit_at: null, hit_count: null, expires_at: null, owner: short(g.OwnerId, 200), created_at: null, filters_readable: e.readable, scope_constraints: [short(`security-group ${g.GroupId}`, 120), ...(e.readable ? [] : [short(`referenced ${e.desc} not resolved`, 120)])] });
    });
  });
  return { vendor: 'aws-security-group', rules, groups: groups.length, unreadable: rules.filter(r => !r.filters_readable).length };
}

// CloudTrail log file {"Records":[...]} (or a bare array)  →  one JSON line per record for the aws-cloudtrail-json format
export function cloudtrailLines(json) {
  const v = obj(json), list = Array.isArray(v) ? v : v?.Records;
  if (!Array.isArray(list)) throw new Error('not a CloudTrail log file (Records[] missing)');
  return list.slice(0, 5000).map(r => JSON.stringify(r));
}

// Network Firewall: each log line is one JSON object; CloudWatch/S3 deliveries are passed through unchanged.
export function networkFirewallLines(text) { return String(text).split(/\r?\n/).filter(l => l.trim()).slice(0, 5000); }

// EventBridge envelopes (one object, an array, or JSON lines)  →  findings and CloudTrail records routed by detail-type
export function eventBridgeEnvelopes(input) {
  const raw = typeof input === 'string' ? input.trim() : input;
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? (raw.startsWith('[') ? JSON.parse(raw) : raw.split(/\r?\n/).filter(Boolean).map(l => JSON.parse(l))) : [raw];
  const out = { findings: [], cloudtrail: [], unsupported: [] };
  for (const e of list.slice(0, 5000)) {
    if (!e || e.version === undefined || !e['detail-type'] || !e.detail) { out.unsupported.push({ id: e?.id || null, reason: 'not-an-eventbridge-envelope' }); continue; }
    const type = e['detail-type'];
    if (type === 'Security Hub Findings - Imported') out.findings.push(...asffFindings({ Findings: e.detail.findings || [] }));
    else if (type === 'GuardDuty Finding') out.findings.push(...guarddutyFindings({ Findings: [e.detail] }));
    else if (type === 'AWS API Call via CloudTrail' || type === 'AWS Console Sign In via CloudTrail') out.cloudtrail.push(JSON.stringify(e.detail));
    else out.unsupported.push({ id: e.id || null, reason: `unsupported-detail-type:${short(type, 80)}` });
  }
  return out;
}

// CloudTrail API calls that disable or erase visibility, change access broadly, or indicate root use.
export const riskyCloudtrailCalls = ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors', 'guardduty:DeleteDetector', 'guardduty:UpdateDetector', 'guardduty:DisassociateFromMasterAccount', 'securityhub:DisableSecurityHub', 'config:StopConfigurationRecorder', 'config:DeleteConfigurationRecorder', 'config:DeleteDeliveryChannel', 'ec2:DeleteFlowLogs', 'network-firewall:DeleteFirewall', 'network-firewall:UpdateFirewallPolicy', 'events:DeleteRule', 'events:DisableRule', 'organizations:LeaveOrganization', 'iam:CreateAccessKey', 'iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:CreateLoginProfile', 'kms:ScheduleKeyDeletion', 's3:PutBucketPolicy', 'ec2:AuthorizeSecurityGroupIngress'];

// Live collection plan used by scripts/aws-connector.js: one read-only AWS CLI call per service and region.
export const serviceProbes = {
  cloudtrail: { args: ['cloudtrail', 'describe-trails'], enabled: v => (v.trailList || []).some(t => t.IsMultiRegionTrail || t.HomeRegion), detail: v => `${(v.trailList || []).length} trail(s)` },
  guardduty: { args: ['guardduty', 'list-detectors'], enabled: v => (v.DetectorIds || []).length > 0, detail: v => `${(v.DetectorIds || []).length} detector(s)` },
  'security-hub': { args: ['securityhub', 'describe-hub'], enabled: v => Boolean(v.HubArn), detail: v => (v.SubscribedAt ? `since ${String(v.SubscribedAt).slice(0, 10)}` : null) },
  inspector: { args: ['inspector2', 'batch-get-account-status'], enabled: v => (v.accounts || []).some(a => a.state?.status === 'ENABLED'), detail: v => (v.accounts || []).map(a => a.state?.status).filter(Boolean).join(',') || null },
  config: { args: ['configservice', 'describe-configuration-recorder-status'], enabled: v => (v.ConfigurationRecordersStatus || []).some(r => r.recording), detail: v => `${(v.ConfigurationRecordersStatus || []).length} recorder(s)` },
  'vpc-flow-logs': { args: ['ec2', 'describe-flow-logs'], enabled: v => (v.FlowLogs || []).some(f => f.FlowLogStatus === 'ACTIVE'), detail: v => `${(v.FlowLogs || []).filter(f => f.FlowLogStatus === 'ACTIVE').length} active flow log(s)` },
  'network-firewall': { args: ['network-firewall', 'list-firewalls'], enabled: v => (v.Firewalls || []).length > 0, detail: v => `${(v.Firewalls || []).length} firewall(s)` },
  'security-groups': { args: ['ec2', 'describe-security-groups', '--query', 'length(SecurityGroups)'], enabled: v => Number(v) > 0, detail: v => `${Number(v) || 0} group(s)` },
  eventbridge: { args: ['events', 'list-rules', '--name-prefix', 'cyberguard'], enabled: v => (v.Rules || []).some(r => r.State === 'ENABLED'), detail: v => `${(v.Rules || []).length} CyberGuard rule(s)` },
};
// Classify an AWS CLI failure without guessing: missing permission vs. service not subscribed vs. other.
export function probeError(stderr) {
  const s = String(stderr || '');
  if (/AccessDenied|UnauthorizedOperation|not authorized/i.test(s)) return 'access-denied';
  if (/not subscribed|SubscriptionRequired|InvalidAccessException|not enabled|BadRequestException.*not.*enabled/i.test(s)) return 'disabled';
  if (/Could not connect|EndpointConnectionError|not supported in this region|UnrecognizedClient/i.test(s)) return 'not-available';
  return 'not-checked';
}
