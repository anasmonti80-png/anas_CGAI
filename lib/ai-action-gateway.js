// CG-039 AI action gateway. The analyst (local or cloud) never sends commands. It may only propose an action
// from the bounded response catalog, as a typed target, for the asset of the alert it is explaining. A proposal
// is inert until a human with the right role promotes it into the normal CG-029 request, which then needs an
// independent approver (and safety approval where the catalog requires it). The AI can never approve or execute.
import { fail, object, text, choice } from './common.js';
import { responseActionCatalog, validateResponseTarget } from './response-actions.js';

// Actions an AI may propose. Excluded: allow/inverse actions, host shutdown and permanent service changes.
export const aiProposableActions = Object.freeze(['network.block-ip', 'network.block-port', 'endpoint.block-app', 'dns.block-domain', 'endpoint.stop-service', 'endpoint.quarantine-file', 'endpoint.isolate-device']);
// Disruptive actions are never proposed for an asset whose recorded service criticality is critical (CG-028 floor).
export const aiDisruptiveActions = Object.freeze(['endpoint.isolate-device', 'endpoint.stop-service']);
// Keys that would carry a raw command; their presence is a rejected raw-command attempt, not a validation typo.
const commandKeys = ['command', 'commands', 'cmd', 'script', 'shell', 'powershell', 'bash', 'exec', 'execute', 'args', 'arguments', 'payload', 'url', 'code'];
const commandLike = /[;&|`<>\r\n]|\$\(|\$\{|\b(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh|curl|wget|invoke-expression|iex|start-process|rm\s+-|del\s+\/|format\s+[a-z]:|net\s+user|reg\s+add|schtasks|certutil)\b/i;

function stringsOf(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach(item => stringsOf(item, out));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => stringsOf(item, out));
  return out;
}

// Screens one AI proposal. Throws with a specific code; the caller audits every rejection.
export function screenAiProposal(input) {
  fail(input && typeof input === 'object' && !Array.isArray(input), 400, 'invalid_ai_proposal');
  fail(!Object.keys(input).some(key => commandKeys.includes(key.toLowerCase())), 400, 'ai_raw_command_rejected');
  object(input, ['action_type', 'target', 'rationale'], 'ai_proposal');
  const action_type = text(input.action_type, 'ai_action_type', 80);
  fail(responseActionCatalog[action_type], 400, 'ai_action_not_in_catalog');
  fail(aiProposableActions.includes(action_type), 403, 'ai_action_not_proposable');
  fail(!stringsOf(input.target).some(value => commandLike.test(value)), 400, 'ai_raw_command_rejected');
  const target = validateResponseTarget(action_type, input.target);
  return { action_type, target, rationale: text(input.rationale, 'ai_rationale', 1000) };
}

// Deterministic typed suggestions from the alert's own evidence: the local analyst's only way to "act".
export function suggestActions({ alert, evidence, asset }) {
  const out = [], seen = new Set(), add = (action_type, target, rationale_ar, rationale_en) => { const key = `${action_type}|${JSON.stringify(target)}`; if (seen.has(key) || out.length >= 3) return; seen.add(key); out.push({ suggestion_id: `s${out.length + 1}`, action_type, target, rationale_ar, rationale_en }); };
  for (const e of evidence) {
    const d = e.details || {};
    const ip = d.source_ip || d.source_a?.ip || null;
    if (ip && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:)/i.test(ip)) add('network.block-ip', { ip }, `حظر عنوان المصدر ${ip} المرتبط بالتنبيه.`, `Block the source address ${ip} linked to the alert.`);
    if (d.sha256 && /^[a-f0-9]{64}$/i.test(d.sha256) && d.path) add('endpoint.quarantine-file', { file_ref: String(d.path).slice(0, 1000), sha256: d.sha256.toLowerCase() }, 'عزل الملف المرتبط بالتنبيه بعد التحقق من بصمته.', 'Quarantine the file linked to the alert after its hash is confirmed.');
    if (d.query && /^[a-z0-9.-]+\.[a-z]{2,63}$/i.test(d.query) && d.action === 'blocked') add('dns.block-domain', { domain: d.query.toLowerCase() }, `حظر النطاق ${d.query} على مستوى DNS.`, `Block the domain ${d.query} at DNS.`);
  }
  if (asset && ['critical', 'high'].includes(alert.severity) && /RANSOM|TAMPER|PROTECTED|LATERAL/.test(alert.rule_id || '')) add('endpoint.isolate-device', { device_ref: asset.external_id }, 'عزل الجهاز عن الشبكة مع إبقاء قناة الإدارة.', 'Isolate the device from the network while keeping the management channel.');
  return out;
}
