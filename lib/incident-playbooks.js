const evidence = Object.freeze({
  alert:'/api/alerts/{alert_id}',
  event:'/api/events/{evidence_id}',
  asset:'/api/assets/{asset_id}',
  case:'/api/cases/{case_id}/report',
  audit:'/api/audit/verify'
});

import { toAr } from './i18n-ar.js';
// Arabic for signals, steps and the automation effect is attached from lib/i18n-ar.js.
const localize = p => Object.freeze({...p,signals_ar:Object.freeze(p.signals.map(toAr)),phases:Object.freeze(p.phases.map(ph=>Object.freeze({...ph,steps_ar:Object.freeze(ph.steps.map(toAr))}))),automation:Object.freeze({...p.automation,effect_ar:toAr(p.automation.effect)})});
const playbook = (id,title_ar,title_en,signals,investigate,contain,recover) => localize({
  id,version:1,incident_type:id.replace('pb-',''),title_ar,title_en,signals:Object.freeze(signals),
  evidence_paths:Object.freeze([evidence.alert,evidence.event,evidence.asset,evidence.case,evidence.audit]),
  phases:Object.freeze([
    Object.freeze({id:'triage',mode:'human',steps:Object.freeze(['Confirm the alert and preserve linked evidence','Record scope, owner and confidence before changing anything'])}),
    Object.freeze({id:'investigate',mode:'human',steps:Object.freeze(investigate)}),
    Object.freeze({id:'contain',mode:'human-approved',steps:Object.freeze(contain)}),
    Object.freeze({id:'recover',mode:'human-approved',steps:Object.freeze(recover)}),
    Object.freeze({id:'review',mode:'human',steps:Object.freeze(['Verify recovery evidence','Record lessons, control gaps and follow-up owners'])})
  ]),
  automation:Object.freeze({id:'open-investigation-case',risk:'low',effect:'Create one local investigation case linked to the selected alert and its current evidence snapshot',requires_recent_mfa:true,requires_independent_approval:true,external_change:false})
});

export const supportedIncidentTypes=Object.freeze([
  'malware','ransomware','identity-compromise','remote-access','network-intrusion',
  'data-exposure','vulnerability-exploitation','defense-tamper','service-disruption','cloud-saas-compromise'
]);

export const incidentPlaybookCatalog=Object.freeze([
  playbook('pb-malware','برمجية خبيثة','Malware',['malicious process','quarantined file'],['Review process ancestry, signer, file hash and connections','Identify affected assets and users'],['Prefer connector quarantine only through the governed response workflow','Do not execute unknown files'],['Restore only after clean evidence and owner approval','Monitor for recurrence']),
  playbook('pb-ransomware','برمجية فدية','Ransomware',['mass file change','ransom note','backup anomaly'],['Preserve file-change, process and backup evidence','Estimate affected scope without opening samples'],['Use approved isolation only when the management path remains safe','Protect backup copies from destructive changes'],['Restore in dependency order from verified clean copies','Validate business service and watch for reinfection']),
  playbook('pb-identity-compromise','اختراق هوية','Identity compromise',['password spray','impossible travel','privilege change'],['Review sign-ins, MFA, token and privilege evidence','Identify active sessions and affected resources'],['Use the identity provider change process with independent approval','Preserve emergency access'],['Re-establish trusted authentication and review grants','Monitor new sign-ins and tokens']),
  playbook('pb-remote-access','وصول بعيد مشبوه','Suspicious remote access',['unexpected RDP','remote session anomaly'],['Build the remote-session timeline','Confirm source, target, relay, user and authorization'],['End or restrict a session only through an approved connector action','Keep an alternate management channel'],['Validate legitimate access paths and credentials','Review related hosts and sessions']),
  playbook('pb-network-intrusion','اختراق شبكي','Network intrusion',['IDS alert','lateral movement','malicious destination'],['Correlate flow, DNS, firewall and endpoint evidence','Map affected segments and exposed services'],['Use typed reversible blocks only after approval and impact analysis','Never push raw network commands'],['Verify traffic and service health after remediation','Remove temporary controls through rollback']),
  playbook('pb-data-exposure','تعرض بيانات','Data exposure',['unexpected transfer','public exposure'],['Identify data classification, source, destination and time window','Preserve access and flow evidence'],['Restrict exposure through the owner change process','Avoid deleting evidence or customer data'],['Verify access boundaries and notification decisions','Track corrective controls']),
  playbook('pb-vulnerability-exploitation','استغلال ثغرة','Vulnerability exploitation',['KEV finding','exploit indicator'],['Confirm affected version, exposure, KEV/EPSS and event evidence','Separate vulnerable from exploited'],['Apply compensating controls through approved change workflows','Do not run exploitation against production'],['Patch or mitigate under owner control and verify version','Rescan only within authorized scope']),
  playbook('pb-defense-tamper','عبث بأدوات الحماية','Defense tamper',['EDR stopped','log clearing','policy tamper'],['Review actor, process, errors, maintenance and recovery evidence','Distinguish authorized change, fault and suspected tamper'],['Restore protection through the approved service workflow','Preserve logs and alternate telemetry'],['Verify sensors, policy and event delivery','Investigate preceding activity']),
  playbook('pb-service-disruption','تعطل خدمة','Service disruption',['service unavailable','collector outage'],['Confirm service, dependencies, owner and health evidence','Check for security and operational causes'],['Use documented fail-safe and recovery plans','Do not permanently remove a service without separate safety approval'],['Restore dependencies first and verify postconditions','Document actual recovery time']),
  playbook('pb-cloud-saas-compromise','اختراق سحابي أو SaaS','Cloud or SaaS compromise',['risky OAuth consent','cloud identity anomaly'],['Review identity, application, grant and activity evidence','Identify tenant scope and application owners'],['Revoke or restrict access only through the provider change process','Preserve audit and emergency administration'],['Validate grants, identities and workload access','Monitor for renewed consent or token use'])
]);

const byId=new Map(incidentPlaybookCatalog.map(item=>[item.id,item]));
if(byId.size!==incidentPlaybookCatalog.length||supportedIncidentTypes.some(type=>!byId.has(`pb-${type}`)))throw new Error('incident_playbook_catalog_incomplete');
export const incidentPlaybook=id=>byId.get(id)||null;
