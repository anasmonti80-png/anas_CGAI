import { fail, object, text } from './common.js';
import { detect } from './prompt-guard.js';

export function modelPolicy({cloudConnectorAvailable=false,consents=[],now=new Date().toISOString()}={}) {
  const active=consents.filter(item=>item.status==='active'&&item.expires_at>now);
  return {schema_version:'cg.ai-model-policy/1',default_route:'local',local:{provider:'local-deterministic-evidence-analyst',primary:true,enabled:true,data_leaves_host:false},cloud:{optional:true,connector_available:cloudConnectorAvailable,enabled:cloudConnectorAvailable&&active.length>0,requires_customer_consent:true,requires_recent_mfa:true,redacted_only:true,active_consents:active.length,allowed_payload_fields:['schema_version','analysis_id','severity','status','occurrences','evidence_kinds','evidence_count','missing_evidence_count','confidence_level','confidence_score','suggested_playbook'],prohibited_payload_fields:['alert title','event identifiers','source identifiers','asset identifiers','hostnames','addresses','user data','raw logs','hashes','commands','credentials']},claim:{ar:'التحليل المحلي هو المسار الأساسي دائمًا. يبقى التحليل السحابي اختياريًا وغير متاح ما لم يُثبت موصل صريح وموافقة عميل سارية. لا يغادر الجهاز إلا المخطط المنقح الثابت.',en:'Local analysis is always the primary route. Cloud analysis is optional and remains unavailable unless a connector is explicitly installed and a current customer consent exists. Only the fixed redacted payload schema may leave the host.'}};
}

export function cloudPayload(analysis) {
  const payload={schema_version:'cg.ai-cloud-redacted/1',analysis_id:'redacted-analysis',severity:analysis.alert.severity,status:analysis.alert.status,occurrences:analysis.alert.occurrences,evidence_kinds:[...new Set(analysis.evidence.map(item=>item.kind))].sort(),evidence_count:analysis.evidence.length,missing_evidence_count:analysis.missing_evidence_ids.length,confidence_level:analysis.confidence.level,confidence_score:analysis.confidence.score,suggested_playbook:analysis.solution.playbook_id};
  const policy=modelPolicy(),allowed=new Set(policy.cloud.allowed_payload_fields);fail(Object.keys(payload).every(key=>allowed.has(key)),500,'cloud_payload_schema_violation');
  return {payload,redaction:{profile:'cg.ai-cloud-redaction/1',raw_evidence_included:false,identifiers_included:false,personal_data_included:false,commands_included:false,credentials_included:false,removed_classes:policy.cloud.prohibited_payload_fields}};
}

export function validateCloudResult(value) {
  object(value,['summary_ar','summary_en','provider_request_id'],'cloud_ai_result');
  // CG-121 a model answer that itself carries instructions, commands or exfiltration links is refused.
  fail(![value.summary_ar,value.summary_en].some(v=>detect(v).some(f=>f.severity==='high')),422,'cloud_ai_output_contains_instructions');
  return {summary_ar:text(value.summary_ar,'cloud_summary_ar',4000),summary_en:text(value.summary_en,'cloud_summary_en',4000),provider_request_id:text(value.provider_request_id,'cloud_provider_request_id',200,true)};
}
