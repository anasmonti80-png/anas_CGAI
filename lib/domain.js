import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { fail, AppError, text, object, choice, integer, timestamp, digest, redact, token } from './common.js';

const osFamilies=['windows','macos','linux','network','unknown'];
const deviceTypes=['workstation','server','domain-controller','switch','router','firewall','access-point','phone','printer','camera','iot','virtual-machine','container','unknown'];
const severities=['critical','high','medium','low','info'];
const kinds=['asset.observed','asset.context','asset.lifecycle','asset.compatibility','governance.threat_model','governance.risk_record','discovery.observed','visibility.gap','auth.failed','protection.observed','remote.application_present','remote.port_open','remote.attempt','remote.authenticated','remote.active','remote.ended','security.finding'];
const phases=['application_present','port_open','attempt','authenticated','active','ended'];
const parse = value => JSON.parse(value);
const safe = value => redact(value);
function calendarTimestamp(value,name) {
  fail(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value),400,`invalid_${name}`);
  const date=Date.parse(value);fail(Number.isFinite(date)&&date>=Date.UTC(2000,0,1)&&date<=Date.UTC(2100,0,1),400,`invalid_${name}`);
  fail(new Date(date).toISOString().slice(0,19)===value.slice(0,19),400,`invalid_${name}`);return new Date(date).toISOString();
}
function scopedIp(value) {
  if(isIP(value)===4){const p=value.split('.').map(Number);return p[0]===10||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||p[0]===127||(p[0]===169&&p[1]===254)||(p[0]===100&&p[1]>=64&&p[1]<=127)||(p[0]===192&&p[1]===0&&p[2]===2)||(p[0]===198&&p[1]===51&&p[2]===100)||(p[0]===203&&p[1]===0&&p[2]===113);}
  if(isIP(value)===6){const v=value.toLowerCase();return v==='::1'||v.startsWith('fc')||v.startsWith('fd')||/^fe[89ab]/.test(v)||v.startsWith('2001:db8:');}
  return false;
}
function cidr(value,name,{scoped=true}={}) {
  const raw=text(value,name,80),[address,prefixText,...rest]=raw.split('/');
  const family=isIP(address),prefix=Number(prefixText);
  fail(rest.length===0&&family!==0&&Number.isInteger(prefix)&&prefix>=0&&prefix<=(family===4?32:128),400,`invalid_${name}`);
  if(scoped)fail(scopedIp(address),400,`public_${name}_not_allowed`);
  return `${address}/${prefix}`;
}
function party(value, name) {
  if (value === undefined || value === null) return {hostname:null,ip:null,account:null};
  object(value,['hostname','ip','account'],name);
  const result={hostname:text(value.hostname,`${name}_hostname`,200,true),ip:text(value.ip,`${name}_ip`,80,true),account:text(value.account,`${name}_account`,200,true)};
  if (result.ip) fail(isIP(result.ip)!==0,400,`invalid_${name}_ip`);
  return result;
}
export function validateEvent(value, now) {
  object(value,['event_id','kind','observed_at','asset','details','origin'], 'event');
  const id=text(value.event_id,'event_id',200), kind=choice(value.kind,kinds,'event_kind');
  const observedAt=timestamp(value.observed_at,'observed_at',now);
  const a=object(value.asset,['external_id','hostname','os_family','device_type','addresses'],'asset');
  const asset={external_id:text(a.external_id,'asset_external_id',200),hostname:text(a.hostname,'hostname',200,true),os_family:choice(a.os_family||'unknown',osFamilies,'os_family'),device_type:choice(a.device_type||'unknown',deviceTypes,'device_type'),addresses:a.addresses||[]};
  fail(Array.isArray(asset.addresses) && asset.addresses.length<=32 && asset.addresses.every(ip=>typeof ip==='string' && isIP(ip)!==0),400,'invalid_addresses');
  let details = {};
  const d=value.details || {};
  if (kind==='asset.observed') object(d,[],'details');
  else if (kind==='asset.context') {
    object(d,['owner','business_service','service_name','site','data_sensitivity','maintenance_windows','service_criticality'],'details');
    const owner=object(d.owner,['owner_id','display_name','contact'],'owner'),windows=d.maintenance_windows||[];
    fail(Array.isArray(windows)&&windows.length<=20,400,'invalid_maintenance_windows');
    details={owner:{owner_id:text(owner.owner_id,'owner_id',200),display_name:text(owner.display_name,'owner_display_name',200),contact:text(owner.contact,'owner_contact',300,true)},business_service:text(d.business_service,'business_service',300),service_name:text(d.service_name,'service_name',300,true),site:text(d.site,'site',200),data_sensitivity:choice(d.data_sensitivity,['public','internal','confidential','restricted','unknown'],'data_sensitivity'),maintenance_windows:windows.map((window,index)=>text(window,`maintenance_window_${index}`,300)),service_criticality:choice(d.service_criticality,['low','medium','high','critical'],'service_criticality')};
  }
  else if (kind==='asset.lifecycle') {
    object(d,['product','operating_system','vendor_support','plan'],'details');
    const productInput=object(d.product,['vendor','name','version','edition'],'lifecycle_product'),operatingSystemInput=object(d.operating_system,['name','version','build'],'lifecycle_operating_system'),supportInput=object(d.vendor_support,['status','standard_support_end','security_updates_end','extended_support'],'vendor_support'),extendedInput=object(supportInput.extended_support,['available','enrolled','end_at'],'extended_support'),planInput=object(d.plan,['action','target','owner_id','due_at','status'],'lifecycle_plan');
    fail(typeof extendedInput.available==='boolean'&&typeof extendedInput.enrolled==='boolean',400,'invalid_extended_support_state');fail(!extendedInput.enrolled||extendedInput.available,400,'extended_support_enrollment_requires_availability');
    const extended_support={available:extendedInput.available,enrolled:extendedInput.enrolled,end_at:extendedInput.end_at?calendarTimestamp(extendedInput.end_at,'extended_support_end_at'):null};fail(!extended_support.available||extended_support.end_at,400,'extended_support_end_required');
    const supportStatus=choice(supportInput.status,['supported','extended','ended','unknown'],'vendor_support_status');fail(supportStatus!=='extended'||extended_support.enrolled,400,'extended_status_requires_enrollment');
    details={product:{vendor:text(productInput.vendor,'product_vendor',200),name:text(productInput.name,'product_name',300),version:text(productInput.version,'product_version',200),edition:text(productInput.edition,'product_edition',200,true)},operating_system:{name:text(operatingSystemInput.name,'operating_system_name',300),version:text(operatingSystemInput.version,'operating_system_version',200),build:text(operatingSystemInput.build,'operating_system_build',200,true)},vendor_support:{status:supportStatus,standard_support_end:calendarTimestamp(supportInput.standard_support_end,'standard_support_end'),security_updates_end:calendarTimestamp(supportInput.security_updates_end,'security_updates_end'),extended_support},plan:{action:choice(planInput.action,['upgrade','replace','retire'],'lifecycle_plan_action'),target:text(planInput.target,'lifecycle_plan_target',500),owner_id:text(planInput.owner_id,'lifecycle_plan_owner',200),due_at:calendarTimestamp(planInput.due_at,'lifecycle_plan_due_at'),status:choice(planInput.status,['planned','approved','in-progress','completed'],'lifecycle_plan_status')}};
  }
  else if (kind==='asset.compatibility') {
    object(d,['profile','support_state','agent','access_mode','read_only_supported','network_isolation','tested_capabilities','performance_constraints','licensing_constraints','recommendation','evidence_basis'],'details');
    const bounded=(value,max,name,{allowEmpty=false}={})=>{fail(Array.isArray(value)&&value.length<=max&&(allowEmpty||value.length>0),400,`invalid_${name}`);return value;};
    const agentInput=object(d.agent,['status','reason'],'compatibility_agent'),isolationInput=object(d.network_isolation,['required','status','zone'],'compatibility_isolation'),basisInput=object(d.evidence_basis,['level','reference'],'compatibility_evidence_basis');fail(typeof d.read_only_supported==='boolean'&&typeof isolationInput.required==='boolean',400,'invalid_compatibility_boolean');
    const evidenceLevel=choice(basisInput.level,['source-report','vendor-documentation','authorized-lab','not-tested'],'compatibility_evidence_level'),evidenceReference=text(basisInput.reference,'compatibility_evidence_reference',500,true);fail(!['vendor-documentation','authorized-lab'].includes(evidenceLevel)||evidenceReference,400,'compatibility_reference_required');
    details={profile:choice(d.profile,['windows-server-2008-r2','windows-server-2012-r2','unsupported-linux','legacy-network-device','other'],'compatibility_profile'),support_state:choice(d.support_state,['vendor-supported','extended-support','end-of-support','unknown'],'compatibility_support_state'),agent:{status:choice(agentInput.status,['available','unavailable','unsupported','unknown'],'compatibility_agent_status'),reason:text(agentInput.reason,'compatibility_agent_reason',1000)},access_mode:choice(d.access_mode,['agent','read-only-remote','authenticated-collector','manual-import','none','unknown'],'compatibility_access_mode'),read_only_supported:d.read_only_supported,network_isolation:{required:isolationInput.required,status:choice(isolationInput.status,['isolated','partial','not-isolated','unknown'],'compatibility_isolation_status'),zone:text(isolationInput.zone,'compatibility_isolation_zone',300,true)},tested_capabilities:bounded(d.tested_capabilities||[],30,'tested_capabilities',{allowEmpty:true}).map((capability,index)=>choice(capability,['inventory','event-logs','remote-session-evidence','network-read','config-backup','health-monitoring'],`tested_capability_${index}`)),performance_constraints:bounded(d.performance_constraints,30,'performance_constraints').map((constraint,index)=>text(constraint,`performance_constraint_${index}`,1000)),licensing_constraints:bounded(d.licensing_constraints,30,'licensing_constraints').map((constraint,index)=>text(constraint,`licensing_constraint_${index}`,1000)),recommendation:text(d.recommendation,'compatibility_recommendation',2000),evidence_basis:{level:evidenceLevel,reference:evidenceReference}};
    if(evidenceLevel==='not-tested')fail(details.tested_capabilities.length===0,400,'not_tested_cannot_claim_capability');
  }
  else if (kind==='governance.threat_model') {
    object(d,['environment','valuable_assets','trust_boundaries','attack_scenarios','service_outage_impact','data_disclosure_impact'],'details');
    const environment=object(d.environment,['environment_id','name','scope'],'environment');
    const bounded=(value,max,name,{allowEmpty=false}={})=>{fail(Array.isArray(value)&&value.length<=max&&(allowEmpty||value.length>0),400,`invalid_${name}`);return value;};
    const valuable_assets=bounded(d.valuable_assets,100,'valuable_assets').map((value,index)=>{object(value,['asset_ref','name','value_reason'],`valuable_asset_${index}`);return {asset_ref:text(value.asset_ref,`valuable_asset_${index}_ref`,200),name:text(value.name,`valuable_asset_${index}_name`,200),value_reason:text(value.value_reason,`valuable_asset_${index}_reason`,1000)};});
    const trust_boundaries=bounded(d.trust_boundaries,100,'trust_boundaries').map((value,index)=>{object(value,['boundary_id','name','from_zone','to_zone','controls'],`trust_boundary_${index}`);return {boundary_id:text(value.boundary_id,`trust_boundary_${index}_id`,200),name:text(value.name,`trust_boundary_${index}_name`,200),from_zone:text(value.from_zone,`trust_boundary_${index}_from`,200),to_zone:text(value.to_zone,`trust_boundary_${index}_to`,200),controls:bounded(value.controls||[],20,`trust_boundary_${index}_controls`,{allowEmpty:true}).map((control,controlIndex)=>text(control,`trust_boundary_${index}_control_${controlIndex}`,300))};});
    const assetRefs=new Set(valuable_assets.map(item=>item.asset_ref)),boundaryRefs=new Set(trust_boundaries.map(item=>item.boundary_id));
    fail(assetRefs.size===valuable_assets.length,400,'duplicate_valuable_asset_ref');fail(boundaryRefs.size===trust_boundaries.length,400,'duplicate_trust_boundary_ref');
    const attack_scenarios=bounded(d.attack_scenarios,100,'attack_scenarios').map((value,index)=>{object(value,['scenario_id','title','description','entry_point','target_asset_refs','trust_boundary_refs','likelihood'],`attack_scenario_${index}`);const target_asset_refs=bounded(value.target_asset_refs,100,`attack_scenario_${index}_assets`).map((ref,refIndex)=>text(ref,`attack_scenario_${index}_asset_${refIndex}`,200)),trust_boundary_refs=bounded(value.trust_boundary_refs,100,`attack_scenario_${index}_boundaries`).map((ref,refIndex)=>text(ref,`attack_scenario_${index}_boundary_${refIndex}`,200));fail(target_asset_refs.every(ref=>assetRefs.has(ref)),400,'unknown_scenario_asset_ref');fail(trust_boundary_refs.every(ref=>boundaryRefs.has(ref)),400,'unknown_scenario_boundary_ref');return {scenario_id:text(value.scenario_id,`attack_scenario_${index}_id`,200),title:text(value.title,`attack_scenario_${index}_title`,300),description:text(value.description,`attack_scenario_${index}_description`,2000),entry_point:text(value.entry_point,`attack_scenario_${index}_entry_point`,300),target_asset_refs,trust_boundary_refs,likelihood:choice(value.likelihood,['low','medium','high'],'likelihood')};});
    fail(new Set(attack_scenarios.map(item=>item.scenario_id)).size===attack_scenarios.length,400,'duplicate_attack_scenario_id');
    const impact=(value,name)=>{object(value,['severity','description'],name);return {severity:choice(value.severity,['low','medium','high','critical'],`${name}_severity`),description:text(value.description,`${name}_description`,2000)};};
    details={environment:{environment_id:text(environment.environment_id,'environment_id',200),name:text(environment.name,'environment_name',300),scope:text(environment.scope,'environment_scope',1000)},valuable_assets,trust_boundaries,attack_scenarios,service_outage_impact:impact(d.service_outage_impact,'service_outage_impact'),data_disclosure_impact:impact(d.data_disclosure_impact,'data_disclosure_impact')};
  }
  else if (kind==='governance.risk_record') {
    object(d,['risk_id','title','description','category','inherent_severity','residual_severity','likelihood','status','coverage','evidence_refs','owner','remediation','exception','risk_acceptance'],'details');
    const bounded=(value,max,name,{allowEmpty=false}={})=>{fail(Array.isArray(value)&&value.length<=max&&(allowEmpty||value.length>0),400,`invalid_${name}`);return value;};
    const coverageInput=object(d.coverage,['state','requirement_ids','control_refs'],'risk_coverage'),requirement_ids=bounded(coverageInput.requirement_ids,100,'risk_requirement_ids').map((id,index)=>{const value=text(id,`risk_requirement_${index}`,20),match=value.match(/^CG-(\d{3,4})$/);fail(match&&Number(match[1])>=1&&Number(match[1])<=1440,400,'invalid_risk_requirement_id');return value;}),control_refs=bounded(coverageInput.control_refs||[],100,'risk_control_refs',{allowEmpty:true}).map((ref,index)=>text(ref,`risk_control_ref_${index}`,200));
    const evidence_refs=bounded(d.evidence_refs,100,'risk_evidence_refs').map((reference,index)=>{object(reference,['type','id'],`risk_evidence_ref_${index}`);return {type:choice(reference.type,['event','alert','case','action'],'risk_evidence_type'),id:text(reference.id,`risk_evidence_id_${index}`,200)};});
    const ownerInput=object(d.owner,['owner_id','display_name','contact'],'risk_owner'),owner={owner_id:text(ownerInput.owner_id,'risk_owner_id',200),display_name:text(ownerInput.display_name,'risk_owner_name',200),contact:text(ownerInput.contact,'risk_owner_contact',300,true)};
    const remediationInput=object(d.remediation,['status','plan','due_at'],'risk_remediation'),remediation={status:choice(remediationInput.status,['not-started','planned','in-progress','implemented','verified','not-applicable'],'risk_remediation_status'),plan:text(remediationInput.plan,'risk_remediation_plan',2000),due_at:calendarTimestamp(remediationInput.due_at,'risk_remediation_due_at')};
    const exceptionInput=object(d.exception,['status','reason','expires_at','approved_by'],'risk_exception'),exceptionStatus=choice(exceptionInput.status,['none','requested','active','expired','rejected'],'risk_exception_status'),exception={status:exceptionStatus,reason:text(exceptionInput.reason,'risk_exception_reason',2000,true),expires_at:exceptionInput.expires_at?calendarTimestamp(exceptionInput.expires_at,'risk_exception_expires_at'):null,approved_by:text(exceptionInput.approved_by,'risk_exception_approved_by',200,true)};fail(exceptionStatus==='none'||exception.reason,400,'risk_exception_reason_required');fail(exceptionStatus!=='active'||(exception.expires_at&&exception.approved_by),400,'active_risk_exception_requires_approval_and_expiry');
    const acceptanceInput=object(d.risk_acceptance,['status','accepted_by','accepted_at','review_due_at','review_interval_days','rationale'],'risk_acceptance'),acceptanceStatus=choice(acceptanceInput.status,['not-accepted','proposed','accepted','rejected'],'risk_acceptance_status'),risk_acceptance={status:acceptanceStatus,accepted_by:text(acceptanceInput.accepted_by,'risk_accepted_by',200,true),accepted_at:acceptanceInput.accepted_at?calendarTimestamp(acceptanceInput.accepted_at,'risk_accepted_at'):null,review_due_at:acceptanceInput.review_due_at?calendarTimestamp(acceptanceInput.review_due_at,'risk_review_due_at'):null,review_interval_days:acceptanceInput.review_interval_days===null||acceptanceInput.review_interval_days===undefined?null:integer(acceptanceInput.review_interval_days,1,365,'risk_review_interval_days'),rationale:text(acceptanceInput.rationale,'risk_acceptance_rationale',2000,true)};
    if(acceptanceStatus==='accepted'){fail(risk_acceptance.accepted_by&&risk_acceptance.accepted_at&&risk_acceptance.review_due_at&&risk_acceptance.review_interval_days&&risk_acceptance.rationale,400,'accepted_risk_requires_review');const reviewSpan=Date.parse(risk_acceptance.review_due_at)-Date.parse(risk_acceptance.accepted_at);fail(reviewSpan>0&&reviewSpan<=risk_acceptance.review_interval_days*86400000,400,'invalid_risk_review_window');}
    const riskStatus=choice(d.status,['open','mitigating','accepted','closed'],'risk_status');fail(riskStatus!=='accepted'||acceptanceStatus==='accepted',400,'accepted_status_requires_risk_acceptance');
    details={risk_id:text(d.risk_id,'risk_id',200),title:text(d.title,'risk_title',300),description:text(d.description,'risk_description',2000),category:text(d.category,'risk_category',200),inherent_severity:choice(d.inherent_severity,['low','medium','high','critical'],'inherent_severity'),residual_severity:choice(d.residual_severity,['low','medium','high','critical','unknown'],'residual_severity'),likelihood:choice(d.likelihood,['low','medium','high'],'risk_likelihood'),status:riskStatus,coverage:{state:choice(coverageInput.state,['covered','partial','gap','unknown'],'risk_coverage_state'),requirement_ids,control_refs},evidence_refs,owner,remediation,exception,risk_acceptance};
  }
  else if (kind==='discovery.observed') {
    object(d,['authorization_ref','acquisition','availability','networks','routes','vlans','interfaces','services'],'details');
    fail(asset.addresses.every(scopedIp),400,'public_discovery_address_not_allowed');
    const array=(value,max,name)=>{fail(Array.isArray(value)&&value.length<=max,400,`invalid_${name}`);return value;};
    const networks=array(d.networks||[],64,'networks').map((value,index)=>cidr(value,`network_${index}`));
    const routes=array(d.routes||[],256,'routes').map((value,index)=>{object(value,['destination','gateway','interface'],`route_${index}`);const gateway=text(value.gateway,`route_${index}_gateway`,80,true);if(gateway)fail(scopedIp(gateway),400,'public_route_gateway_not_allowed');return {destination:cidr(value.destination,`route_${index}_destination`,{scoped:false}),gateway,interface:text(value.interface,`route_${index}_interface`,100,true)};});
    const vlans=array(d.vlans||[],128,'vlans').map((value,index)=>{object(value,['id','name'],`vlan_${index}`);return {id:integer(value.id,1,4094,`vlan_${index}_id`),name:text(value.name,`vlan_${index}_name`,100,true)};});
    const interfaces=array(d.interfaces||[],256,'interfaces').map((value,index)=>{object(value,['name','status','vlan'],'interface');return {name:text(value.name,`interface_${index}_name`,100),status:choice(value.status,['up','down','unknown'],`interface_${index}_status`),vlan:value.vlan===null||value.vlan===undefined?null:integer(value.vlan,1,4094,`interface_${index}_vlan`)};});
    const services=array(d.services||[],256,'services').map((value,index)=>{object(value,['transport','port','state','name','evidence'],'service');return {transport:choice(value.transport,['tcp','udp'],`service_${index}_transport`),port:integer(value.port,1,65535,`service_${index}_port`),state:choice(value.state,['observed-open','observed-closed','unknown'],`service_${index}_state`),name:text(value.name,`service_${index}_name`,100,true),evidence:choice(value.evidence,['source-report','authenticated-observation'],`service_${index}_evidence`)};});
    details={authorization_ref:text(d.authorization_ref,'authorization_ref',200),acquisition:choice(d.acquisition,['passive-import','authenticated-collector','span-tap','flow-logs','agent'], 'acquisition'),availability:choice(d.availability,['up','down','unknown'],'availability'),networks,routes,vlans,interfaces,services};
  }
  else if (kind==='visibility.gap') {
    object(d,['entity_type','entity_ref','reason','last_seen','recommendation','status'],'details');
    const entity_type=choice(d.entity_type,['system','network','account'],'entity_type'),allowed={system:['no-agent','no-logs','no-authorization','outage'],network:['no-span','no-logs','no-authorization','outage'],account:['no-logs','no-authorization','outage']}[entity_type];
    const entity_ref=entity_type==='network'?cidr(d.entity_ref,'entity_ref'):text(d.entity_ref,'entity_ref',300);
    details={entity_type,entity_ref,reason:choice(d.reason,allowed,'gap_reason'),last_seen:d.last_seen===null||d.last_seen===undefined?null:timestamp(d.last_seen,'last_seen',now),recommendation:text(d.recommendation,'recommendation',1000),status:choice(d.status||'open',['open','resolved'],'gap_status')};
  }
  else if (kind==='auth.failed') {
    object(d,['account','source_ip','protocol'],'details');
    details={account:text(d.account,'account',200,true),source_ip:text(d.source_ip,'source_ip',80,true),protocol:choice(d.protocol||'unknown',['rdp','ssh','winrm','web','unknown'],'protocol')};
    if (details.source_ip) fail(isIP(details.source_ip)!==0,400,'invalid_source_ip');
  } else if (kind==='protection.observed') {
    object(d,['engine','installed','running','collecting','mode'],'details');
    for (const key of ['installed','running','collecting']) fail(typeof d[key]==='boolean',400,`invalid_${key}`);
    fail(!d.running || d.installed,400,'running_requires_installed');
    fail(!d.collecting || d.running,400,'collecting_requires_running');
    details={engine:text(d.engine,'engine',200),installed:d.installed,running:d.running,collecting:d.collecting,mode:choice(d.mode,['active','passive','unknown'],'mode'),prevention_verified:false,verification_reason:'No independent prevention test evidence'};
  } else if (kind.startsWith('remote.')) {
    object(d,['session_id','protocol','source_a','target_b','relay','evidence_type','assessment','assessment_basis','authorization_ref','rationale'],'details');
    const phase=kind.slice(7);
    const allowed={application_present:['software_inventory'],port_open:['port_observation'],attempt:['connection_attempt'],authenticated:['authentication_log'],active:['session_log'],ended:['session_log']};
    const assessment=choice(d.assessment||'unknown',['unknown','authorized','suspicious'],'assessment'),authorization_ref=text(d.authorization_ref,'authorization_ref',200,true),rationale=text(d.rationale,'rationale',1000,true);
    fail(assessment!=='authorized'||authorization_ref,400,'authorized_remote_requires_reference');
    fail(assessment!=='suspicious'||rationale,400,'suspicious_remote_requires_rationale');
    details={session_id:text(d.session_id,'session_id',200),protocol:choice(d.protocol,['rdp','ssh','winrm','anydesk','teamviewer','apple-remote-desktop','vpn','other'],'protocol'),source_a:party(d.source_a,'source_a'),target_b:party(d.target_b,'target_b'),relay:d.relay===true,evidence_type:choice(d.evidence_type,allowed[phase],'evidence_type'),assessment,assessment_basis:choice(d.assessment_basis||'source-report',['source-report','policy-match','analyst-reviewed'],'assessment_basis'),authorization_ref,rationale};
    if (details.relay) details.source_a={hostname:null,ip:null,account:null};
  } else if (kind==='security.finding') {
    object(d,['title','severity','description'],'details');
    details={title:text(d.title,'title',200),severity:choice(d.severity,severities,'severity'),description:text(d.description,'description',2000)};
  }
  let origin;
  if(value.origin){object(value.origin,['parser','record_id','raw_sha256'],'origin');origin={parser:choice(value.origin.parser,['windows-security/1'],'parser'),record_id:text(value.origin.record_id,'record_id',100),raw_sha256:text(value.origin.raw_sha256,'raw_sha256',64)};fail(/^[a-f0-9]{64}$/.test(origin.raw_sha256),400,'invalid_raw_sha256');}
  return safe({event_id:id,kind,observed_at:observedAt,asset,details,...(origin?{origin}:{})});
}

export class Domain {
  constructor(store,{clock=()=>Date.now()}={}) { this.s=store; this.clock=clock; }
  now() { return new Date(this.clock()).toISOString(); }
  createSource(actor,input) {
    object(input,['name','stale_seconds','source_type'],'source');
    fail(this.s.get('SELECT COUNT(*) n FROM sources').n<100,409,'source_limit');
    const id=randomUUID(), name=text(input.name,'source_name',100), stale=integer(input.stale_seconds||300,30,86400,'stale_seconds'), sourceType=choice(input.source_type||'generic',['generic','managed-agent','log-forwarder','network-collector'],'source_type');
    fail(!this.s.get('SELECT id FROM sources WHERE name=?',name),409,'source_name_exists');
    const credential=token();
    this.s.transaction(()=>{
      this.s.run('INSERT INTO sources(id,name,kind,token_hash,created_at,stale_seconds) VALUES (?,?,?,?,?,?)',id,name,sourceType,digest(credential),this.now(),stale);
      this.s.audit(actor,'source.created',id,{source_type:sourceType,schema_version:'cg.telemetry/1'},this.now());
    });
    return {id,name,source_type:sourceType,schema_version:'cg.telemetry/1',token:credential,stale_seconds:stale};
  }
  rotateSource(actor,id) {
    this.s.require('SELECT id FROM sources WHERE id=?',[id]);
    const credential=token();
    this.s.transaction(()=>{this.s.run('UPDATE sources SET token_hash=?,revoked=0 WHERE id=?',digest(credential),id);this.s.audit(actor,'source.rotated',id,{},this.now());});
    return {id,token:credential};
  }
  revokeSource(actor,id) {
    this.s.require('SELECT id FROM sources WHERE id=?',[id]);
    this.s.transaction(()=>{this.s.run('UPDATE sources SET token_hash=NULL,revoked=1 WHERE id=?',id);this.s.audit(actor,'source.revoked',id,{},this.now());});
    return {id,status:'revoked'};
  }
  sourceToken(credential,id) {
    fail(typeof credential==='string' && credential.length<=100,401,'invalid_source_token');
    const source=this.s.get('SELECT id FROM sources WHERE id=? AND token_hash=? AND revoked=0',id,digest(credential));
    fail(source,401,'invalid_source_token'); return source;
  }
  sources() {
    return this.s.all('SELECT id,name,kind,created_at,last_received,stale_seconds,revoked FROM sources ORDER BY created_at DESC').map(s=>{
      const age=Math.max(0,this.clock()-Date.parse(s.last_received || s.created_at))/1000;
      const source_type=['generic','managed-agent','log-forwarder','network-collector'].includes(s.kind)?s.kind:'generic';
      const health=s.revoked?'revoked':age>s.stale_seconds?'lost-coverage':s.last_received?'receiving':'awaiting-data';
      const monitor_state=source_type==='managed-agent'?({receiving:'agent-online','lost-coverage':'agent-lost','awaiting-data':'awaiting-agent','revoked':'revoked'}[health]):source_type==='log-forwarder'?({receiving:'logs-flowing','lost-coverage':'log-delivery-failed','awaiting-data':'awaiting-logs','revoked':'revoked'}[health]):health;
      return {id:s.id,name:s.name,source_type,schema_version:'cg.telemetry/1',created_at:s.created_at,last_received:s.last_received,stale_seconds:s.stale_seconds,revoked:s.revoked,age_seconds:Math.floor(age),health,monitor_state};
    });
  }
  ingest(actor,sourceId,input) {
    object(input,['schema_version','events'],'batch');
    fail(input.schema_version==='cg.telemetry/1',400,'unsupported_schema');
    fail(Array.isArray(input.events) && input.events.length>=1 && input.events.length<=250,400,'batch_requires_1_to_250_events');
    const source=this.s.require('SELECT * FROM sources WHERE id=?',[sourceId]);
    fail(!source.revoked,409,'source_revoked');
    const events=input.events.map(raw=>({rawHash:digest(raw),data:validateEvent(raw,this.clock())}));
    return this.s.transaction(()=>{
      let accepted=0,duplicates=0;
      for (const {rawHash,data:e} of events) {
        const previous=this.s.get('SELECT original_sha256 FROM events WHERE source_id=? AND external_id=?',sourceId,e.event_id);
        if (previous) { fail(previous.original_sha256===rawHash,409,'event_id_content_conflict'); duplicates++; continue; }
        const asset=this.observe(sourceId,e.asset,e.observed_at);
        const id=randomUUID(), payload=JSON.stringify(e), receivedAt=this.now();
        this.s.run('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',id,sourceId,e.event_id,asset.id,e.kind,e.observed_at,receivedAt,'cg.telemetry/1',e.origin?.parser||'cg-json/1',rawHash,digest(payload),payload);
        this.correlate({id,source_id:sourceId,asset_id:asset.id,...e});
        accepted++;
      }
      this.s.run('UPDATE sources SET last_received=? WHERE id=?',this.now(),sourceId);
      this.s.audit(actor,'telemetry.ingested',sourceId,{accepted,duplicates},this.now());
      return {accepted,duplicates,received_at:this.now()};
    });
  }
  observe(sourceId,a,observedAt) {
    let asset=this.s.get('SELECT * FROM assets WHERE source_id=? AND external_id=?',sourceId,a.external_id);
    if (!asset) {
      const id=randomUUID(), protection=JSON.stringify({engine:null,installed:null,running:null,collecting:null,mode:'unknown',prevention_verified:false});
      this.s.run('INSERT INTO assets(id,source_id,external_id,hostname,os_family,device_type,addresses,first_seen,last_seen,received_at,protection) VALUES (?,?,?,?,?,?,?,?,?,?,?)',id,sourceId,a.external_id,a.hostname,a.os_family,a.device_type,JSON.stringify(a.addresses),observedAt,observedAt,this.now(),protection);
      asset=this.s.get('SELECT * FROM assets WHERE id=?',id);
    } else if (observedAt>=asset.last_seen) {
      this.s.run('UPDATE assets SET hostname=COALESCE(?,hostname),os_family=CASE WHEN ?=\'unknown\' THEN os_family ELSE ? END,device_type=CASE WHEN ?=\'unknown\' THEN device_type ELSE ? END,addresses=?,last_seen=?,received_at=?,version=version+1 WHERE id=?',a.hostname,a.os_family,a.os_family,a.device_type,a.device_type,JSON.stringify(a.addresses),observedAt,this.now(),asset.id);
    }
    return asset;
  }
  alert({key,assetId=null,sourceId=null,rule,severity,title,eventId=null}) {
    let existing=this.s.get('SELECT * FROM alerts WHERE dedup_key=?',key);
    if (existing) {
      const evidence=parse(existing.evidence_ids); if (eventId && !evidence.includes(eventId)) evidence.push(eventId);
      this.s.run('UPDATE alerts SET occurrences=occurrences+1,last_seen=?,evidence_ids=?,status=\'open\',acknowledged_at=NULL,acknowledged_by=NULL WHERE id=?',this.now(),JSON.stringify(evidence.slice(-100)),existing.id);
      return existing.id;
    }
    const id=randomUUID();
    this.s.run('INSERT INTO alerts(id,dedup_key,asset_id,source_id,rule_id,rule_version,severity,title,first_seen,last_seen,evidence_ids) VALUES (?,?,?,?,?,?,?,?,?,?,?)',id,key,assetId,sourceId,rule,'1.0.0',severity,title,this.now(),this.now(),JSON.stringify(eventId?[eventId]:[]));
    return id;
  }
  correlate(e) {
    const day=e.observed_at.slice(0,10);
    if (e.kind==='discovery.observed') {
      const previousRow=this.s.get('SELECT id,payload FROM events WHERE asset_id=? AND kind=\'discovery.observed\' AND id<>? ORDER BY observed_at DESC,received_at DESC,id DESC LIMIT 1',e.asset_id,e.id);
      const previous=previousRow?parse(previousRow.payload).details:null;
      if(!previous)this.alert({key:`discovery-added:${e.asset_id}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-ASSET-ADDED',severity:'info',title:'Authorized discovery added an asset / أضيف أصل من اكتشاف مصرح',eventId:e.id});
      else if(digest(previous)!==digest(e.details))this.alert({key:`discovery-change:${e.asset_id}:${e.id}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-ASSET-CHANGED',severity:'medium',title:'Authorized discovery observed an asset change / تغير أصل في اكتشاف مصرح',eventId:e.id});
      if(e.details.availability==='down')this.alert({key:`discovery-down:${e.asset_id}:${e.id}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-ASSET-UNREACHABLE',severity:'high',title:'Source reports asset unavailable / المصدر يبلغ أن الأصل غير متاح',eventId:e.id});
      if(previous?.availability==='down'&&e.details.availability==='up')this.alert({key:`discovery-restored:${e.asset_id}:${e.id}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-ASSET-RESTORED',severity:'info',title:'Source reports asset restored / المصدر يبلغ عودة الأصل',eventId:e.id});
    }
    if (e.kind==='visibility.gap') {
      const key=`visibility-gap:${e.source_id}:${e.details.entity_type}:${digest(e.details.entity_ref)}`;
      if(e.details.status==='open')this.alert({key,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-VISIBILITY-GAP',severity:e.details.reason==='outage'?'high':'medium',title:`Visibility gap: ${e.details.reason} / فجوة رؤية: ${e.details.reason}`,eventId:e.id});
      else this.s.run("UPDATE alerts SET status='resolved',last_seen=? WHERE dedup_key=?",this.now(),key);
    }
    if (e.kind==='security.finding') this.alert({key:`reported:${e.asset_id}:${digest(e.details.title)}:${day}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-REPORTED-FINDING',severity:e.details.severity,title:e.details.title,eventId:e.id});
    if (e.kind==='auth.failed') {
      const start=new Date(Date.parse(e.observed_at)-5*60*1000).toISOString();
      const recent=this.s.all('SELECT id,payload FROM events WHERE source_id=? AND asset_id=? AND kind=\'auth.failed\' AND observed_at BETWEEN ? AND ?',e.source_id,e.asset_id,start,e.observed_at);
      const matching=recent.filter(x=>{const d=parse(x.payload).details; return d.account===e.details.account && d.source_ip===e.details.source_ip;});
      if (matching.length>=5) this.alert({key:`auth:${e.asset_id}:${digest([e.details.account,e.details.source_ip])}:${day}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-AUTH-FAILURES-5-IN-5M',severity:'high',title:'Repeated authentication failures / محاولات دخول فاشلة متكررة',eventId:e.id});
    }
    if (e.kind==='protection.observed') {
      const last=this.s.get('SELECT observed_at FROM events WHERE asset_id=? AND kind=\'protection.observed\' ORDER BY observed_at DESC LIMIT 1',e.asset_id);
      if (e.observed_at>=last.observed_at) this.s.run('UPDATE assets SET protection=? WHERE id=?',JSON.stringify({...e.details,observed_at:e.observed_at,source_id:e.source_id}),e.asset_id);
      if (e.details.installed && !e.details.running) this.alert({key:`protection:${e.asset_id}:${day}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-PROTECTION-NOT-RUNNING',severity:'high',title:'Protection reported stopped / مصدر الحماية يبلّغ عن توقفها',eventId:e.id});
    }
    if (e.kind.startsWith('remote.')) this.remote(e);
  }
  remote(e) {
    const d=e.details, phase=e.kind.slice(7);
    const old=this.s.get('SELECT * FROM remote_sessions WHERE source_id=? AND asset_id=? AND session_key=?',e.source_id,e.asset_id,d.session_id);
    const evidence=old?parse(old.evidence_ids):[]; evidence.push(e.id);
    if (!old) this.s.run('INSERT INTO remote_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',randomUUID(),e.source_id,e.asset_id,d.session_id,d.protocol,phase,JSON.stringify(d.source_a),JSON.stringify(d.target_b),d.relay?1:0,d.assessment,e.observed_at,e.observed_at,JSON.stringify(evidence));
    else {
      fail(old.protocol===d.protocol,409,'session_protocol_conflict');
      const advances=e.observed_at>=old.last_seen && phases.indexOf(phase)>=phases.indexOf(old.phase);
      const mergeParty=(previous,current)=>Object.fromEntries(Object.keys(current).map(k=>[k,current[k]??previous[k]]));
      const sourceParty=d.relay?d.source_a:mergeParty(parse(old.source_a),d.source_a);
      const targetParty=mergeParty(parse(old.target_b),d.target_b);
      this.s.run('UPDATE remote_sessions SET phase=?,source_a=?,target_b=?,relay=?,confidence=?,last_seen=?,evidence_ids=? WHERE id=?',advances?phase:old.phase,advances?JSON.stringify(sourceParty):old.source_a,advances?JSON.stringify(targetParty):old.target_b,advances?(d.relay?1:0):old.relay,advances?d.assessment:old.confidence,advances?e.observed_at:old.last_seen,JSON.stringify(evidence.slice(-100)),old.id);
    }
    if (phase==='port_open') this.alert({key:`exposure:${e.asset_id}:${d.protocol}:${e.observed_at.slice(0,10)}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-REMOTE-EXPOSURE',severity:'medium',title:'Remote service exposure; session not proven / انكشاف خدمة دون إثبات جلسة',eventId:e.id});
    if (d.assessment==='suspicious'&&phase!=='application_present') this.alert({key:`remote-suspicious:${e.asset_id}:${d.session_id}:${e.observed_at.slice(0,10)}`,assetId:e.asset_id,sourceId:e.source_id,rule:'CG-REMOTE-SUSPICIOUS',severity:'high',title:'Source reports suspicious remote activity / المصدر يبلغ عن نشاط وصول بعيد مريب',eventId:e.id});
  }
  checkHealth() {
    for (const source of this.sources().filter(s=>s.health==='lost-coverage')) {
      const key=`coverage:${source.id}:${source.last_received||source.created_at}`;
      if (!this.s.get('SELECT id FROM alerts WHERE dedup_key=?',key)) this.s.transaction(()=>{
        const finding=source.source_type==='managed-agent'?{rule:'CG-AGENT-LOST',title:'Managed agent visibility lost / فقدان رؤية Agent مُدار'}:source.source_type==='log-forwarder'?{rule:'CG-LOG-DELIVERY-FAILED',title:'Log delivery failed or stopped / فشل أو توقف إرسال السجلات'}:{rule:'CG-LOST-COVERAGE',title:'Telemetry visibility lost / فقدان رؤية مصدر الأحداث'};
        this.alert({key,sourceId:source.id,severity:'high',...finding});
        this.s.audit('health-service','source.coverage_lost',source.id,{reason:source.health,source_type:source.source_type,monitor_state:source.monitor_state},this.now());
      });
    }
  }
  list(kind,{limit=25,offset=0,q=''}={}) {
    const config={assets:['hostname','last_seen'],events:['kind','received_at'],alerts:['title','last_seen'],remote_sessions:['protocol','last_seen'],cases:['title','updated_at'],actions:['reason','requested_at'],audit:['action','seq']}[kind];
    fail(config,404,'not_found');
    const where=q?` WHERE ${config[0]} LIKE ? ESCAPE '\\'`:'';
    const args=q?[`%${q.replace(/[\\%_]/g,'\\$&')}%`]:[];
    const total=this.s.get(`SELECT COUNT(*) total FROM ${kind}${where}`,...args).total;
    const rows=this.s.all(`SELECT * FROM ${kind}${where} ORDER BY ${config[1]} DESC${kind==='audit'?'':',id'} LIMIT ? OFFSET ?`,...args,limit,offset).map(r=>this.decode(r));
    return {items:rows,total,limit,offset};
  }
  decode(row) {
    const r={...row};
    for (const k of ['addresses','protection','payload','evidence_ids','source_a','target_b','notes','alert_ids']) if (typeof r[k]==='string') r[k]=parse(r[k]);
    return r;
  }
  asset(id) {
    const asset=this.decode(this.s.require('SELECT * FROM assets WHERE id=?',[id]));
    const source=this.sources().find(s=>s.id===asset.source_id);
    const contextRow=this.s.get("SELECT id,observed_at,payload FROM events WHERE asset_id=? AND kind='asset.context' ORDER BY observed_at DESC,received_at DESC,id DESC LIMIT 1",id),context=contextRow?{event_id:contextRow.id,observed_at:contextRow.observed_at,...parse(contextRow.payload).details}:{owner:null,business_service:null,service_name:null,site:null,data_sensitivity:'unknown',maintenance_windows:[],service_criticality:null};
    const lifecycleRow=this.s.get("SELECT id,observed_at,payload FROM events WHERE asset_id=? AND kind='asset.lifecycle' ORDER BY observed_at DESC,received_at DESC,id DESC LIMIT 1",id),lifecycle=lifecycleRow?{event_id:lifecycleRow.id,observed_at:lifecycleRow.observed_at,...parse(lifecycleRow.payload).details}:{product:null,operating_system:null,vendor_support:{status:'unknown',standard_support_end:null,security_updates_end:null,extended_support:{available:false,enrolled:false,end_at:null}},plan:null};
    return {...asset,source,visibility:source.health,governance_context:context,lifecycle,protection_claim:'not-independently-verified',events:this.s.all('SELECT id,kind,observed_at,sanitized_sha256 FROM events WHERE asset_id=? ORDER BY observed_at DESC LIMIT 50',id),alerts:this.s.all('SELECT id,title,status,severity FROM alerts WHERE asset_id=? ORDER BY last_seen DESC LIMIT 30',id)};
  }
  acknowledge(actor,id) {
    const alert=this.s.require('SELECT * FROM alerts WHERE id=?',[id]);
    if (alert.status==='acknowledged') return this.decode(alert);
    this.s.transaction(()=>{this.s.run('UPDATE alerts SET status=\'acknowledged\',acknowledged_at=?,acknowledged_by=? WHERE id=?',this.now(),actor,id);this.s.audit(actor,'alert.acknowledged',id,{},this.now());});
    return this.decode(this.s.get('SELECT * FROM alerts WHERE id=?',id));
  }
  createCase(actor,input) {
    object(input,['title','alert_ids'],'case');
    const title=text(input.title,'title',200), ids=input.alert_ids;
    fail(Array.isArray(ids)&&ids.length>0&&ids.length<=50&&ids.every(id=>typeof id==='string'),400,'case_requires_alerts');
    for (const id of ids) this.s.require('SELECT id FROM alerts WHERE id=?',[id]);
    const id=randomUUID();
    this.s.transaction(()=>{this.s.run('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?)',id,safe(title),'open',actor,this.now(),this.now(),JSON.stringify([...new Set(ids)]),'[]');this.s.audit(actor,'case.created',id,{alert_count:ids.length},this.now());});
    return this.decode(this.s.get('SELECT * FROM cases WHERE id=?',id));
  }
  updateCase(actor,id,input) {
    object(input,['note','status'],'case_update');
    const current=this.s.require('SELECT * FROM cases WHERE id=?',[id]);
    const note=text(input.note,'note',4000), status=choice(input.status||current.status,['open','investigating','closed'],'case_status');
    const notes=parse(current.notes); fail(notes.length<1000,409,'case_note_limit');
    notes.push({actor,at:this.now(),text:safe(note)});
    this.s.transaction(()=>{this.s.run('UPDATE cases SET notes=?,status=?,updated_at=? WHERE id=?',JSON.stringify(notes),status,this.now(),id);this.s.audit(actor,'case.updated',id,{status},this.now());});
    return this.decode(this.s.get('SELECT * FROM cases WHERE id=?',id));
  }
  caseReport(id) {
    const investigation=this.decode(this.s.require('SELECT * FROM cases WHERE id=?',[id]));
    const alerts=investigation.alert_ids.map(alertId=>this.decode(this.s.require('SELECT * FROM alerts WHERE id=?',[alertId])));
    const evidenceIds=[...new Set(alerts.flatMap(alert=>alert.evidence_ids))];
    const events=evidenceIds.map(eventId=>this.s.get('SELECT id,source_id,external_id,asset_id,kind,observed_at,received_at,schema_version,parser_version,original_sha256,sanitized_sha256 FROM events WHERE id=?',eventId)).filter(Boolean);
    const assets=[...new Set(alerts.map(alert=>alert.asset_id).filter(Boolean))].map(assetId=>this.s.get('SELECT id,hostname,os_family,device_type,criticality,last_seen FROM assets WHERE id=?',assetId)).filter(Boolean);
    const timeline=[
      ...events.map(event=>({at:event.observed_at,type:'evidence-observed',reference:event.id,summary:event.kind})),
      ...alerts.map(alert=>({at:alert.first_seen,type:'alert-opened',reference:alert.id,summary:alert.title,severity:alert.severity})),
      ...investigation.notes.map((note,index)=>({at:note.at,type:'analyst-note',reference:`note-${index+1}`,summary:note.text,actor:note.actor})),
    ].sort((a,b)=>a.at.localeCompare(b.at)||a.type.localeCompare(b.type));
    const custody=this.s.all('SELECT seq,at,actor,action,target,previous_hash,hash FROM audit WHERE target=? OR target IN ('+alerts.map(()=>'?').join(',')+') ORDER BY seq',id,...alerts.map(a=>a.id));
    const missing=[];
    if(!events.length)missing.push('No event records are linked to the selected alerts.');
    if(alerts.some(a=>!a.asset_id))missing.push('At least one alert has no attributed asset.');
    if(alerts.some(a=>!a.evidence_ids.length))missing.push('At least one alert is based on source health or other evidence without an event record.');
    return {schema_version:'cg.case-report/1',generated_at:this.now(),method:'deterministic-local-evidence-pack; no language model',case:investigation,assets,alerts:alerts.map(({dedup_key,...alert})=>alert),events,timeline,chain_of_custody:{scope:'local append-only audit chain; no external timestamp or WORM anchor',entries:custody,verification:this.s.verifyAudit()},unknowns:missing,limitations:['This report contains local, redacted evidence references; it is not a legal attribution of a person or organization.','Source-reported observations are not independent proof of prevention, compromise, or containment.','Original evidence content is represented by hashes and source references; raw sensitive material is not embedded.']};
  }
  summary() {
    this.checkHealth();
    const sources=this.sources();
    const count=(type,state)=>sources.filter(s=>(!type||s.source_type===type)&&(!state||s.health===state||s.monitor_state===state)).length;
    return {at:this.now(),stage:'engineering-preview',assets:this.s.get('SELECT COUNT(*) n FROM assets').n,events:this.s.get('SELECT COUNT(*) n FROM events').n,open_alerts:this.s.get('SELECT COUNT(*) n FROM alerts WHERE status=\'open\'').n,critical_alerts:this.s.get('SELECT COUNT(*) n FROM alerts WHERE status=\'open\' AND severity=\'critical\'').n,open_cases:this.s.get('SELECT COUNT(*) n FROM cases WHERE status<>\'closed\'').n,sources:sources.length,receiving_sources:sources.filter(s=>s.health==='receiving').length,coverage_health:{configured:sources.length,receiving:count(null,'receiving'),visibility_gaps:sources.filter(s=>s.health==='lost-coverage').length,agents:{configured:count('managed-agent'),online:count('managed-agent','agent-online'),lost:count('managed-agent','agent-lost')},log_forwarders:{configured:count('log-forwarder'),flowing:count('log-forwarder','logs-flowing'),failed:count('log-forwarder','log-delivery-failed')}},visibility:sources.length===0?'not-configured':sources.every(s=>s.health==='receiving')?'receiving':'visibility-gap',prevention:'not-verified',outbound_ai:'disabled',production_ready:false};
  }
  securityOutcomes() {
    const count=table=>this.s.get(`SELECT COUNT(*) n FROM ${table}`).n;
    const rows=(sql,...params)=>this.s.all(sql,...params).map(row=>row.id||row.hash).filter(Boolean);
    const sources=this.sources(),audit=this.s.verifyAudit(),assets=count('assets'),events=count('events'),alerts=count('alerts'),cases=count('cases'),actions=count('actions');
    const protection=this.s.get("SELECT COUNT(*) n FROM events WHERE kind='protection.observed'").n,rollbacks=this.s.get("SELECT COUNT(*) n FROM actions WHERE status='rolled-back'").n;
    const make=(fn,evidence,gaps)=>({function:fn,status:evidence.reduce((sum,item)=>sum+item.count,0)>0?(gaps.length?'partial':'evidence-available'):'gap',evidence,gaps});
    return {framework:'NIST CSF 2.0',claim:'Evidence map for the configured CyberGuard scope; not a compliance assessment or certification.',generated_at:this.now(),outcomes:[
      make('GOVERN',[{type:'audit-chain',count:audit.checked,references:[audit.head]} ,{type:'local-roles',count:this.s.get('SELECT COUNT(*) n FROM users').n,references:[]}],[...(audit.valid?[]:['Local audit-chain verification failed.']),'No external audit anchor, SSO policy evidence or compliance certification is configured.']),
      make('IDENTIFY',[{type:'assets',count:assets,references:rows('SELECT id FROM assets ORDER BY last_seen DESC LIMIT 10')},{type:'authorized-discovery',count:this.s.get("SELECT COUNT(*) n FROM events WHERE kind='discovery.observed'").n,references:rows("SELECT id FROM events WHERE kind='discovery.observed' ORDER BY observed_at DESC LIMIT 10")}],[...(assets?[]:['No assets have been observed.']),...(sources.some(source=>source.health!=='receiving')?['At least one configured source has a visibility gap.']:[])]),
      make('PROTECT',[{type:'protection-observations',count:protection,references:rows("SELECT id FROM events WHERE kind='protection.observed' ORDER BY observed_at DESC LIMIT 10")}],['Prevention effectiveness has not been independently validated.']),
      make('DETECT',[{type:'events',count:events,references:rows('SELECT id FROM events ORDER BY received_at DESC LIMIT 10')},{type:'alerts',count:alerts,references:rows('SELECT id FROM alerts ORDER BY last_seen DESC LIMIT 10')}],[...(sources.length?[]:['No telemetry source is configured.']),...(sources.some(source=>source.health!=='receiving')?['Detection visibility is incomplete because a source is not receiving.']:[])]),
      make('RESPOND',[{type:'cases',count:cases,references:rows('SELECT id FROM cases ORDER BY updated_at DESC LIMIT 10')},{type:'actions',count:actions,references:rows('SELECT id FROM actions ORDER BY requested_at DESC LIMIT 10')}],['Device and network response connectors are not validated.']),
      make('RECOVER',[{type:'verified-rollbacks',count:rollbacks,references:rows("SELECT id FROM actions WHERE status='rolled-back' ORDER BY requested_at DESC LIMIT 10")}],['No backup restore or disaster-recovery exercise evidence is recorded.'])
    ]};
  }
  threatModels({limit=25,offset=0,q=''}={}) {
    const rows=this.s.all("SELECT id,source_id,asset_id,observed_at,received_at,payload FROM (SELECT e.*,ROW_NUMBER() OVER (PARTITION BY json_extract(payload,'$.details.environment.environment_id') ORDER BY observed_at DESC,received_at DESC,id DESC) latest FROM events e WHERE kind='governance.threat_model') WHERE latest=1 ORDER BY observed_at DESC,id");
    const items=rows.map(row=>{const model=parse(row.payload).details;return {event_id:row.id,source_id:row.source_id,anchor_asset_id:row.asset_id,observed_at:row.observed_at,received_at:row.received_at,...model,valuable_assets:model.valuable_assets.map(asset=>({...asset,central_asset_ids:this.s.all('SELECT id FROM assets WHERE external_id=? ORDER BY id',asset.asset_ref).map(item=>item.id)}))};});
    const query=q.toLowerCase(),matching=items.filter(item=>!query||`${item.environment.environment_id} ${item.environment.name} ${item.environment.scope} ${item.valuable_assets.map(asset=>`${asset.asset_ref} ${asset.name}`).join(' ')} ${item.attack_scenarios.map(scenario=>scenario.title).join(' ')}`.toLowerCase().includes(query));
    return {items:matching.slice(offset,offset+limit),total:matching.length,limit,offset,claim:'Latest versioned threat model per registered environment. Asset links resolve only to existing central device records; source-reported impact remains subject to governance review.'};
  }
  riskRegister({limit=25,offset=0,q=''}={}) {
    const rows=this.s.all("SELECT id,source_id,asset_id,observed_at,received_at,payload FROM (SELECT e.*,ROW_NUMBER() OVER (PARTITION BY json_extract(payload,'$.details.risk_id') ORDER BY observed_at DESC,received_at DESC,id DESC) latest FROM events e WHERE kind='governance.risk_record') WHERE latest=1 ORDER BY observed_at DESC,id");
    const tables={event:'events',alert:'alerts',case:'cases',action:'actions'},now=this.clock();
    const items=rows.map(row=>{const risk=parse(row.payload).details,evidence_refs=risk.evidence_refs.map(reference=>({...reference,resolved:Boolean(this.s.get(`SELECT id FROM ${tables[reference.type]} WHERE id=?`,reference.id))}));const reviewDue=risk.risk_acceptance.review_due_at?Date.parse(risk.risk_acceptance.review_due_at):null,exceptionExpiry=risk.exception.expires_at?Date.parse(risk.exception.expires_at):null;return {event_id:row.id,source_id:row.source_id,anchor_asset_id:row.asset_id,observed_at:row.observed_at,received_at:row.received_at,...risk,evidence_refs,review_state:risk.risk_acceptance.status!=='accepted'?'not-accepted':reviewDue<now?'overdue':'scheduled',exception_state:risk.exception.status==='active'&&exceptionExpiry<now?'expired':risk.exception.status};});
    const query=q.toLowerCase(),matching=items.filter(item=>!query||`${item.risk_id} ${item.title} ${item.description} ${item.category} ${item.owner.display_name} ${item.coverage.requirement_ids.join(' ')} ${item.status}`.toLowerCase().includes(query));
    return {items:matching.slice(offset,offset+limit),total:matching.length,limit,offset,claim:'Latest versioned record per risk. Coverage and evidence links are explicit; exceptions and accepted risks retain expiry or review deadlines. Source assertions remain subject to governance review.'};
  }
  compatibilityMatrix({limit=25,offset=0,q=''}={}) {
    const rows=this.s.all("SELECT e.id event_id,e.source_id,e.asset_id,e.observed_at,e.received_at,e.payload,a.external_id,a.hostname,a.os_family,a.device_type FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='asset.compatibility' AND NOT EXISTS (SELECT 1 FROM events newer WHERE newer.asset_id=e.asset_id AND newer.kind='asset.compatibility' AND (newer.observed_at>e.observed_at OR (newer.observed_at=e.observed_at AND newer.received_at>e.received_at) OR (newer.observed_at=e.observed_at AND newer.received_at=e.received_at AND newer.id>e.id))) ORDER BY e.observed_at DESC,e.id");
    const items=rows.map(row=>({event_id:row.event_id,source_id:row.source_id,observed_at:row.observed_at,received_at:row.received_at,asset:{id:row.asset_id,external_id:row.external_id,hostname:row.hostname,os_family:row.os_family,device_type:row.device_type},...parse(row.payload).details})),query=q.toLowerCase(),matching=items.filter(item=>!query||`${item.asset.external_id} ${item.asset.hostname||''} ${item.profile} ${item.support_state} ${item.agent.status} ${item.access_mode} ${item.recommendation}`.toLowerCase().includes(query));
    return {items:matching.slice(offset,offset+limit),total:matching.length,limit,offset,claim:'Latest source-reported compatibility record per central asset. Not-tested remains explicit; only authorized-lab evidence may represent a tested capability.'};
  }
  visibilityGaps({limit=25,offset=0,q=''}={}) {
    const explicit=this.s.all("SELECT id,source_id,asset_id,observed_at,received_at,payload FROM (SELECT e.*,ROW_NUMBER() OVER (PARTITION BY source_id,json_extract(payload,'$.details.entity_type'),json_extract(payload,'$.details.entity_ref') ORDER BY observed_at DESC,received_at DESC,id DESC) latest FROM events e WHERE kind='visibility.gap') WHERE latest=1").map(row=>({id:row.id,source_id:row.source_id,asset_id:row.asset_id,observed_at:row.observed_at,origin:'reported-gap',...parse(row.payload).details}));
    const automatic=this.sources().filter(source=>source.health!=='receiving').map(source=>({id:`source:${source.id}`,source_id:source.id,asset_id:null,observed_at:this.now(),origin:'source-health',entity_type:'source',entity_ref:source.name,reason:source.source_type==='managed-agent'?'no-agent':source.source_type==='network-collector'?'no-span':source.source_type==='log-forwarder'?'no-logs':'outage',last_seen:source.last_received,recommendation:source.revoked?'Review the intentional revocation and replace the source if coverage is still required.':'Restore receipt, validate the source credential and confirm end-to-end delivery.',status:source.revoked?'resolved':'open'}));
    const query=q.toLowerCase(),all=[...explicit,...automatic].filter(item=>!query||`${item.entity_type} ${item.entity_ref} ${item.reason} ${item.recommendation} ${item.status}`.toLowerCase().includes(query)).sort((a,b)=>String(b.observed_at).localeCompare(String(a.observed_at))||a.id.localeCompare(b.id));
    return {items:all.slice(offset,offset+limit),total:all.length,limit,offset,scope:'Known registered systems, networks, accounts and configured sources only; unknown entities cannot be enumerated without authorized evidence.'};
  }
  discovery({limit=25,offset=0,q=''}={}) {
    const escaped=`%${q.replace(/[\\%_]/g,'\\$&')}%`,filter=q?" AND (a.hostname LIKE ? ESCAPE '\\' OR a.external_id LIKE ? ESCAPE '\\')":'';
    const args=q?[escaped,escaped]:[];
    const base="FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='discovery.observed' AND NOT EXISTS (SELECT 1 FROM events newer WHERE newer.asset_id=e.asset_id AND newer.kind='discovery.observed' AND (newer.observed_at>e.observed_at OR (newer.observed_at=e.observed_at AND newer.received_at>e.received_at) OR (newer.observed_at=e.observed_at AND newer.received_at=e.received_at AND newer.id>e.id)))";
    const total=this.s.get(`SELECT COUNT(*) total ${base}${filter}`,...args).total;
    const rows=this.s.all(`SELECT e.id event_id,e.source_id,e.observed_at,e.received_at,e.payload,a.id asset_id,a.external_id,a.hostname,a.os_family,a.device_type,a.addresses ${base}${filter} ORDER BY e.observed_at DESC,e.id LIMIT ? OFFSET ?`,...args,limit,offset);
    const items=rows.map(row=>{
      const observation=parse(row.payload).details;
      const prior=this.s.get("SELECT payload FROM events WHERE asset_id=? AND kind='discovery.observed' AND id<>? AND observed_at<=? ORDER BY observed_at DESC,received_at DESC,id DESC LIMIT 1",row.asset_id,row.event_id,row.observed_at);
      const previous=prior?parse(prior.payload).details:null;
      const change=observation.availability==='down'?'unavailable':previous?.availability==='down'&&observation.availability==='up'?'restored':!previous?'added':digest(previous)!==digest(observation)?'changed':'unchanged';
      return {event_id:row.event_id,source_id:row.source_id,observed_at:row.observed_at,received_at:row.received_at,change,asset:{id:row.asset_id,external_id:row.external_id,hostname:row.hostname,os_family:row.os_family,device_type:row.device_type,addresses:parse(row.addresses)},observation};
    });
    return {items,total,limit,offset,scope:'Latest authorized source observation per central asset; passive evidence only; no network probe is executed by this endpoint.'};
  }
  evidenceReadiness(sources=this.sources()) {
    const assets=this.s.all('SELECT id,hostname,os_family,device_type,addresses FROM assets');
    const events=this.s.all('SELECT source_id,external_id,asset_id,schema_version,parser_version,original_sha256,sanitized_sha256 FROM events');
    if(!sources.length||!assets.length||!events.length) return null;
    const round=value=>Math.round(Math.max(0,Math.min(100,value)));
    const coverage=round(sources.filter(source=>source.health==='receiving').length/sources.length*100);
    const eventAssets=new Set(events.map(event=>event.asset_id));
    const evidence=round(assets.reduce((sum,asset)=>{
      const addresses=parse(asset.addresses);
      const identified=Boolean(asset.hostname||asset.os_family!=='unknown'||asset.device_type!=='unknown'||addresses.length);
      return sum+(eventAssets.has(asset.id)?0.5:0)+(identified?0.5:0);
    },0)/assets.length*100);
    const freshness=round(sources.reduce((sum,source)=>{
      if(source.revoked||!source.last_received)return sum;
      return sum+Math.max(0,1-source.age_seconds/source.stale_seconds);
    },0)/sources.length*100);
    const confidence=round(events.filter(event=>event.source_id&&event.external_id&&event.schema_version&&event.parser_version&&/^[a-f0-9]{64}$/.test(event.original_sha256)&&/^[a-f0-9]{64}$/.test(event.sanitized_sha256)).length/events.length*100);
    const components={coverage,evidence,freshness,confidence};
    const score=Math.round((coverage*.35+evidence*.25+freshness*.25+confidence*.15)*10);
    return {score,scale:1000,components,formula_version:'cg.evidence-readiness/1',scope:{configured_sources:sources.length,observed_assets:assets.length,evidence_events:events.length},claim:'Evidence readiness for the configured scope; not a security guarantee, protection score, or environment coverage percentage.'};
  }
  dashboard(severity='all') {
    choice(severity,['all',...severities],'severity');
    const summary=this.summary();
    const today=Date.parse(this.now().slice(0,10)+'T00:00:00.000Z');
    const days=Array.from({length:28},(_,i)=>new Date(today-(27-i)*86400000).toISOString().slice(0,10));
    const start=days[0]+'T00:00:00.000Z';
    const eventCounts=new Map(this.s.all('SELECT substr(received_at,1,10) day,COUNT(*) n FROM events WHERE received_at>=? AND received_at<=? GROUP BY day',start,this.now()).map(r=>[r.day,r.n]));
    const where=severity==='all'?'':' AND severity=?';
    const args=severity==='all'?[]:[severity];
    const alertCounts=new Map(this.s.all(`SELECT substr(first_seen,1,10) day,COUNT(*) n FROM alerts WHERE first_seen>=? AND first_seen<=?${where} GROUP BY day`,start,this.now(),...args).map(r=>[r.day,r.n]));
    const counts=Object.fromEntries(severities.map(s=>[s,0]));
    for(const row of this.s.all('SELECT severity,COUNT(*) n FROM alerts GROUP BY severity')) counts[row.severity]=row.n;
    const recent=this.s.all(`SELECT id,title,severity,status,first_seen,last_seen,rule_id FROM alerts${severity==='all'?'':' WHERE severity=?'} ORDER BY last_seen DESC,id LIMIT 5`,...args);
    const ack=this.s.get("SELECT COUNT(*) n, AVG((julianday(acknowledged_at)-julianday(first_seen))*1440.0) minutes FROM alerts WHERE acknowledged_at IS NOT NULL AND acknowledged_at>=first_seen");
    const readiness=this.evidenceReadiness();
    return {...summary,severity_filter:severity,severity_counts:counts,total_alerts:Object.values(counts).reduce((a,b)=>a+b,0),recent_alerts:recent,
      daily:days.map(day=>({day,events:eventCounts.get(day)||0,alerts:alertCounts.get(day)||0})),
      sources_detail:this.sources().map(s=>({id:s.id,name:s.name,source_type:s.source_type,health:s.health,monitor_state:s.monitor_state,last_received:s.last_received})),
      security_score:readiness?.score??null,security_score_components:readiness?.components??null,security_score_scope:readiness?.scope??null,
      security_score_formula:readiness?.formula_version??null,security_score_claim:readiness?.claim??'Not assessed: configured sources, observed assets, and evidence events are required.',
      vulnerability_scan:null,mean_detection_minutes:null,
      mean_acknowledge_minutes:ack.n?Math.max(0,Number(ack.minutes.toFixed(2))):null,acknowledged_samples:ack.n,
      metric_scope:'UTC; events by receipt, alerts by first detection; mean ACK is time from first detection to the latest acknowledgement, not MTTR or containment; evidence readiness is limited to the configured scope and is not a security guarantee'};
  }
  evidenceReport(assetId) {
    const a=this.asset(assetId);
    return {schema_version:'cg.investigation/1',generated_at:this.now(),method:'deterministic-evidence-report; no language model',asset_id:a.id,hostname:a.hostname,conclusions:[{claim:'Asset observed by configured source',evidence:a.events.map(e=>e.id)},{claim:`Telemetry: ${a.visibility}`,source_id:a.source_id},{claim:'Prevention has not been independently tested',evidence:[]}],source:a.source,protection:a.protection,alerts:a.alerts,events:a.events,limitations:['Imported source reports are not independently authenticated endpoint facts.','No attribution of a person from IP, relay or shared account.','No commands or model requests are executed.']};
  }
  action(id) {
    const action=this.s.require('SELECT * FROM actions WHERE id=?',[id]);
    const lifecycle=this.s.all("SELECT seq,at,actor,action,hash FROM audit WHERE target=? AND action LIKE 'action.%' ORDER BY seq",id);
    return {...action,
      dry_run:{result:'passed',preflight_hash:action.preflight_hash,side_effects:false,recorded_at:action.requested_at},
      impact_analysis:{scope:'CyberGuard local asset record',affected_records:1,endpoint_changes:0,network_changes:0,management_channel_impact:'none'},
      rollback_plan:{method:'restore-prior-criticality',before_value:action.before_value,guard:'asset version and current value must match the verified execution'},
      lifecycle,audit_chain:this.s.verifyAudit()};
  }
  previewAction(actor,input) {
    object(input,['type','asset_id','criticality','reason','ttl_seconds'],'action');
    choice(input.type,['asset.set-criticality'],'action_type');
    const asset=this.s.require('SELECT * FROM assets WHERE id=?',[text(input.asset_id,'asset_id',40)]);
    const after=choice(input.criticality,['standard','important','critical'],'criticality');
    fail(asset.criticality!==after,400,'no_change');
    const reason=safe(text(input.reason,'reason',1000)), ttl=integer(input.ttl_seconds||600,60,3600,'ttl_seconds');
    const id=randomUUID(), expires=new Date(this.clock()+ttl*1000).toISOString();
    this.s.transaction(()=>{this.s.run('INSERT INTO actions(id,type,asset_id,requested_by,reason,requested_at,expires_at,preflight_hash,before_value,after_value,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)',id,input.type,asset.id,actor,reason,this.now(),expires,digest({id:asset.id,version:asset.version,criticality:asset.criticality}),asset.criticality,after,'pending-approval');this.s.audit(actor,'action.previewed',id,{type:input.type,asset_id:asset.id},this.now());});
    return this.action(id);
  }
  approveAction(actor,id) {
    const a=this.s.require('SELECT * FROM actions WHERE id=?',[id]);
    fail(a.status==='pending-approval',409,'action_not_pending');
    fail(a.requested_by!==actor,403,'independent_approver_required');
    fail(a.expires_at>this.now(),409,'approval_expired');
    this.checkActionState(a);
    this.s.transaction(()=>{this.s.run('UPDATE actions SET approved_by=?,status=\'approved\' WHERE id=?',actor,id);this.s.audit(actor,'action.approved',id,{},this.now());});
    return this.action(id);
  }
  checkActionState(a) {
    const asset=this.s.require('SELECT * FROM assets WHERE id=?',[a.asset_id]);
    fail(digest({id:asset.id,version:asset.version,criticality:asset.criticality})===a.preflight_hash,409,'preflight_state_changed'); return asset;
  }
  executeAction(actor,id) {
    return this.s.transaction(()=>{
      const a=this.s.require('SELECT * FROM actions WHERE id=?',[id]);
      if (a.status==='verified') return this.action(id);
      fail(a.status==='approved'&&a.approved_by,409,'action_not_approved');
      fail(a.expires_at>this.now(),409,'approval_expired');
      const asset=this.checkActionState(a);
      this.s.run('UPDATE assets SET criticality=?,version=version+1 WHERE id=? AND version=?',a.after_value,a.asset_id,asset.version);
      this.s.audit(actor,'action.executed',id,{type:a.type},this.now());
      const updated=this.s.get('SELECT criticality,version FROM assets WHERE id=?',asset.id);
      fail(updated.criticality===a.after_value,409,'postcondition_failed');
      this.s.run('UPDATE actions SET status=\'verified\',result=?,executed_version=? WHERE id=?','Local DB postcondition verified; no device action',updated.version,id);
      this.s.audit(actor,'action.verified',id,{type:a.type},this.now());
      return this.action(id);
    });
  }
  rollbackAction(actor,id) {
    return this.s.transaction(()=>{
      const a=this.s.require('SELECT * FROM actions WHERE id=?',[id]);
      fail(a.status==='verified',409,'action_not_verified');
      const asset=this.s.require('SELECT * FROM assets WHERE id=?',[a.asset_id]);
      fail(asset.version===a.executed_version&&asset.criticality===a.after_value,409,'rollback_state_changed');
      this.s.run('UPDATE assets SET criticality=?,version=version+1 WHERE id=?',a.before_value,a.asset_id);
      this.s.audit(actor,'action.rollback.executed',id,{type:a.type},this.now());
      fail(this.s.get('SELECT criticality FROM assets WHERE id=?',a.asset_id).criticality===a.before_value,409,'rollback_not_verified');
      this.s.run('UPDATE actions SET status=\'rolled-back\',result=\'Local DB rollback verified\' WHERE id=?',id);
      this.s.audit(actor,'action.rollback.verified',id,{type:a.type},this.now());
      return this.action(id);
    });
  }
}
