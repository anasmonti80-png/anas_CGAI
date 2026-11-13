import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read=name=>fs.readFileSync(new URL(`../public/${name}`,import.meta.url),'utf8');

test('SOC shell exposes every required navigation destination as an operable view',()=>{
  const app=read('app.js');
  const required=['Overview','Discover','Assets','Network Map','Threats','Incidents','Vulnerabilities','Identity','Cloud','Policies','Response','AI Analyst','Reports','Settings'];
  let cursor=-1;
  for(const label of required){const next=app.indexOf(`'${label}'`,cursor+1);assert.ok(next>cursor,`${label} is present in the required order`);cursor=next;}
  for(const id of ['network-map','vulnerabilities','identity','cloud','policies','ai-analyst','reports']) assert.ok(app.includes(`${id}:`)||app.includes(`'${id}':`),`${id} has a rendered capability view`);
  assert.match(app,/No full acceptance evidence/);
});

test('bilingual RTL and responsive contracts cover desktop, tablet and mobile layouts',()=>{
  const app=read('app.js'),styles=read('styles.css'),soc=read('soc.css'),html=read('index.html');
  assert.match(app,/document\.documentElement\.lang=state\.lang/);
  assert.match(app,/document\.documentElement\.dir=state\.lang==='ar'\?'rtl':'ltr'/);
  assert.match(styles,/@media\(max-width:1100px\)/);
  assert.match(styles,/@media\(max-width:760px\)/);
  assert.match(soc,/@media\(max-width:390px\)/);
  assert.match(html,/styles\.css/);assert.match(html,/soc\.css/);
});

test('security posture UI keeps unknown, not configured and unverified evidence explicit',()=>{
  const app=read('app.js'),dashboard=read('dashboard.js');
  for(const marker of ['غير معروف','Unknown','لم تُضبط المصادر','Not configured','المنع الأمني غير متحقق','Prevention not verified']) assert.ok(app.includes(marker)||dashboard.includes(marker),marker);
  assert.match(app,/Missing data is never converted into a safe result/);
  assert.match(dashboard,/Insufficient evidence for assessment/);
  assert.match(dashboard,/not a security guarantee or an environment coverage percentage/);
});

test('discovery view exposes authorization, evidence boundaries and central asset observations',()=>{
  const app=read('app.js');
  assert.match(app,/\/api\/discovery/);
  assert.match(app,/Public discovery addresses are rejected/);
  assert.match(app,/this path performs no network probe/);
  assert.match(app,/authorization_ref:'SYNTHETIC-AUTHORIZATION-REFERENCE'/);
  for(const field of ['networks','routes','vlans','interfaces','services']) assert.ok(app.includes(field),field);
});

test('settings exposes all operating modes and the PC visibility boundary',()=>{
  const app=read('app.js'),server=fs.readFileSync(new URL('../server.js',import.meta.url),'utf8');
  assert.match(app,/\/api\/modes/);
  for(const mode of ['PC Local','Enterprise Collectors','Authorized Defense Validation Lab']) assert.ok(app.includes(mode),mode);
  for(const marker of ['behind a switch','SPAN/TAP observations','flow logs','managed agents']) assert.ok(server.includes(marker),marker);
});

test('action review exposes dry run, impact, approval lifecycle, verification, audit and rollback evidence',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');
  for(const marker of ['Dry-run result','Affected records','Rollback plan','Action lifecycle and audit','Local audit-chain integrity']) assert.ok(app.includes(marker),marker);
  for(const stage of ['action.previewed','action.approved','action.executed','action.verified','action.rollback.executed','action.rollback.verified']) assert.ok(domain.includes(stage),stage);
});

test('source health UI distinguishes managed agents, log forwarders and delivery failures',()=>{
  const app=read('app.js');
  for(const marker of ['Managed Agent','Log Forwarder','source_type','monitor_state']) assert.ok(app.includes(marker),marker);
});

test('remote access UI distinguishes application presence, connection phase and evidence assessment',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');
  for(const marker of ['Application presence','Observed phase','Assessment']) assert.ok(app.includes(marker),marker);
  for(const marker of ['remote.application_present','authorized_remote_requires_reference','suspicious_remote_requires_rationale','CG-REMOTE-SUSPICIOUS']) assert.ok(domain.includes(marker),marker);
});

test('policies view maps all six NIST CSF 2.0 functions to evidence and coverage gaps',()=>{
  const app=read('app.js');assert.match(app,/\/api\/security-outcomes/);
  for(const marker of ['GOVERN','IDENTIFY','PROTECT','DETECT','RESPOND','RECOVER','Coverage gaps']) assert.ok(app.includes(marker)||fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8').includes(marker),marker);
});

test('policies view exposes a versioned threat model for every registered environment',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/threat-models/);
  for(const marker of ['Threat models by environment','Valuable assets','Trust boundaries','Attack scenarios','Service outage impact','Data disclosure impact','Threat-model evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['governance.threat_model','unknown_scenario_asset_ref','Latest versioned threat model per registered environment']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes the institutional risk register and review deadlines',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/risk-register/);
  for(const marker of ['Versioned institutional risk register','Risk / owner','Coverage','Evidence','Remediation','Exception','Risk acceptance / review','Review due','Risk-record evidence','Active exception','Risk accepted','Review scheduled']) assert.ok(app.includes(marker),marker);
  for(const marker of ['governance.risk_record','accepted_risk_requires_review','invalid_risk_review_window','Latest versioned record per risk']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes a legacy compatibility matrix without converting not-tested into support',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/compatibility-matrix/);
  for(const marker of ['Legacy compatibility matrix','Agent availability / access','Read-only support / network isolation','Tested capabilities / evidence basis','Performance / licensing constraints','Compatibility evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['windows-server-2008-r2','windows-server-2012-r2','unsupported-linux','legacy-network-device','not_tested_cannot_claim_capability']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes evidence-backed legacy compensating controls through migration',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/compensating-controls/);
  for(const marker of ['Legacy compensating controls','Network segmentation','Jump host / MFA','Internet access','Backup / restore','Monitoring','Migration','Controls evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['asset.compensating_controls','enforced_segmentation_requires_boundary','enforced_jump_host_requires_host','enforced_mfa_requires_method','passed_restore_test_requires_evidence','migration_plan_requires_owner_target_due']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes backup copy separation, immutability, change monitoring and permission review',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/backup-security/);
  for(const marker of ['Backup security','Copies / separation','Immutability','Modification / deletion monitoring','Backup permissions','Backup-security evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['resilience.backup_security','backup_security_requires_multiple_copies','unsupported_immutability_must_be_not_applicable','monitored_backup_changes_require_signal_and_evidence','current_backup_permission_review_requires_evidence']) assert.ok(domain.includes(marker),marker);
});

test('reports view keeps backup presence separate from restore readiness and measured RPO or RTO',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/restore-readiness/);
  for(const marker of ['Restore readiness','Backup presence / readiness','Target / measured RPO','Target / measured RTO','Backup integrity','Periodic restore test','Restore-readiness evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['resilience.restore_readiness','passed_restore_test_requires_measurements_and_evidence','verified_backup_integrity_requires_evidence','recoverability_state']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes ordered incident recovery and blocks reconnection before threat clearance',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/incident-recovery/);
  for(const marker of ['Incident recovery workflows','Containment','Identity / configuration / device recovery','Threat clearance','Reconnection','Recovery-workflow evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['resilience.incident_recovery','recovery_requires_completed_containment','threat_clearance_requires_recovered_identity_configuration_and_devices','threat_clearance_requires_zero_findings','reconnection_requires_completed_threat_clearance','completed_reconnection_requires_approval']) assert.ok(domain.includes(marker),marker);
});

test('reports view exposes evidence-gated network and SOC resilience controls with an expiring automatic policy fail-safe',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/resilience-controls/);
  for(const marker of ['Resilience controls','Network configuration backups','Out-of-band management','Alternate management connector','SOC engine outage playbook','Temporary-policy fail-safe','Resilience-control evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['resilience.controls','current_network_configuration_backup_requires_separated_evidence','pathControl','alternate_management_connector_ready_requires_test_evidence','ready_soc_engine_outage_playbook_requires_exercise_evidence','armed_temporary_policy_fail_safe_requires_automatic_expiry_evidence','fail_safe_active','resilience_state']) assert.ok(domain.includes(marker),marker);
});

test('identity view exposes AD and Entra privilege, change, service-account, trust and sign-in policy audit evidence',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/directory-audits/);
  for(const marker of ['AD / Entra audit','Tier 0 / control plane','Domain Admin changes','Service accounts','Trust relationships','Sign-in policies','Directory-audit evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['directoryLabel','Member added','Bidirectional','Conditional','Unreviewed']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.directory_audit','reviewed_tier0_control_plane_requires_evidence','tier0_principal_status_requires_evidence','service_account_posture_requires_evidence','known_trust_relationship_requires_review_evidence','known_sign_in_policy_requires_evidence','unapproved_domain_admin_changes','audit_state']) assert.ok(domain.includes(marker),marker);
});

test('identity view exposes per-device Windows LAPS policy, rotation failures and secret-view audit metadata without secret values',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/laps-posture/);
  for(const marker of ['Windows LAPS posture','Password-rotation policy','Local administrator','Rotation status','Secret-view audit','Secret values','Not collected','LAPS-posture evidence','CG-083','configured:[','managed:[','enabled:[','failed:[']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.laps_posture','configured_laps_policy_requires_rotation_and_evidence','failed_laps_rotation_requires_failure_evidence','enabled_laps_access_audit_requires_review_evidence','secret_values_collected:false','does not retrieve a LAPS secret']) assert.ok(domain.includes(marker),marker);
});

test('identity view exposes AD CS services and issuance, Kerberos delegation, legacy NTLM and access-decided authentication changes',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/adcs-kerberos-posture/);
  for(const marker of ['AD CS and Kerberos posture','AD CS services','Templates / issuance','Kerberos delegation','Legacy NTLM','Authentication changes','Sensitive material / evidence','Not collected','CG-084']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.adcs_kerberos_posture','deployed_adcs_requires_service_template_evidence','known_adcs_service_requires_evidence','allowed_authentication_change_requires_authorization','delegation_gaps','ntlm_gaps','credential_material_collected:false','No private keys']) assert.ok(domain.includes(marker),marker);
});

test('identity view exposes JIT and PIM, PAW posture, temporary administrative sessions and high-sensitivity review evidence',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/privileged-access/);
  for(const marker of ['Privileged Access Management','JIT / PIM','PAW device','Administrative session','Review / authorization','Not executed','PAM evidence','CG-085']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.privileged_access','approved_privileged_activation_requires_bounded_reviewed_mfa_evidence','known_paw_posture_requires_device_evidence','approved_privileged_review_requires_authorization_evidence','session_controlled','privilege_grant_executed:false','does not grant privilege']) assert.ok(domain.includes(marker),marker);
});

test('identity view inventories SaaS OAuth applications and service identities with owners, credential rotation, permissions and activities',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/saas-service-inventory/);
  for(const marker of ['SaaS, OAuth and service identity inventory','Application / owner','Service identity','Credentials / rotation','Permissions','Observed activities','Sensitive values / evidence','Identity-inventory evidence','CG-086']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.saas_service_inventory','current_service_credential_requires_rotation_dates','admin_service_permission_requires_review_authorization','credential_gaps','permission_gaps','credential_values_collected:false','Credential values are rejected']) assert.ok(domain.includes(marker),marker);
});

test('identity view correlates sign-in MFA token privilege file resource and network evidence without confirming an attack',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/identity-attack-correlations/);
  for(const marker of ['Identity attack correlation','Sign-in / MFA','Tokens / privilege','Files / resources','Movement / sequence','Attack confirmed','Token values','Identity-correlation evidence','CG-087']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.attack_correlation','correlation_requires_identity_and_downstream_signal','missing_signal_types','sequence_valid','unapproved_sensitive_changes','token_values_collected:false','attack_confirmed:false','does not confirm an attack']) assert.ok(domain.includes(marker),marker);
});

test('network map view renders a bounded visibility-gap registry without guessed topology',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/visibility-gaps/);
  for(const marker of ['Visibility reason','Last seen','Recommendation','no guessed network links']) assert.ok(app.includes(marker),marker);
  for(const marker of ['no-agent','no-span','no-logs','no-authorization','outage']) assert.ok(domain.includes(marker),marker);
});

test('asset detail renders ownership, business context, site, sensitivity, maintenance and criticality evidence',()=>{
  const app=read('app.js');
  for(const marker of ['Owner','Business / operational service','Site','Data sensitivity','Maintenance windows','Service criticality','Context evidence']) assert.ok(app.includes(marker),marker);
});

test('asset detail renders lifecycle versions, support dates, extended support and the owned upgrade or replacement plan',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');
  for(const marker of ['Product / version','OS lifecycle version','Vendor support status','Standard support end','Security updates end','Extended support','Upgrade / replacement plan','Lifecycle evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['asset.lifecycle','extended_support_enrollment_requires_availability','lifecycle_plan_action']) assert.ok(domain.includes(marker),marker);
});
