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

test('identity view shows help desk reset verification approval audit and temporary-access follow-up without secret values',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/helpdesk-resets/);
  for(const marker of ['Help desk abuse controls','Identity verification','Approval','Execution / audit','Temporary access / follow-up','Approver is the operator','Temporary secret values','Executed by CyberGuard','Help-desk request evidence','CG-088']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.helpdesk_reset','verified_requester_requires_method_verifier_time_evidence','approved_reset_requires_approver_time_authorization_evidence','approver-not-independent','follow-up-overdue','secret_values_collected:false','reset_executed_by_cyberguard:false','performs no reset']) assert.ok(domain.includes(marker),marker);
});

test('threats view shows process causality tree, persistence changes, connections and masked command lines without a malware verdict',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/process-causality/);assert.match(app,/state\.view==='threats'\?await threatsView\(\)/);
  for(const marker of ['Process causality','Process tree','Services / scheduled tasks','Connections','Confidence / privacy','Personal data masked','Malicious verdict','Parent not observed','Process-causality evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['endpoint.process_causality','causality_record_references_unknown_process','causality_record_outside_window','[EMAIL]','[NATIONAL-ID]','[PHONE]','raw_personal_data_stored:false','malicious_verdict:false','not a malware verdict']) assert.ok(domain.includes(marker),marker);
});

test('threats view shows defense tamper classification between authorized change, fault and suspected deliberate tampering',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/defense-tamper/);
  for(const marker of ['Defense tamper detection','Host / control','Actor / method','Classification','Recovery / evidence','Suspected deliberate tampering','Likely fault','Authorized change','Response by CyberGuard','Tamper evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['endpoint.defense_tamper','tamper_action_not_valid_for_control','time_change_requires_skew','tamper_recovery_requires_evidence_after_change','suspected-deliberate','likely-fault','response_executed_by_cyberguard:false','it is not attribution']) assert.ok(domain.includes(marker),marker);
});

test('threats view shows anti-ransomware posture with CFA/ASR availability, file-activity indicators, backup integrity and recovery store',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8');assert.match(app,/\/api\/ransomware-posture/);
  for(const marker of ['Anti-ransomware posture','CFA / ASR','File activity','Backup integrity','Recovery store','Indicators / gaps','Not available on platform','Ransomware confirmed','Ransomware-posture evidence']) assert.ok(app.includes(marker),marker);
  for(const marker of ['endpoint.ransomware_posture','backup_verification_requires_time_and_evidence','modification-spike','shadow-copies-deleted','recovery-store-not-isolated','ransomware_confirmed:false','not a ransomware verdict']) assert.ok(domain.includes(marker),marker);
});

test('discover view shows the sequential discovery run with ordered stages, merged devices, neighbour links and a read-only local exporter',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),exporter=fs.readFileSync(new URL('../scripts/Export-LocalDiscovery.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/discovery-sequences/);
  for(const marker of ['Sequential discovery','Discovery stages in order','Merged devices','Neighbour links','Coverage / evidence','Active scan','Discovery evidence','CG-006']) assert.ok(app.includes(marker),marker);
  for(const marker of ['discovery.sequence','discovery_stages_out_of_sequence','discovery_sequence_requires_every_method','discovery_finding_outside_scope','credentialed_discovery_stage_requires_credential_reference','active_scan_performed:false','No active scan is performed']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['Get-NetNeighbor','Get-DnsClientCache','Win32_NetworkAdapterConfiguration','discovery.sequence','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Test-Connection','Test-NetConnection','Set-','New-NetFirewall','Remove-','ping ']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('data sources view shows the distributed 20,000-device collector plan and the measured single-node benchmark',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),bench=fs.readFileSync(new URL('../scripts/scale-benchmark.js',import.meta.url),'utf8');assert.match(app,/\/api\/collector-capacity/);
  for(const marker of ['Distributed scale to 20,000 devices','Usable capacity','Headroom','Collector / site','Role / upstream','Capacity / utilization','Single-node benchmark','CG-009']) assert.ok(app.includes(marker),marker);
  for(const marker of ['scale.collector_capacity','capacity-below-target','site-single-point-of-failure','non_central_collector_requires_upstream','never a single PC for every device']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['20000','devices_per_second','within_budget','Synthetic documentation-range data only']) assert.ok(bench.includes(marker),marker);
});

test('data sources view shows optional managed-device agents and both agents stay read only',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),win=fs.readFileSync(new URL('../scripts/agent/CyberGuard-Agent.ps1',import.meta.url),'utf8'),lnx=fs.readFileSync(new URL('../scripts/agent/cyberguard-agent.sh',import.meta.url),'utf8');assert.match(app,/\/api\/agents/);
  for(const marker of ['Optional managed-device agents','Log channels','Services / processes','Protection status','State / gaps','Command lines','Agent evidence','CG-010']) assert.ok(app.includes(marker),marker);
  for(const marker of ['agent.inventory_report','agent_enrollment_must_be_optional','collected_agent_channel_requires_event_count','signatures-older-than-7-days','command_lines_collected:false','Agents change nothing']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['Get-WinEvent','Sysmon','Win32_Service','Get-MpComputerStatus','No upload performed']) assert.ok(win.includes(marker),marker);
  for(const marker of ['auditd','journalctl','syslog','systemctl list-units','ps -eo pid=,comm=','No upload performed']) assert.ok(lnx.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Set-','Remove-','Stop-','Start-Service','Restart-']) assert.ok(!win.includes(forbidden),forbidden);
  for(const forbidden of ['curl ','wget ','systemctl stop','systemctl start','systemctl enable','systemctl disable','rm -']) assert.ok(!lnx.includes(forbidden),forbidden);
});

test('policies view shows sensitive change monitoring and the snapshot monitor stays read only',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),monitor=fs.readFileSync(new URL('../scripts/Watch-SensitiveChanges.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/sensitive-changes/);
  for(const marker of ['Sensitive change monitoring','Host / category','Before → after','Detection','Risk / review','Change evidence','CG-011']) assert.ok(app.includes(marker),marker);
  for(const marker of ['change.sensitive','added_change_requires_only_after_state','modified_change_requires_different_states','persistence-location','reverted_by_cyberguard:false','CyberGuard reverts nothing']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['CurrentVersion\\Run','Win32_Service','Uninstall','Get-NetFirewallRule','Get-LocalUser','Policies','Get-FileHash','change.sensitive','No upload performed']) assert.ok(monitor.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Set-','Remove-','Stop-','Start-Service','New-NetFirewallRule','Disable-','Enable-']) assert.ok(!monitor.includes(forbidden),forbidden);
});

test('threats view lists the versioned malware, ransomware and tamper detection rules with alert counts',()=>{
  const app=read('app.js'),rules=fs.readFileSync(new URL('../lib/detection-rules.js',import.meta.url),'utf8');assert.match(app,/\/api\/detection-rules/);
  for(const marker of ['Malware, ransomware and tamper detection rules','Rule / version','What it detects','Evidence source','CG-012']) assert.ok(app.includes(marker),marker);
  for(const marker of ['CG-MAL-LOLBIN-001','CG-MAL-PERSIST-002','CG-MAL-USERPATH-003','CG-TAMPER-004','CG-RAN-005','CG-AGENT-NOAV-006','vssadmin','encodedcommand','they never act']) assert.ok(rules.includes(marker),marker);
});

test('vulnerabilities view shows software and update inventory linked to imported catalogs by installed version, and the exporter is read only',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),exporter=fs.readFileSync(new URL('../scripts/Export-SoftwareInventory.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/software-vulnerabilities/);assert.match(app,/state\.view==='vulnerabilities'\?await vulnerabilitiesView\(\)/);
  for(const marker of ['Software, update and vulnerability inventory','Device / OS','Software / updates','Version-linked vulnerabilities','Fixed by update','Version unknown','Inventory evidence','CG-013']) assert.ok(app.includes(marker),marker);
  for(const marker of ['software.inventory','vulnerability.catalog','vulnerability_requires_affected_range_or_fixing_update','fixed-by-update','version-unknown','nothing is scanned or exploited']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['Uninstall','Win32_QuickFixEngineering','Win32_OperatingSystem','software.inventory','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Set-','Remove-','Install-','Uninstall-','Start-Process']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('identity view shows directory integration with group and privilege change monitoring, and the snapshot exporter is read only',()=>{
  const app=read('app.js'),domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),exporter=fs.readFileSync(new URL('../scripts/Export-IdentitySnapshot.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/identity-directories/);
  for(const marker of ['Identity directory integration and group/privilege change monitoring','Directory / connector','Privileged group members','Changes since previous snapshot','Microsoft Entra ID','AWS IAM','Identity snapshot evidence','CG-014']) assert.ok(app.includes(marker),marker);
  for(const marker of ['identity.directory_snapshot','identity_connector_must_be_read_only','remote_identity_connector_requires_credential_reference','CG-IDENT-PRIVADD-007','CG-IDENT-PRIVGRANT-008','write_access_used:false']) assert.ok(domain.includes(marker),marker);
  for(const marker of ['Get-LocalUser','Get-LocalGroupMember','S-1-5-32-544','adsisearcher','identity.directory_snapshot','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Set-','Remove-','Add-LocalGroupMember','New-LocalUser','Disable-','Enable-']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('identity view shows identity threat findings and the account posture exporter is read only',()=>{
  const app=read('app.js'),lib=fs.readFileSync(new URL('../lib/identity-threats.js',import.meta.url),'utf8'),exporter=fs.readFileSync(new URL('../scripts/Export-AccountPosture.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/identity-threats/);
  for(const marker of ['Identity threat detection','Password spraying','Impossible travel','Risky OAuth consent','Unauthorized IdP change','Account without MFA','Stale account','CG-015']) assert.ok(app.includes(marker),marker);
  for(const marker of ['password-spraying','brute-force-then-success','impossible-travel','risky-oauth-consent','idp-change-unauthorized','mfa-not-registered','stale-account','CG-IDENT-SPRAY-009']) assert.ok(lib.includes(marker),marker);
  for(const marker of ['Get-LocalUser','LastLogon','PasswordLastSet','4625','identity.account_posture','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Invoke-RestMethod','Set-','Remove-','Disable-','Enable-']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('no evidence schema field name is one that the secret redactor would erase',()=>{
  const domain=fs.readFileSync(new URL('../lib/domain.js',import.meta.url),'utf8'),keys=new Set([...domain.matchAll(/object\([a-zA-Z.]*,\[([^\]]*)\]/g)].flatMap(m=>[...m[1].matchAll(/'([a-z_]+)'/g)].map(k=>k[1])));
  const erased=[...keys].filter(k=>/password|passwd|secret|token|api.?key|authorization|cookie|community|private.?key/i.test(k)&&k!=='authorization_ref');
  assert.ok(keys.size>100,'schema keys found');assert.deepEqual(erased,[]);
});

test('settings view offers just-in-time privilege requests with approval, revocation and visible expiry',()=>{
  const app=read('app.js'),auth=fs.readFileSync(new URL('../lib/auth.js',import.meta.url),'utf8'),store=fs.readFileSync(new URL('../lib/store.js',import.meta.url),'utf8');assert.match(app,/\/api\/jit/);
  for(const marker of ['Just-in-time privileges','Request temporary privilege','Requested role','Action cap','Approve','Deny','Revoke','temporary until','CG-017']) assert.ok(app.includes(marker),marker);
  for(const marker of ['jit_self_approval_forbidden','jit_approver_must_be_standing_admin','jit_role_must_exceed_current_role','jit.requested','jit.used','exhausted','expired']) assert.ok(auth.includes(marker),marker);
  assert.match(store,/CREATE TABLE jit_grants/);assert.ok(app.includes("nav.filter(n=>state.user.role==='admin'||n[0]!=='audit')"),'settings reachable by every role for JIT requests');
});

test('events view shows normalised logs from every supported source family',()=>{
  const app=read('app.js'),norm=fs.readFileSync(new URL('../lib/log-normalizer.js',import.meta.url),'utf8'),conv=fs.readFileSync(new URL('../scripts/logs-to-telemetry.js',import.meta.url),'utf8');assert.match(app,/\/api\/normalized-logs/);assert.match(app,/state\.view==='events'\?await eventsView\(\)/);
  for(const marker of ['Normalised logs','Time / category','Source → destination','NetFlow/IPFIX','IDS/IPS','CG-018']) assert.ok(app.includes(marker),marker);
  for(const marker of ['syslog','journal','nfdump-csv','goflow-json','suricata-eve','bind-query','isc-dhcpd','openvpn','iptables','windows-firewall','pfsense-filterlog']) assert.ok(norm.includes(marker),marker);
  assert.match(conv,/No upload performed/);
});

test('network map view shows connection zones, Internet exposure, unusual DNS and lateral movement, and the connection exporter is read only',()=>{
  const app=read('app.js'),exporter=fs.readFileSync(new URL('../scripts/Export-ConnectionEvidence.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/network-analysis/);
  for(const marker of ['Connections, exposure, DNS and lateral movement','Lateral-movement indicators','Internet exposure','Unusual DNS','Top connections','CG-019']) assert.ok(app.includes(marker),marker);
  for(const marker of ['Get-NetTCPConnection','Get-DnsClientCache','goflow-json','suricata-eve','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Invoke-WebRequest','Test-Connection','Test-NetConnection','Set-','Remove-','Stop-']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('every browser script parses as valid JavaScript',async()=>{
  const {execFileSync}=await import('node:child_process'),{fileURLToPath}=await import('node:url');
  for(const file of fs.readdirSync(new URL('../public/',import.meta.url)).filter(name=>name.endsWith('.js')))assert.doesNotThrow(()=>execFileSync(process.execPath,['--check',fileURLToPath(new URL('../public/'+file,import.meta.url))],{stdio:'pipe'}),file);
});

test('policies view shows the firewall rule analyzer and the Windows rule exporter is read only',()=>{
  const app=read('app.js'),exporter=fs.readFileSync(new URL('../scripts/Export-FirewallRules.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/firewall-rules/);
  for(const marker of ['Firewall rule analyzer','Shadowed by an earlier rule','Allow overridden by block','Any-any allow','Admin port open to any','Expired exception','Change since previous ruleset','unreadable without elevation','CG-020']) assert.ok(app.includes(marker),marker);
  for(const marker of ['Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','deny-overrides','filters_readable','No upload performed']) assert.ok(exporter.includes(marker),marker);
  for(const forbidden of ['Set-NetFirewall','New-NetFirewall','Remove-NetFirewall','Enable-NetFirewall','Disable-NetFirewall','Invoke-WebRequest']) assert.ok(!exporter.includes(forbidden),forbidden);
});

test('network map view shows device versions, DNS, VPN and management monitoring and both collectors keep secrets out',()=>{
  const app=read('app.js'),conv=fs.readFileSync(new URL('../scripts/convert-cisco-config.js',import.meta.url),'utf8'),host=fs.readFileSync(new URL('../scripts/Export-HostNetworkConfig.ps1',import.meta.url),'utf8');assert.match(app,/\/api\/device-configs/);
  for(const marker of ['Network device versions, DNS, VPN and management','Insecure management protocol','Management exposed','Vulnerable firmware','DNS changed','Firmware downgraded','CG-021']) assert.ok(app.includes(marker),marker);
  assert.match(conv,/Secrets were not copied/);for(const marker of ['Get-DnsClientServerAddress','Get-VpnConnection','fDenyTSConnections','WinRM','network.device_config','No upload performed']) assert.ok(host.includes(marker),marker);
  for(const forbidden of ['Set-','Remove-','Enable-','Disable-','Invoke-WebRequest']) assert.ok(!host.includes(forbidden),forbidden);
});

test('data sources view shows security control integrations for DNS security, WAF, IDS/IPS, NAC, NDR and ZTNA',()=>{
  const app=read('app.js');assert.match(app,/\/api\/security-integrations/);
  for(const marker of ['Security control integrations by environment','DNS security','Receiving, not declared','Not configured','Actually received','CG-023']) assert.ok(app.includes(marker),marker);
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
