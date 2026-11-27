import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { digest, AppError } from './common.js';

const migrations = [String.raw`
CREATE TABLE users(id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')), created_at TEXT NOT NULL);
CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, token_hash TEXT UNIQUE, created_at TEXT NOT NULL, last_received TEXT, stale_seconds INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE assets(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), external_id TEXT NOT NULL, hostname TEXT, os_family TEXT NOT NULL, device_type TEXT NOT NULL, addresses TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, received_at TEXT NOT NULL, criticality TEXT NOT NULL DEFAULT 'standard', version INTEGER NOT NULL DEFAULT 1, protection TEXT NOT NULL, UNIQUE(source_id,external_id));
CREATE INDEX assets_hostname ON assets(hostname);
CREATE TABLE events(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), external_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id), kind TEXT NOT NULL, observed_at TEXT NOT NULL, received_at TEXT NOT NULL, schema_version TEXT NOT NULL, parser_version TEXT NOT NULL, original_sha256 TEXT NOT NULL, sanitized_sha256 TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(source_id,external_id));
CREATE INDEX events_asset_time ON events(asset_id,observed_at DESC);
CREATE INDEX events_source_time ON events(source_id,received_at DESC);
CREATE TABLE alerts(id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, asset_id TEXT REFERENCES assets(id), source_id TEXT REFERENCES sources(id), rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', occurrences INTEGER NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, evidence_ids TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT REFERENCES users(id));
CREATE INDEX alerts_status ON alerts(status,last_seen DESC);
CREATE TABLE remote_sessions(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), asset_id TEXT NOT NULL REFERENCES assets(id), session_key TEXT NOT NULL, protocol TEXT NOT NULL, phase TEXT NOT NULL, source_a TEXT NOT NULL, target_b TEXT NOT NULL, relay INTEGER NOT NULL, confidence TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, evidence_ids TEXT NOT NULL, UNIQUE(source_id,asset_id,session_key));
CREATE TABLE cases(id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, alert_ids TEXT NOT NULL, notes TEXT NOT NULL);
CREATE TABLE actions(id TEXT PRIMARY KEY, type TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id), requested_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT REFERENCES users(id), reason TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, preflight_hash TEXT NOT NULL, before_value TEXT NOT NULL, after_value TEXT NOT NULL, status TEXT NOT NULL, result TEXT, executed_version INTEGER);
CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, details TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit_append_only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit_append_only'); END;
`, String.raw`
CREATE TABLE jit_grants(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), base_role TEXT NOT NULL, requested_role TEXT NOT NULL CHECK(requested_role IN ('admin','analyst')), scope TEXT NOT NULL, reason TEXT NOT NULL, duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 5 AND 480), max_actions INTEGER NOT NULL CHECK(max_actions BETWEEN 1 AND 500), used_actions INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','revoked')), requested_at TEXT NOT NULL, decided_by TEXT REFERENCES users(id), decided_at TEXT, decision_note TEXT, starts_at TEXT, expires_at TEXT, revoked_by TEXT REFERENCES users(id), revoked_at TEXT);
CREATE INDEX jit_grants_user ON jit_grants(user_id,status);
`, String.raw`
CREATE TABLE response_jobs(action_id TEXT PRIMARY KEY REFERENCES actions(id), source_id TEXT NOT NULL REFERENCES sources(id), connector_id TEXT NOT NULL, request_json TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('execute','rollback')), status TEXT NOT NULL CHECK(status IN ('pending-approval','queued','succeeded','failed')), queued_at TEXT NOT NULL, completed_at TEXT, completion_json TEXT);
CREATE INDEX response_jobs_source_status ON response_jobs(source_id,status,queued_at);
`, String.raw`
CREATE TABLE action_safety_approvals(action_id TEXT PRIMARY KEY REFERENCES actions(id), approved_by TEXT NOT NULL REFERENCES users(id), approved_at TEXT NOT NULL, recovery_plan_hash TEXT NOT NULL);
`, String.raw`
CREATE TABLE temporary_permits(id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), user_ref TEXT NOT NULL, source_ref TEXT NOT NULL, destination_ref TEXT NOT NULL, protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')), port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535), duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 1 AND 1440), reason TEXT NOT NULL, owner_ref TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT REFERENCES users(id), requested_at TEXT NOT NULL, approved_at TEXT, expires_at TEXT, status TEXT NOT NULL CHECK(status IN ('pending','active','revoked','expired')), revoked_by TEXT REFERENCES users(id), revoked_at TEXT, revocation_evidence_ref TEXT);
CREATE INDEX temporary_permits_status_expiry ON temporary_permits(status,expires_at);
`, String.raw`
ALTER TABLE sessions ADD COLUMN mfa_at INTEGER;
CREATE TABLE user_mfa(user_id TEXT PRIMARY KEY REFERENCES users(id), seed_cipher TEXT NOT NULL, enrolled_at TEXT NOT NULL, enabled_at TEXT);
CREATE TABLE mfa_assertions(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), session_hash TEXT NOT NULL, method TEXT NOT NULL CHECK(method IN ('totp')), verified_at TEXT NOT NULL, expires_at TEXT NOT NULL, evidence_hash TEXT NOT NULL);
CREATE INDEX mfa_assertions_user_expiry ON mfa_assertions(user_id,expires_at);
CREATE TABLE break_glass_grants(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), base_role TEXT NOT NULL, scope TEXT NOT NULL, reason TEXT NOT NULL, duration_minutes INTEGER NOT NULL CHECK(duration_minutes BETWEEN 5 AND 60), max_actions INTEGER NOT NULL CHECK(max_actions BETWEEN 1 AND 5), used_actions INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','revoked')), requested_at TEXT NOT NULL, approved_by TEXT REFERENCES users(id), approved_at TEXT, expires_at TEXT, revoked_by TEXT REFERENCES users(id), revoked_at TEXT);
CREATE INDEX break_glass_user_status ON break_glass_grants(user_id,status);
`, String.raw`
CREATE TABLE incident_playbook_runs(id TEXT PRIMARY KEY, playbook_id TEXT NOT NULL, playbook_version INTEGER NOT NULL, alert_id TEXT NOT NULL REFERENCES alerts(id), requested_by TEXT NOT NULL REFERENCES users(id), reason TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','executed')), approved_by TEXT REFERENCES users(id), approved_at TEXT, executed_by TEXT REFERENCES users(id), executed_at TEXT, case_id TEXT REFERENCES cases(id), evidence_snapshot TEXT NOT NULL);
CREATE INDEX incident_playbook_runs_status ON incident_playbook_runs(status,requested_at DESC);
`, String.raw`
CREATE TABLE ai_cloud_consents(id TEXT PRIMARY KEY, provider TEXT NOT NULL, purpose TEXT NOT NULL, customer_approval_ref TEXT NOT NULL, approved_by TEXT NOT NULL REFERENCES users(id), approved_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')));
CREATE INDEX ai_cloud_consents_status_expiry ON ai_cloud_consents(status,expires_at);
`, String.raw`
CREATE TABLE ai_action_proposals(id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(id), asset_id TEXT NOT NULL REFERENCES assets(id), origin TEXT NOT NULL, action_type TEXT NOT NULL, target_json TEXT NOT NULL, rationale TEXT NOT NULL, rationale_ar TEXT, proposed_for TEXT NOT NULL REFERENCES users(id), proposed_at TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT REFERENCES users(id), decided_at TEXT, action_id TEXT REFERENCES actions(id));
CREATE INDEX ai_action_proposals_alert_status ON ai_action_proposals(alert_id,status);
`, String.raw`
CREATE TABLE sso_config(id INTEGER PRIMARY KEY CHECK(id=1), issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_secret_env TEXT, authorization_endpoint TEXT NOT NULL, token_endpoint TEXT NOT NULL, jwks_uri TEXT NOT NULL, tenant TEXT, tenant_claim TEXT NOT NULL, groups_claim TEXT NOT NULL, role_map TEXT NOT NULL, mfa_amr TEXT NOT NULL, mfa_acr TEXT NOT NULL, enabled INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE sso_states(state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, redirect_uri TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE sso_links(issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id), last_login_at TEXT NOT NULL, PRIMARY KEY(issuer,subject));
CREATE TABLE user_scopes(user_id TEXT PRIMARY KEY REFERENCES users(id), tenant TEXT NOT NULL, sites TEXT NOT NULL, domains TEXT NOT NULL, source TEXT NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE mfa_assertions_v2(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), session_hash TEXT NOT NULL, method TEXT NOT NULL CHECK(method IN ('totp','oidc')), verified_at TEXT NOT NULL, expires_at TEXT NOT NULL, evidence_hash TEXT NOT NULL);
INSERT INTO mfa_assertions_v2 SELECT * FROM mfa_assertions;
DROP TABLE mfa_assertions;
ALTER TABLE mfa_assertions_v2 RENAME TO mfa_assertions;
CREATE INDEX mfa_assertions_user_expiry ON mfa_assertions(user_id,expires_at);
`, String.raw`
CREATE TABLE secrets(ref TEXT PRIMARY KEY, kind TEXT NOT NULL, purpose TEXT NOT NULL, cipher TEXT NOT NULL, wrapped_key TEXT NOT NULL, fingerprint TEXT NOT NULL, owner TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, rotated_at TEXT NOT NULL, rotation_days INTEGER NOT NULL, version INTEGER NOT NULL, last_used_at TEXT, uses INTEGER NOT NULL DEFAULT 0, revoked_at TEXT);
CREATE TABLE secret_delegations(ref TEXT NOT NULL REFERENCES secrets(ref), source_id TEXT NOT NULL REFERENCES sources(id), granted_by TEXT NOT NULL, granted_at TEXT NOT NULL, PRIMARY KEY(ref,source_id));
`, String.raw`
CREATE TABLE alert_dispositions(alert_id TEXT PRIMARY KEY REFERENCES alerts(id), rule_id TEXT NOT NULL, disposition TEXT NOT NULL CHECK(disposition IN ('true-positive','benign-true-positive','false-positive')), note TEXT NOT NULL, decided_by TEXT NOT NULL REFERENCES users(id), decided_at TEXT NOT NULL, occurrences INTEGER NOT NULL);
CREATE INDEX alert_dispositions_rule ON alert_dispositions(rule_id,decided_at);
`, String.raw`
CREATE TABLE tenant_policy(id INTEGER PRIMARY KEY CHECK(id=1), retention_days INTEGER NOT NULL, max_events_per_day INTEGER NOT NULL, max_sources INTEGER NOT NULL, max_assets INTEGER NOT NULL, max_db_mb INTEGER NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX events_kind_received ON events(kind,received_at);
`, String.raw`
CREATE TABLE source_delivery(source_id TEXT PRIMARY KEY REFERENCES sources(id), queue_depth INTEGER NOT NULL, oldest_queued_at TEXT, delivery_attempt INTEGER NOT NULL, reported_at TEXT NOT NULL, max_delay_minutes REAL NOT NULL DEFAULT 0);
`, String.raw`
CREATE TABLE rollout_stages(id INTEGER PRIMARY KEY AUTOINCREMENT, stage TEXT NOT NULL CHECK(stage IN ('isolated-lab','limited-pilot','expansion')), asset_refs TEXT NOT NULL, sites TEXT NOT NULL, authorization_ref TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES users(id), requested_at TEXT NOT NULL, approved_by TEXT REFERENCES users(id), approved_at TEXT, status TEXT NOT NULL CHECK(status IN ('pending','active','superseded','rejected')), gate_json TEXT);
`, String.raw`
CREATE TABLE detection_hypotheses(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, source_type TEXT NOT NULL, source_ref TEXT NOT NULL, technique_ids TEXT NOT NULL, severity TEXT NOT NULL, rationale TEXT NOT NULL, logic TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','tested','approved','rejected','retired')), author TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, version INTEGER NOT NULL, test_json TEXT, decided_by TEXT REFERENCES users(id), decided_at TEXT, decision_note TEXT);
`, String.raw`
ALTER TABLE detection_hypotheses ADD COLUMN active_version INTEGER;
CREATE TABLE hypothesis_versions(hypothesis_id INTEGER NOT NULL REFERENCES detection_hypotheses(id), version INTEGER NOT NULL, content TEXT NOT NULL, signature TEXT NOT NULL, signer_fingerprint TEXT NOT NULL, approved_by TEXT NOT NULL REFERENCES users(id), approved_at TEXT NOT NULL, PRIMARY KEY(hypothesis_id,version));
CREATE TABLE trusted_rule_keys(fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL, label TEXT NOT NULL, added_by TEXT NOT NULL REFERENCES users(id), added_at TEXT NOT NULL, revoked_at TEXT);
`, String.raw`
CREATE TABLE vuln_tracking(key TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), vuln_id TEXT NOT NULL, product TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, risk_band TEXT NOT NULL, score INTEGER NOT NULL, due_at TEXT NOT NULL, resolved_at TEXT);
CREATE TABLE vuln_exceptions(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, reason TEXT NOT NULL, compensating_control TEXT NOT NULL, approved_by TEXT NOT NULL REFERENCES users(id), approved_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT);
`, String.raw`
CREATE TABLE sandboxes(id TEXT PRIMARY KEY, name TEXT NOT NULL, source_id TEXT NOT NULL UNIQUE REFERENCES sources(id), isolation_ref TEXT NOT NULL, egress TEXT NOT NULL CHECK(egress IN ('none','simulated-internet')), registered_by TEXT NOT NULL REFERENCES users(id), registered_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','suspended','retired')), last_isolation TEXT);
CREATE TABLE detonation_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, sandbox_id TEXT NOT NULL REFERENCES sandboxes(id), sha256 TEXT NOT NULL, file_name TEXT NOT NULL, custody_id TEXT, reason TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES users(id), requested_at TEXT NOT NULL, approved_by TEXT REFERENCES users(id), approved_at TEXT, started_at TEXT, completed_at TEXT, status TEXT NOT NULL CHECK(status IN ('pending-approval','approved','running','completed','rejected','expired')), report_json TEXT);
`, String.raw`
CREATE TABLE ot_safety_approvers(user_id TEXT PRIMARY KEY REFERENCES users(id), qualification_ref TEXT NOT NULL, designated_by TEXT NOT NULL REFERENCES users(id), designated_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE ot_safety_approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT NOT NULL REFERENCES actions(id), decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')), approver TEXT NOT NULL REFERENCES users(id), operator_on_site INTEGER NOT NULL, manual_fallback_confirmed INTEGER NOT NULL, process_state TEXT NOT NULL, note TEXT, decided_at TEXT NOT NULL);
`, String.raw`
ALTER TABLE detection_hypotheses ADD COLUMN environment_tuning TEXT NOT NULL DEFAULT '{"environment":"all","exclusions":[],"false_positive_budget_percent":20}';
`, String.raw`
CREATE TABLE threat_indicators(id TEXT PRIMARY KEY, type TEXT NOT NULL CHECK(type IN ('ipv4','ipv6','domain','url','sha256')), value TEXT NOT NULL, source_name TEXT NOT NULL, source_ref TEXT NOT NULL, published_at TEXT NOT NULL, expires_at TEXT NOT NULL, confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100), redistribution_rights TEXT NOT NULL CHECK(redistribution_rights IN ('permitted','restricted','prohibited','unknown')), source_verified INTEGER NOT NULL CHECK(source_verified IN (0,1)), added_by TEXT NOT NULL REFERENCES users(id), added_at TEXT NOT NULL);
CREATE INDEX threat_indicators_lookup ON threat_indicators(type,value,expires_at);
`, String.raw`
CREATE TABLE evidence_items(id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), parent_id TEXT REFERENCES evidence_items(id), name TEXT NOT NULL, media_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, source_ref TEXT NOT NULL, acquisition TEXT NOT NULL, collected_at TEXT NOT NULL, collected_by TEXT NOT NULL, received_at TEXT NOT NULL, received_by TEXT NOT NULL, transform TEXT);
CREATE INDEX evidence_items_case ON evidence_items(case_id);
CREATE TABLE evidence_custody(seq INTEGER PRIMARY KEY AUTOINCREMENT, item_id TEXT NOT NULL REFERENCES evidence_items(id), at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, purpose TEXT, details TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER evidence_items_no_update BEFORE UPDATE ON evidence_items BEGIN SELECT RAISE(ABORT,'evidence_immutable'); END;
CREATE TRIGGER evidence_items_no_delete BEFORE DELETE ON evidence_items BEGIN SELECT RAISE(ABORT,'evidence_immutable'); END;
CREATE TRIGGER evidence_custody_no_update BEFORE UPDATE ON evidence_custody BEGIN SELECT RAISE(ABORT,'custody_append_only'); END;
CREATE TRIGGER evidence_custody_no_delete BEFORE DELETE ON evidence_custody BEGIN SELECT RAISE(ABORT,'custody_append_only'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events_immutable'); END;
`, String.raw`
CREATE TABLE validation_lab_runs(id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('scenario','replay')), ref TEXT NOT NULL, title TEXT NOT NULL, actor TEXT NOT NULL, at TEXT NOT NULL, expected TEXT NOT NULL, observed TEXT NOT NULL, missing TEXT NOT NULL, unexpected TEXT NOT NULL, passed INTEGER NOT NULL, details TEXT NOT NULL);
CREATE TRIGGER validation_lab_runs_no_update BEFORE UPDATE ON validation_lab_runs BEGIN SELECT RAISE(ABORT,'validation_runs_append_only'); END;
`, String.raw`
CREATE TABLE hunts(id TEXT PRIMARY KEY, name TEXT NOT NULL, hypothesis TEXT, query TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE hunt_notes(id TEXT PRIMARY KEY, hunt_id TEXT NOT NULL REFERENCES hunts(id), at TEXT NOT NULL, actor TEXT NOT NULL, text TEXT NOT NULL, event_refs TEXT NOT NULL);
CREATE TABLE hunt_reports(id TEXT PRIMARY KEY, hunt_id TEXT NOT NULL REFERENCES hunts(id), at TEXT NOT NULL, actor TEXT NOT NULL, result_sha256 TEXT NOT NULL, rows_total INTEGER NOT NULL, report TEXT NOT NULL);
CREATE TRIGGER hunt_notes_no_update BEFORE UPDATE ON hunt_notes BEGIN SELECT RAISE(ABORT,'hunt_notes_append_only'); END;
CREATE TRIGGER hunt_reports_no_update BEFORE UPDATE ON hunt_reports BEGIN SELECT RAISE(ABORT,'hunt_reports_immutable'); END;
`, String.raw`
CREATE TABLE change_windows(id TEXT PRIMARY KEY, asset_ref TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, change_ref TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE action_confirmations(action_id TEXT PRIMARY KEY REFERENCES actions(id), confirmed_by TEXT NOT NULL, confirmed_at TEXT NOT NULL, typed_target TEXT NOT NULL, emergency TEXT);
`, String.raw`
CREATE TABLE orchestrations(id TEXT PRIMARY KEY, playbook_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id), params TEXT NOT NULL, authorization_ref TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, steps TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX orchestrations_key ON orchestrations(idempotency_key,status);
`, String.raw`
CREATE TABLE ai_source_snapshots(id TEXT PRIMARY KEY, source_type TEXT NOT NULL, ref TEXT NOT NULL, sha256 TEXT NOT NULL, captured_at TEXT NOT NULL, observed_at TEXT, content TEXT NOT NULL, UNIQUE(ref,sha256));
CREATE TABLE ai_answers(id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, generated_at TEXT NOT NULL, generated_for TEXT NOT NULL, role TEXT NOT NULL, answer TEXT NOT NULL, answer_sha256 TEXT NOT NULL);
CREATE TRIGGER ai_source_snapshots_immutable BEFORE UPDATE ON ai_source_snapshots BEGIN SELECT RAISE(ABORT,'snapshot_immutable'); END;
CREATE TRIGGER ai_answers_immutable BEFORE UPDATE ON ai_answers BEGIN SELECT RAISE(ABORT,'answer_immutable'); END;
`, String.raw`
CREATE TABLE ai_eval_runs(id TEXT PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, passed INTEGER NOT NULL, total INTEGER NOT NULL, cases TEXT NOT NULL);
CREATE TRIGGER ai_eval_runs_immutable BEFORE UPDATE ON ai_eval_runs BEGIN SELECT RAISE(ABORT,'evaluation_immutable'); END;
`, String.raw`
CREATE TABLE compliance_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, saved_at TEXT NOT NULL, saved_by TEXT NOT NULL, profile TEXT NOT NULL);
`, String.raw`
CREATE TABLE msoc_provider(id INTEGER PRIMARY KEY AUTOINCREMENT, saved_at TEXT NOT NULL, saved_by TEXT NOT NULL, profile TEXT NOT NULL);
CREATE TABLE msoc_customers(id TEXT PRIMARY KEY, name TEXT NOT NULL, sector TEXT NOT NULL, pdpl_agreement_ref TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
`, String.raw`
CREATE TABLE instance_identity(id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL, bound_at TEXT NOT NULL);
CREATE TRIGGER instance_identity_immutable BEFORE UPDATE ON instance_identity BEGIN SELECT RAISE(ABORT,'tenant_binding_immutable'); END;
CREATE TABLE data_residency(data_class TEXT PRIMARY KEY, region TEXT NOT NULL, declared_by TEXT NOT NULL, declared_at TEXT NOT NULL);
CREATE TABLE erasure_requests(id TEXT PRIMARY KEY, identifier_sha256 TEXT NOT NULL, reason TEXT NOT NULL, requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT, completed_at TEXT, matched INTEGER NOT NULL, erased INTEGER, held INTEGER NOT NULL);
`, String.raw`
CREATE TABLE soc_sla(id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE soc_shifts(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE soc_escalations(alert_id TEXT NOT NULL, level INTEGER NOT NULL, role TEXT NOT NULL, to_user TEXT, at TEXT NOT NULL, overdue_minutes INTEGER NOT NULL, PRIMARY KEY(alert_id,level));
CREATE TABLE case_tickets(case_id TEXT PRIMARY KEY REFERENCES cases(id), assignee TEXT NOT NULL, priority TEXT NOT NULL, due_at TEXT NOT NULL, assigned_by TEXT NOT NULL, assigned_at TEXT NOT NULL);
CREATE TABLE case_closures(case_id TEXT PRIMARY KEY REFERENCES cases(id), resolution TEXT NOT NULL, root_cause TEXT NOT NULL, requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, needs_review INTEGER NOT NULL, status TEXT NOT NULL, reviewed_by TEXT, reviewed_at TEXT);
CREATE TABLE soc_lessons(id TEXT PRIMARY KEY, case_id TEXT, exercise_id TEXT, what_happened TEXT NOT NULL, went_well TEXT, to_improve TEXT NOT NULL, detection_gap INTEGER NOT NULL, actions TEXT NOT NULL, hypothesis_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE soc_exercises(id TEXT PRIMARY KEY, title TEXT NOT NULL, scenario TEXT NOT NULL, scheduled_at TEXT NOT NULL, participants TEXT NOT NULL, status TEXT NOT NULL, findings TEXT, completed_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
`, String.raw`
CREATE TABLE platform_backups(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, restore_tested INTEGER NOT NULL, audit_chain_valid INTEGER NOT NULL, detail TEXT NOT NULL);
`, String.raw`
CREATE TABLE required_flows(id TEXT PRIMARY KEY, name TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, criticality TEXT NOT NULL, path TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE change_analyses(id TEXT PRIMARY KEY, device_ref TEXT NOT NULL, requested_by TEXT NOT NULL, at TEXT NOT NULL, decision TEXT NOT NULL, summary TEXT NOT NULL, change TEXT NOT NULL);
`, String.raw`
CREATE TABLE intended_reviews(key TEXT PRIMARY KEY, decision TEXT NOT NULL, note TEXT, conflict TEXT NOT NULL, reviewed_by TEXT NOT NULL, reviewed_at TEXT NOT NULL);
`, String.raw`
CREATE TABLE impact_roles(id TEXT PRIMARY KEY, asset_ref TEXT NOT NULL, role TEXT NOT NULL, consumers_json TEXT NOT NULL, note TEXT, declared_by TEXT NOT NULL, declared_at TEXT NOT NULL, UNIQUE(asset_ref, role));
`, String.raw`
CREATE TABLE adapter_lab_validations(id TEXT PRIMARY KEY, adapter_id TEXT NOT NULL, model TEXT NOT NULL, firmware TEXT NOT NULL, result TEXT NOT NULL, lab_ref TEXT NOT NULL, notes TEXT, tested_at TEXT NOT NULL, recorded_by TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE INDEX adapter_lab_by_adapter ON adapter_lab_validations(adapter_id, tested_at);
`, String.raw`
CREATE TABLE vuln_observations(asset_ref TEXT NOT NULL, vuln_id TEXT NOT NULL, kev INTEGER NOT NULL, first_vulnerable_at TEXT NOT NULL, last_vulnerable_at TEXT NOT NULL, fixed_at TEXT, PRIMARY KEY(asset_ref, vuln_id));
CREATE TABLE post_patch_investigations(id TEXT PRIMARY KEY, asset_ref TEXT NOT NULL, vuln_id TEXT NOT NULL, vulnerable_from TEXT NOT NULL, patched_at TEXT NOT NULL, exposure_json TEXT NOT NULL, items_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, closed_at TEXT, closed_by TEXT, gaps_reason TEXT);
`, String.raw`
CREATE TABLE detection_tests(id TEXT PRIMARY KEY, rule TEXT NOT NULL, result TEXT NOT NULL, method TEXT NOT NULL, evidence_ref TEXT NOT NULL, notes TEXT, tested_at TEXT NOT NULL, recorded_by TEXT NOT NULL);
CREATE INDEX detection_tests_by_rule ON detection_tests(rule, tested_at);
`, String.raw`
CREATE TABLE permission_reduction(key TEXT PRIMARY KEY, principal TEXT NOT NULL, permission TEXT NOT NULL, state TEXT NOT NULL, change_ref TEXT, approver TEXT, note TEXT, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
`, String.raw`
CREATE TABLE collection_stops(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id), stopped_by TEXT NOT NULL REFERENCES users(id), stopped_at TEXT NOT NULL, reason TEXT NOT NULL, authorization_ref TEXT NOT NULL, incident_owner_ref TEXT, events_total INTEGER NOT NULL, protected_events INTEGER NOT NULL, open_alerts INTEGER NOT NULL, open_cases INTEGER NOT NULL);
`, String.raw`
CREATE TABLE correlation_rules(id INTEGER PRIMARY KEY AUTOINCREMENT, definition TEXT NOT NULL, version INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','active','disabled')), test_json TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, approved_by TEXT REFERENCES users(id), approved_at TEXT);
`, String.raw`
CREATE TABLE source_contracts(source_id TEXT PRIMARY KEY REFERENCES sources(id), connector TEXT NOT NULL, connector_version TEXT NOT NULL, event_source TEXT NOT NULL, time_zone TEXT NOT NULL, clock_source TEXT NOT NULL, declared_at TEXT NOT NULL);
CREATE TABLE ingest_rejections(seq INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL REFERENCES sources(id), at TEXT NOT NULL, code TEXT NOT NULL, events INTEGER NOT NULL);
CREATE INDEX ingest_rejections_by_source ON ingest_rejections(source_id, at);
`, String.raw`
CREATE TABLE decoys(id TEXT PRIMARY KEY, type TEXT NOT NULL, ref_display TEXT NOT NULL, ref_hash TEXT NOT NULL, match_ref TEXT, placement TEXT NOT NULL, owner TEXT NOT NULL, authorization_ref TEXT NOT NULL, isolation TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('proposed','active','retired')), proposed_by TEXT NOT NULL REFERENCES users(id), proposed_at TEXT NOT NULL, expires_days INTEGER NOT NULL, note TEXT, approved_by TEXT REFERENCES users(id), approved_at TEXT, expires_at TEXT, retired_at TEXT);
`, String.raw`
ALTER TABLE detection_hypotheses ADD COLUMN canary_version INTEGER;
ALTER TABLE detection_hypotheses ADD COLUMN canary_started_at TEXT;
ALTER TABLE detection_hypotheses ADD COLUMN canary_until TEXT;
ALTER TABLE detection_hypotheses ADD COLUMN previous_version INTEGER;
ALTER TABLE detection_hypotheses ADD COLUMN lifecycle_stage TEXT;
CREATE TABLE canary_hits(hypothesis_id INTEGER NOT NULL REFERENCES detection_hypotheses(id), version INTEGER NOT NULL, event_id TEXT NOT NULL, at TEXT NOT NULL, disposition TEXT CHECK(disposition IN ('true-positive','false-positive')), reviewed_by TEXT REFERENCES users(id), reviewed_at TEXT, PRIMARY KEY(hypothesis_id,version,event_id));
`, String.raw`
CREATE TABLE case_confidence(case_id TEXT PRIMARY KEY REFERENCES cases(id), level TEXT NOT NULL CHECK(level IN ('verified-security-incident','confirmed-compromise')), verified_by TEXT NOT NULL REFERENCES users(id), verified_at TEXT NOT NULL, verification_rationale TEXT NOT NULL, evidence_event_ids TEXT NOT NULL, compromise_type TEXT, compromise_evidence_refs TEXT, confirmation_rationale TEXT, confirmed_by TEXT REFERENCES users(id), confirmed_at TEXT);
`, String.raw`
CREATE TABLE privacy_rules(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, field TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('drop','mask','hash','encrypt')), source_type TEXT, reason TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, disabled_at TEXT, disabled_by TEXT REFERENCES users(id));
CREATE TABLE retention_rules(scope TEXT NOT NULL CHECK(scope IN ('source','source-type','event-kind')), match TEXT NOT NULL, days INTEGER NOT NULL, legal_basis TEXT NOT NULL, legal_minimum_days INTEGER, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, PRIMARY KEY(scope,match));
`, String.raw`
CREATE TABLE ingest_batches(seq INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL REFERENCES sources(id), at TEXT NOT NULL, accepted INTEGER NOT NULL, duplicates INTEGER NOT NULL, processing_ms INTEGER NOT NULL);
CREATE INDEX ingest_batches_by_time ON ingest_batches(at);
`];

export class Store {
  constructor(filename) {
    if (filename !== ':memory:') fs.mkdirSync(path.dirname(filename),{recursive:true,mode:0o700});
    this.filename = filename;
    this.db = new DatabaseSync(filename);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;');
    this.migrate();
    if (!this.verifyAudit().valid) { this.db.close(); throw new Error('audit_integrity_failure'); }
  }
  migrate() {
    this.db.exec('CREATE TABLE IF NOT EXISTS migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)');
    const version = this.db.prepare('SELECT COALESCE(MAX(version),0) version FROM migrations').get().version;
    if (version > migrations.length) throw new Error('database_schema_newer_than_application');
    if (version && version < migrations.length && this.filename !== ':memory:') {
      this.db.exec('PRAGMA wal_checkpoint(FULL)');
      fs.copyFileSync(this.filename,`${this.filename}.pre-migration-${version}`);
    }
    for (let i = version; i < migrations.length; i++) this.transaction(() => {
      this.db.exec(migrations[i]);
      this.run('INSERT INTO migrations VALUES (?,?)',i+1,new Date().toISOString());
    });
  }
  run(sql,...params) { return this.db.prepare(sql).run(...params); }
  get(sql,...params) { return this.db.prepare(sql).get(...params); }
  all(sql,...params) { return this.db.prepare(sql).all(...params); }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); if (result?.then) throw new Error('async_transaction_forbidden'); this.db.exec('COMMIT'); return result; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  audit(actor, action, target, details = {}, at = new Date().toISOString()) {
    // Details must be a known schema; never pass request bodies, credentials or raw evidence here.
    const previous = this.get('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1')?.hash || '0'.repeat(64);
    const row = {at,actor,action,target,details:JSON.stringify(details),previous_hash:previous};
    const hash = digest(row);
    this.run('INSERT INTO audit(at,actor,action,target,details,previous_hash,hash) VALUES (?,?,?,?,?,?,?)',at,actor,action,target,row.details,previous,hash);
    return hash;
  }
  verifyAudit() {
    let previous = '0'.repeat(64), count = 0;
    for (const row of this.db.prepare('SELECT * FROM audit ORDER BY seq').iterate()) {
      const computed = digest({at:row.at,actor:row.actor,action:row.action,target:row.target,details:row.details,previous_hash:row.previous_hash});
      if (row.previous_hash !== previous || row.hash !== computed) return {valid:false,checked:count};
      previous = row.hash; count++;
    }
    return {valid:true,checked:count,head:previous,scope:'local-chain-only; external anchoring not configured'};
  }
  require(sql,params = []) { const row = this.get(sql,...params); if (!row) throw new AppError(404,'not_found'); return row; }
  close() { this.db.close(); }
}
