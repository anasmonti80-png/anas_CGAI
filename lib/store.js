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
