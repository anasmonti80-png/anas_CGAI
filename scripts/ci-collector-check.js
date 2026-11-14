// CI check: ingest real collector output files into a disposable store and fail if any is rejected
// or larger than the HTTP ingest limit (the API would answer 413 for it).
// Usage: node scripts/ci-collector-check.js <file.json> [more.json ...]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { MAX_INGEST_BYTES } from '../lib/common.js';
import { normalizeWindowsExport } from '../lib/windows-events.js';

const files = process.argv.slice(2);
if (!files.length) throw new Error('No collector output files given.');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ci-collector-'));
const store = new Store(path.join(dir, 'ci.sqlite'));
const domain = new Domain(store);
store.run('INSERT INTO users VALUES (?,?,?,?,?)', 'ci-admin', 'ci-admin', 'ci-not-a-password-hash', 'admin', new Date().toISOString());
const source = domain.createSource('ci-admin', { name: 'CI REAL COLLECTOR RUN', stale_seconds: 86400 });
let failed = 0;
for (const file of files) {
  try {
    const bytes = fs.statSync(file).size;
    if (bytes > MAX_INGEST_BYTES) throw new Error(`file is ${bytes} bytes; the ingest API accepts at most ${MAX_INGEST_BYTES}`);
    const batch = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));
    // cg.windows-export/1 files go through the same normalizer the HTTP endpoint uses. That parser keeps only
    // remote-interactive (RDP, type 10) logons and failed logons; a host without them yields
    // no_supported_windows_events, which is a correct result, so it is reported (with the logon types seen) and
    // not counted as a failure. Any other error (format, provider, fields) still fails the check.
    if (batch.schema_version === 'cg.windows-export/1') {
      try { normalizeWindowsExport(batch); } catch (error) {
        if (error.code !== 'no_supported_windows_events') throw error;
        const types = {}; for (const e of batch.events) { const key = `${e.event_id}/type ${e.data?.LogonType ?? '-'}`; types[key] = (types[key] || 0) + 1; }
        console.log(`PARSED ${path.basename(file)}: ${batch.events.length} record(s) valid, none remote-interactive or failed; logon types seen ${JSON.stringify(types)}`);
        continue;
      }
    }
    const result = batch.schema_version === 'cg.windows-export/1' ? domain.ingest('ci-admin', source.id, normalizeWindowsExport(batch).batch) : domain.ingest('ci-admin', source.id, batch);
    const kinds = batch.schema_version === 'cg.windows-export/1' ? 'windows security events' : [...new Set(batch.events.map(e => e.kind))].join(', ');
    console.log(`ACCEPTED ${path.basename(file)}: ${batch.events.length} event(s) [${kinds}]`, JSON.stringify(result).slice(0, 200));
  } catch (error) {
    failed++;
    console.error(`REJECTED ${path.basename(file)}: ${error.code || error.message}`);
  }
}
const summary = { agents: domain.agentInventory().total, software: domain.softwareVulnerabilities().total, changes: domain.sensitiveChanges().total, discovery: domain.discoverySequences().total, identity: domain.identityDirectories().total, normalized_log_records: domain.normalizedLogs().total };
console.log('Registries after ingest:', JSON.stringify(summary));
store.close(); fs.rmSync(dir, { recursive: true, force: true });
if (failed) process.exit(1);
