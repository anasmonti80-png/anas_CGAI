// CI check: ingest real collector output files into a disposable store and fail if any is rejected.
// Usage: node scripts/ci-collector-check.js <file.json> [more.json ...]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

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
    const batch = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));
    const result = domain.ingest('ci-admin', source.id, batch);
    const kinds = [...new Set(batch.events.map(e => e.kind))].join(', ');
    console.log(`ACCEPTED ${path.basename(file)}: ${batch.events.length} event(s) [${kinds}]`, JSON.stringify(result).slice(0, 200));
  } catch (error) {
    failed++;
    console.error(`REJECTED ${path.basename(file)}: ${error.code || error.message}`);
  }
}
const summary = { agents: domain.agentInventory().total, software: domain.softwareVulnerabilities().total, changes: domain.sensitiveChanges().total, discovery: domain.discoverySequences().total };
console.log('Registries after ingest:', JSON.stringify(summary));
store.close(); fs.rmSync(dir, { recursive: true, force: true });
if (failed) process.exit(1);
