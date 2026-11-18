import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { incidentStudies, tactics, preventionAr } from '../lib/incident-studies.js';
import { Store } from '../lib/store.js';
import { Domain, evidenceKinds } from '../lib/domain.js';
import { responseActionCatalog } from '../lib/response-actions.js';
import { detectionCatalog } from '../lib/detection-rules.js';

const source = ['lib/domain.js', 'lib/identity-threats.js', 'lib/detection-rules.js'].map(f => fs.readFileSync(new URL(`../${f}`, import.meta.url), 'utf8')).join('\n');

test('every incident study cites an official advisory and maps each stage to real evidence kinds, rules, actions and controls (CG-064)', () => {
  assert.ok(incidentStudies.length >= 8); assert.equal(new Set(incidentStudies.map(s => s.id)).size, incidentStudies.length);
  const catalogRules = new Set(detectionCatalog().map(r => r.id));
  for (const s of incidentStudies) {
    assert.match(s.source.url, /^https:\/\/www\.cisa\.gov\//, `${s.id} cites an official advisory`); assert.ok(s.title[1] && s.summary[1], `${s.id} has Arabic text`);
    assert.ok(s.stages.length >= 2, `${s.id} has stages`);
    for (const t of s.stages) {
      assert.ok(tactics.includes(t.tactic), `${s.id} tactic ${t.tactic}`);
      for (const id of t.techniques) assert.match(id, /^T\d{4}(\.\d{3})?$/, `${s.id} technique ${id}`);
      for (const k of t.evidence) assert.ok(evidenceKinds.includes(k), `${s.id} evidence kind ${k} exists`);
      for (const r of t.rules) assert.ok(catalogRules.has(r) || source.includes(`'${r}'`), `${s.id} rule ${r} exists in CyberGuard`);
      for (const a of t.response) assert.ok(responseActionCatalog[a], `${s.id} response ${a} exists in the catalog`);
      assert.ok(t.evidence.length && t.prevention.length && t.what[1]); for (const p of t.prevention) assert.ok(preventionAr[p], `Arabic for ${p}`);
    }
  }
});

test('incident studies show per installation which stages are visible and how often their rules fired (CG-064)', () => {
  const s = new Store(':memory:'), now = Date.now(), d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Edge firewall logs', stale_seconds: 3600 }), asset = { external_id: 'edge-01', hostname: 'EDGE-01', os_family: 'network', device_type: 'firewall', addresses: ['192.0.2.60'] };
  let r = d.incidentStudies(); const wannacry = () => r.items.find(x => x.id === 'wannacry-2017');
  assert.equal(wannacry().visible_stages, 0, 'nothing received yet: every stage is blind here'); assert.ok(r.claim_ar.includes('حوادث موثقة'));
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: Array.from({ length: 5 }, (_, i) => ({ event_id: `f-${i}`, kind: 'auth.failed', observed_at: new Date(now).toISOString(), asset, details: { account: 'admin', source_ip: '198.51.100.90', protocol: 'ssh' } })) });
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'disc', kind: 'discovery.observed', observed_at: new Date(now).toISOString(), asset, details: { authorization_ref: 'AUTH-LAB-064', acquisition: 'passive-import', availability: 'up', networks: ['192.0.2.0/24'], routes: [], vlans: [], interfaces: [], services: [] } }] });
  d.alert({ key: 'lateral-064', rule: 'CG-NET-LATERAL-015', severity: 'high', title: 'Synthetic lateral SMB' });
  r = d.incidentStudies(); assert.equal(wannacry().stages.find(t => t.tactic === 'lateral-movement').alerts_90d, 1, 'the mapped rule fired once here'); const lateral = wannacry().stages.find(t => t.tactic === 'lateral-movement');
  assert.equal(lateral.visibility, 'visible'); assert.deepEqual(lateral.evidence_received, ['discovery.observed']); assert.equal(wannacry().stages[0].visibility, 'blind');
  assert.equal(lateral.tactic_name[1], 'الحركة الجانبية'); assert.ok(lateral.prevention_ar[0].includes('SMB'));
  assert.equal(d.incidentStudies({ q: 'T1219' }).items.map(x => x.id).join(), 'scattered-spider-2023', 'search by technique');
  s.close();
});
