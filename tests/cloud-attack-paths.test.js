import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { attackPaths, attackPathView } from '../lib/cloud-attack-paths.js';

const EVENTS = JSON.parse(fs.readFileSync(new URL('./fixtures/cloud-paths/events.json', import.meta.url), 'utf8'));
const asset = { external_id: 'aws:111122223333', hostname: 'AWS 111122223333', os_family: 'unknown', device_type: 'unknown', addresses: [] };
function fixture(t, events) {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = d.createSource('a', { name: 'Cloud', stale_seconds: 86400 });
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: events.map(e => ({ ...e, observed_at: new Date().toISOString(), asset })) }); return { s, d, src };
}

test('attack paths link exposure, misconfiguration, identity, permission and sensitive target from stored records, and external reachability is validated only by an external observation (CG-153)', t => {
  const { s } = fixture(t, EVENTS), paths = attackPaths(s);
  const web = paths.find(p => p.entry_name === 'web-frontend' && p.target_name === 'customer-exports');
  assert.equal(web.status, 'validated-external-reachability', 'an external observation reached the entry resource');
  assert.deepEqual(web.steps.map(x => x.type), ['exposure', 'misconfiguration', 'identity', 'permission', 'sensitive-target']);
  assert.deepEqual(web.inferred_steps, ['identity'], 'the attached identity comes from a declared tag');
  assert.ok(web.steps.every(x => x.event_ids.length), 'every step names its stored record');
  const self = paths.find(p => p.entry_name === 'public-reports'); assert.equal(self.status, 'inferred', 'public by configuration only'); assert.equal(self.target_name, 'public-reports');
  assert.ok(!paths.some(p => p.entry_name === 'batch-worker'), 'an admin identity on an unexposed resource is not an entry point');
  const noEasm = fixture(t, EVENTS.filter(e => e.kind !== 'easm.observation')); assert.equal(attackPaths(noEasm.s).find(p => p.entry_name === 'web-frontend').status, 'inferred', 'without the observation the same path is inferred');
  const v = attackPathView(s); assert.deepEqual([v.summary.validated, v.summary.inferred], [2, 1], 'web-frontend also reaches the confidential bucket in its granted account'); assert.equal(v.comparison.length, 4);
});

test('critical paths and high paths with validated reachability raise one alert each, and a broken step removes the path (CG-153)', t => {
  const { s } = fixture(t, EVENTS), alerts = s.all("SELECT title,severity FROM alerts WHERE rule_id='CG-CLOUD-PATH-153'");
  assert.deepEqual(alerts.map(a => a.title.split(' (')[0].replace('Possible attack path ', '')).sort(), ['web-frontend → customer-exports', 'web-frontend → public-reports']);
  assert.ok(alerts.every(a => a.severity === 'critical' && /external reachability validated/.test(a.title)), 'the inferred public-reports self path stays below the alert threshold');
  const narrowed = EVENTS.map(e => e.kind === 'cloud.access_grant' ? { ...e, details: { ...e.details, grants: e.details.grants.filter(g => g.grant_id !== 'g-web') } } : e);
  const { s: s2 } = fixture(t, narrowed); assert.ok(!attackPaths(s2).some(p => p.target_name === 'customer-exports'), 'removing the grant breaks the path');
});
