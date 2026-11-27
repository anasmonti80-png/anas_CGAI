import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ThreatIntelligence } from '../lib/threat-intelligence.js';
import { FeedGovernance } from '../lib/feed-governance.js';

const ip = n => `198.51.100.${n}`, exp = new Date(Date.now() + 30 * 86400000).toISOString(), day = new Date(Date.now() - 86400000).toISOString();
const feedV = (items, extra = {}) => ({ feed: 'partner-blocklist', kind: 'threat-intel', source_ref: 'https://intel.example/feeds/partner.json', source_date: day, license: 'Partner TLP:GREEN, internal use only', redistribution_rights: 'restricted', source_verified: true, items, ...extra });
const it = (n, confidence = 80) => ({ type: 'ipv4', value: ip(n), confidence, expires_at: exp });

test('feed updates are staged with source date, licence and diff, need a second approver and an acknowledgement for mass changes, never create response actions and can be rolled back (CG-169)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), ti = new ThreatIntelligence(s), fg = new FeedGovernance(s, { domain: d, threatIntel: ti });
  for (const [u, role] of [['analyst', 'analyst'], ['admin', 'admin']]) s.run('INSERT INTO users VALUES (?,?,?,?,?)', u, u, 'fixture-not-a-password-hash', role, new Date().toISOString());
  assert.throws(() => fg.stage('analyst', feedV([it(1)], { source_ref: 'http://intel.example/x' })), /feed_source_must_be_https/);
  const v1 = fg.stage('analyst', feedV([it(1), it(2), it(3)]));
  assert.deepEqual([v1.status, v1.diff.added, v1.license], ['staged', 3, 'Partner TLP:GREEN, internal use only']);
  assert.equal(s.get('SELECT COUNT(*) n FROM threat_indicators').n, 0, 'nothing is applied while staged');
  assert.throws(() => fg.approve('analyst', v1.id), /feed_needs_second_approver/);
  fg.approve('admin', v1.id); assert.equal(s.get("SELECT COUNT(*) n FROM threat_indicators WHERE source_name='partner-blocklist'").n, 3);
  const v2 = fg.stage('analyst', feedV([it(1), it(2, 40), it(4)]));
  assert.deepEqual([v2.diff.added, v2.diff.removed, v2.diff.changed, v2.diff.sample.removed], [1, 1, 1, [`ipv4|${ip(3)}`]]);
  fg.approve('admin', v2.id);
  const live = v => s.get('SELECT COUNT(*) n FROM threat_indicators WHERE value=? AND expires_at>?', v, new Date().toISOString()).n; // list() is capped at 500 rows
  assert.deepEqual([live(ip(3)), live(ip(4))], [0, 1], 'a removed indicator is expired, not deleted');
  assert.equal(s.get('SELECT COUNT(*) n FROM threat_indicators WHERE value=?', ip(3)).n, 1);

  // Mass change: 250 new addresses and 400 new domains (650 added).
  const bulk = [...Array.from({ length: 250 }, (_, i) => ({ type: 'ipv4', value: `203.0.113.${i}`, confidence: 50, expires_at: exp })), ...Array.from({ length: 400 }, (_, i) => ({ type: 'domain', value: `bad${i}.example`, confidence: 50, expires_at: exp }))];
  const v3 = fg.stage('analyst', feedV([it(1), it(2, 40), it(4), ...bulk]));
  assert.equal(v3.mass_change, true); assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-FEED-MASS-169'").n, 1);
  assert.throws(() => fg.approve('admin', v3.id), /feed_mass_change_needs_acknowledgement/);
  fg.approve('admin', v3.id, { acknowledge_mass_change: true, note: 'Partner confirmed a campaign' });
  assert.equal(s.get("SELECT COUNT(*) n FROM actions").n, 0, 'a feed change never creates a response action');
  assert.ok(ti.list().every(x => x.auto_block_allowed === false));
  // Rollback to v2: the v3 additions expire, v2 is active again.
  const rb = fg.rollback('admin', 'partner-blocklist', { version_no: 2, reason: 'Campaign list was a partner error' });
  assert.deepEqual([rb.status, rb.applied_diff.removed], ['active', 650]); assert.equal(live('bad1.example'), 0); assert.equal(live(ip(4)), 1);
  assert.deepEqual(fg.view().feeds[0].versions.map(v => [v.version_no, v.status]), [[3, 'superseded'], [2, 'active'], [1, 'superseded']]);
  // KEV: the catalogue becomes a vulnerability.intel event only after approval.
  const kev = { catalogVersion: '2026.11.26', dateReleased: '2026-11-26T12:00:00.000Z', vulnerabilities: [{ cveID: 'CVE-2026-1001', vendorProject: 'Lab', product: 'App', vulnerabilityName: 'Lab RCE', dateAdded: '2026-11-20', dueDate: '2026-12-11', knownRansomwareCampaignUse: 'Known' }] };
  const k1 = fg.stage('analyst', { feed: 'cisa-kev', kind: 'cisa-kev', source_ref: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', license: 'CISA KEV catalog (public)', redistribution_rights: 'permitted', kev_catalog: kev });
  assert.equal(s.get("SELECT COUNT(*) n FROM events WHERE kind='vulnerability.intel'").n, 0); fg.approve('admin', k1.id);
  assert.equal(JSON.parse(s.get("SELECT payload FROM events WHERE kind='vulnerability.intel'").payload).details.entries[0].cve_id, 'CVE-2026-1001');
  assert.deepEqual(s.all("SELECT action FROM audit WHERE action LIKE 'feed.%' ORDER BY seq").map(r => r.action), ['feed.staged', 'feed.approved', 'feed.staged', 'feed.approved', 'feed.staged', 'feed.approved', 'feed.rolled_back', 'feed.staged', 'feed.approved']);
});
