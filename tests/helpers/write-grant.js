// Test helper (not a test file): gives a response connector an approved CG-177 write grant through the real request and
// second-approver path, using two fixture administrators created here if they do not exist.
import { ConnectorGrants } from '../../lib/connector-grants.js';

export function grantWrite(store, sourceId, targetIds, { clock } = {}) {
  for (const id of ['grant-requester', 'grant-approver']) if (!store.get('SELECT id FROM users WHERE id=?', id)) store.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const g = new ConnectorGrants(store, { clock });
  return g.approve('grant-approver', g.request('grant-requester', { source_id: sourceId, scope_type: 'site', scope_ref: 'test-site', target_ids: targetIds, days: 365, reason: 'Test fixture write grant' }).id);
}

// Grants every response connector the targets its stored response.capability declares (each through request and approval).
export function grantDeclaredCapabilities(store, { clock } = {}) {
  const done = new Set(store.all("SELECT source_id,target_ids FROM connector_grants WHERE status='active'").flatMap(g => JSON.parse(g.target_ids).map(t => `${g.source_id}|${t}`)));
  for (const r of store.all("SELECT source_id,payload FROM events WHERE kind='response.capability'")) {
    const targets = (JSON.parse(r.payload).details.target_asset_refs || []).filter(t => !done.has(`${r.source_id}|${t}`));
    if (targets.length) { grantWrite(store, r.source_id, targets, { clock }); for (const t of targets) done.add(`${r.source_id}|${t}`); }
  }
}
