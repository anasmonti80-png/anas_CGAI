// CG-052 Attribute-based access on top of roles: tenant, site and functional-domain scope per user.
// - Tenant: one tenant per installation (CG_TENANT). A user scoped to another tenant is refused everywhere.
// - Domains: cloud, network, identity, response and vulnerabilities areas; '*' means all.
// - Sites: from asset.context.site. A site-limited user works only in the investigation workspace (alerts, events,
//   assets, cases, actions, remote sessions, AI analysis), filtered to assets of those sites; organisation-wide views
//   that aggregate every site are refused so no count or finding outside the scope leaks.
export const scopeDomains = ['cloud', 'network', 'identity', 'response', 'vulnerability'];
const domainPaths = [
  ['cloud', /^\/api\/(cloud-|nsg-flow-migration)/],
  ['network', /^\/api\/(network-|firewall|device-config|device-capabilities|security-integrations|discovery|normalized-logs|network-analysis)/],
  ['identity', /^\/api\/(identity|directory|laps|adcs|privileged-access|saas-service|helpdesk|signin)/],
  ['response', /^\/api\/(actions|response-|temporary-permits|playbook|ai-action-proposals|incident-playbooks)/],
  ['vulnerability', /^\/api\/(software-vuln|vulnerabilit|validation|detection-coverage|critical-production)/]];
export const pathDomain = p => (domainPaths.find(([, re]) => re.test(p)) || [null])[0];
// Paths a site-limited user may call (everything else aggregates across sites).
const siteScopedPaths = [/^\/api\/auth\//, /^\/api\/sso\//, /^\/api\/(jit|break-glass)(\/|$)/, /^\/api\/(alerts|events|assets|cases|actions|remote-sessions)$/, /^\/api\/(alerts|events|assets|cases|actions|ai-analysis|ai-action-proposals|playbook-runs)\/[0-9a-f-]{36}(\/[a-z-]+)?$/, /^\/api\/actions\/preview$/, /^\/api\/playbook-runs$/, /^\/api\/ai-model-policy$/, /^\/api\/scoped-overview$/, /^\/api\/remote-access$/];
export const siteScopedPath = p => siteScopedPaths.some(re => re.test(p));
export function scopeFor(store, userId, deploymentTenant) {
  const row = store.get('SELECT * FROM user_scopes WHERE user_id=?', userId);
  if (!row) return { tenant: deploymentTenant, sites: ['*'], domains: ['*'], source: 'default', restricted: false };
  const sites = JSON.parse(row.sites), domains = JSON.parse(row.domains);
  return { tenant: row.tenant, sites, domains, source: row.source, restricted: !sites.includes('*') };
}
