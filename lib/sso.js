// CG-052 SSO service: provider configuration, login start (state, nonce, PKCE), callback (code exchange, ID token
// verification, MFA claim) and least-privilege mapping of IdP groups to a CyberGuard role and tenant/site scope.
import { randomUUID, randomBytes } from 'node:crypto';
import { AppError, fail, text, choice, digest } from './common.js';
import { checkIssuerUrl, discover, fetchJwks, exchangeCode, verifyIdToken, pkcePair, b64url } from './oidc.js';

const rank = { viewer: 0, analyst: 1, admin: 2 };
export class Sso {
  constructor(store, auth, { clock = () => Date.now(), tenant = 'default' } = {}) { this.store = store; this.auth = auth; this.clock = clock; this.tenant = tenant; this.jwks = null; }
  config() { const c = this.store.get('SELECT * FROM sso_config WHERE id=1'); return c ? { ...c, role_map: JSON.parse(c.role_map), mfa_amr: JSON.parse(c.mfa_amr), mfa_acr: JSON.parse(c.mfa_acr), enabled: Boolean(c.enabled) } : null; }
  publicStatus() { const c = this.config(); return { enabled: Boolean(c?.enabled), issuer: c?.issuer || null, claim: 'Single sign-on through an OpenID Connect provider (for example Microsoft Entra ID, Okta or Keycloak) with PKCE, a verified ID token and a required multi-factor claim; local password login remains for the first administrator and break-glass.', claim_ar: 'دخول موحد عبر مزود OpenID Connect (مثل Microsoft Entra ID أو Okta أو Keycloak) مع PKCE ورمز هوية موثق ومطالبة إلزامية بالتحقق متعدد العوامل؛ ويبقى الدخول المحلي بكلمة المرور للمسؤول الأول ولحالات الطوارئ.' }; }
  async configure(actor, input) {
    this.auth.requireRecentMfa(actor); fail((actor.base_role || actor.role) === 'admin', 403, 'insufficient_role');
    const issuer = checkIssuerUrl(text(input.issuer, 'sso_issuer', 500)), clientId = text(input.client_id, 'sso_client_id', 200);
    const secretEnv = input.client_secret_env == null ? null : text(input.client_secret_env, 'sso_client_secret_env', 100); fail(!secretEnv || /^[A-Z][A-Z0-9_]{2,99}$/.test(secretEnv), 400, 'sso_client_secret_env_must_be_an_environment_variable_name');
    fail(Array.isArray(input.role_map) && input.role_map.length >= 1 && input.role_map.length <= 100, 400, 'sso_role_map_required');
    const roleMap = input.role_map.map((m, i) => ({ group: text(m.group, `sso_role_map_${i}_group`, 200), role: choice(m.role, ['viewer', 'analyst', 'admin'], `sso_role_map_${i}_role`), tenant: (t => (fail(t === this.tenant, 400, `sso_role_map_${i}_tenant_is_not_this_installation`), t))(text(m.tenant ?? this.tenant, `sso_role_map_${i}_tenant`, 100)), sites: (fail(Array.isArray(m.sites ?? ['*']) && (m.sites ?? ['*']).length <= 100, 400, `invalid_sso_role_map_${i}_sites`), (m.sites ?? ['*']).map((s, k) => text(s, `sso_role_map_${i}_site_${k}`, 200))), domains: (fail(Array.isArray(m.domains ?? ['*']) && (m.domains ?? ['*']).length <= 20, 400, `invalid_sso_role_map_${i}_domains`), (m.domains ?? ['*']).map((s, k) => text(s, `sso_role_map_${i}_domain_${k}`, 50))) }));
    const mfaAmr = (input.mfa_amr ?? ['mfa']).map((v, i) => text(v, `sso_mfa_amr_${i}`, 50)), mfaAcr = (input.mfa_acr ?? []).map((v, i) => text(v, `sso_mfa_acr_${i}`, 200)); fail(mfaAmr.length + mfaAcr.length >= 1, 400, 'sso_mfa_claim_required');
    const endpoints = await discover(issuer), now = new Date(this.clock()).toISOString();
    this.store.transaction(() => {
      this.store.run('INSERT INTO sso_config VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?) ON CONFLICT(id) DO UPDATE SET issuer=excluded.issuer,client_id=excluded.client_id,client_secret_env=excluded.client_secret_env,authorization_endpoint=excluded.authorization_endpoint,token_endpoint=excluded.token_endpoint,jwks_uri=excluded.jwks_uri,tenant=excluded.tenant,tenant_claim=excluded.tenant_claim,groups_claim=excluded.groups_claim,role_map=excluded.role_map,mfa_amr=excluded.mfa_amr,mfa_acr=excluded.mfa_acr,enabled=1,updated_by=excluded.updated_by,updated_at=excluded.updated_at', issuer, clientId, secretEnv, endpoints.authorization_endpoint, endpoints.token_endpoint, endpoints.jwks_uri, input.tenant == null ? null : text(input.tenant, 'sso_tenant', 100), text(input.tenant_claim ?? 'tid', 'sso_tenant_claim', 50), text(input.groups_claim ?? 'groups', 'sso_groups_claim', 50), JSON.stringify(roleMap), JSON.stringify(mfaAmr), JSON.stringify(mfaAcr), actor.id, now);
      this.store.audit(actor.id, 'sso.configured', 'sso', { issuer, client_id: clientId, groups: roleMap.length }, now);
    });
    this.jwks = null; return this.publicStatus();
  }
  start(redirectUri) {
    const c = this.config(); fail(c?.enabled, 404, 'sso_not_configured');
    const state = b64url(randomBytes(24)), nonce = b64url(randomBytes(24)), { verifier, challenge } = pkcePair(), now = this.clock();
    this.store.run('DELETE FROM sso_states WHERE expires_at<?', now);
    fail(this.store.get('SELECT COUNT(*) n FROM sso_states').n < 200, 429, 'too_many_pending_sso_logins');
    this.store.run('INSERT INTO sso_states VALUES (?,?,?,?,?)', digest(state), nonce, verifier, redirectUri, now + 10 * 60000);
    const u = new URL(c.authorization_endpoint); for (const [k, v] of Object.entries({ response_type: 'code', client_id: c.client_id, redirect_uri: redirectUri, scope: 'openid profile email', state, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) u.searchParams.set(k, v);
    return u.href;
  }
  async callback({ code, state, error }) {
    fail(!error, 401, 'sso_provider_denied'); fail(typeof state === 'string' && state.length <= 100 && typeof code === 'string' && code.length <= 4096, 400, 'sso_invalid_callback');
    const c = this.config(); fail(c?.enabled, 404, 'sso_not_configured');
    const row = this.store.get('SELECT * FROM sso_states WHERE state_hash=?', digest(state)); this.store.run('DELETE FROM sso_states WHERE state_hash=?', digest(state));
    fail(row && row.expires_at > this.clock(), 401, 'sso_state_invalid_or_expired');
    const idToken = await exchangeCode({ tokenEndpoint: c.token_endpoint, code, redirectUri: row.redirect_uri, clientId: c.client_id, verifier: row.verifier, clientSecret: c.client_secret_env ? process.env[c.client_secret_env] || null : null });
    const opts = { issuer: c.issuer, clientId: c.client_id, nonce: row.nonce, now: this.clock(), tenant: c.tenant, tenantClaim: c.tenant_claim, mfaAmr: c.mfa_amr, mfaAcr: c.mfa_acr };
    let claims; try { this.jwks ||= await fetchJwks(c.jwks_uri); claims = verifyIdToken(idToken, { ...opts, keys: this.jwks }); }
    catch (e) { if (e.code !== 'sso_unknown_signing_key') { this.store.audit('anonymous', 'sso.denied', 'sso', { reason: e.code || 'error' }); throw e; } this.jwks = await fetchJwks(c.jwks_uri); try { claims = verifyIdToken(idToken, { ...opts, keys: this.jwks }); } catch (e2) { this.store.audit('anonymous', 'sso.denied', 'sso', { reason: e2.code || 'error' }); throw e2; } }
    const groups = [].concat(claims[c.groups_claim] || []).map(String), matched = c.role_map.filter(m => groups.includes(m.group));
    if (!matched.length) { this.store.audit('anonymous', 'sso.denied', 'sso', { reason: 'sso_no_role_mapping' }); throw new AppError(403, 'sso_no_role_mapping'); }
    // Least privilege: the highest mapped role; scope is the union of the sites and domains of the groups granting that role.
    const role = matched.reduce((r, m) => (rank[m.role] > rank[r] ? m.role : r), 'viewer'), top = matched.filter(m => m.role === role);
    fail(new Set(top.map(m => m.tenant)).size === 1, 403, 'sso_groups_span_tenants');
    const sites = top.some(m => m.sites.includes('*')) ? ['*'] : [...new Set(top.flatMap(m => m.sites))], domains = top.some(m => m.domains.includes('*')) ? ['*'] : [...new Set(top.flatMap(m => m.domains))];
    const now = this.clock(), iso = new Date(now).toISOString(), username = String(claims.preferred_username || claims.email || claims.sub).replace(/[^A-Za-z0-9_.@-]/g, '_').slice(0, 64);
    const user = this.store.transaction(() => {
      let link = this.store.get('SELECT * FROM sso_links WHERE issuer=? AND subject=?', c.issuer, claims.sub), u;
      if (link) { u = this.store.get('SELECT * FROM users WHERE id=?', link.user_id); this.store.run('UPDATE users SET role=? WHERE id=?', role, u.id); this.store.run('UPDATE sso_links SET last_login_at=? WHERE issuer=? AND subject=?', iso, c.issuer, claims.sub); }
      else { const id = randomUUID(), name = this.store.get('SELECT id FROM users WHERE username=?', username) ? `${username.slice(0, 55)}-${id.slice(0, 8)}` : username; fail(this.store.get('SELECT COUNT(*) n FROM users').n < 100, 409, 'user_limit');
        this.store.run('INSERT INTO users VALUES (?,?,?,?,?)', id, name, `sso-only$${randomBytes(16).toString('hex')}`, role, iso); this.store.run('INSERT INTO sso_links VALUES (?,?,?,?)', c.issuer, claims.sub, id, iso); this.store.audit('sso', 'user.created', id, { role, via: 'sso' }, iso); u = { id, username: name, role }; }
      this.store.run('INSERT INTO user_scopes VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET tenant=excluded.tenant,sites=excluded.sites,domains=excluded.domains,source=excluded.source,updated_by=excluded.updated_by,updated_at=excluded.updated_at', u.id, top[0].tenant, JSON.stringify(sites), JSON.stringify(domains), 'sso', 'sso', iso);
      return { ...u, role };
    });
    const authTime = Number.isFinite(claims.auth_time) ? claims.auth_time * 1000 : now, recent = authTime >= now - 5 * 60000;
    return this.auth.createSession(user, Math.min(authTime, now), recent ? 'oidc' : null, 'sso');
  }
}
