// CG-052 OpenID Connect single sign-on: authorization code flow with PKCE (S256), state and nonce, ID token signature
// verification against the provider JWKS (RS256, PS256, ES256), issuer/audience/time/nonce/tenant checks and a required
// multi-factor claim (RFC 8176 amr or a configured acr). No client secret is stored: only the name of the environment
// variable that holds it.
import { createHash, createPublicKey, randomBytes, verify as verifySig, constants } from 'node:crypto';
import { AppError, fail } from './common.js';

export const b64url = buf => Buffer.from(buf).toString('base64url');
export const pkcePair = () => { const verifier = b64url(randomBytes(32)); return { verifier, challenge: b64url(createHash('sha256').update(verifier).digest()) }; };
const loopback = u => ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
export function checkIssuerUrl(value) {
  let u; try { u = new URL(value); } catch { throw new AppError(400, 'invalid_sso_issuer'); }
  fail(u.protocol === 'https:' || (u.protocol === 'http:' && loopback(u)), 400, 'sso_issuer_must_use_https');
  fail(!u.username && !u.password && !u.search && !u.hash, 400, 'invalid_sso_issuer'); return u.href.replace(/\/$/, '');
}
async function getJson(url, init = {}) {
  const res = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) });
  fail(res.ok, 502, `sso_provider_http_${res.status}`); const t = await res.text(); fail(t.length < 512 * 1024, 502, 'sso_provider_response_too_large');
  try { return JSON.parse(t); } catch { throw new AppError(502, 'sso_provider_invalid_json'); }
}
export async function discover(issuer) {
  const d = await getJson(`${issuer}/.well-known/openid-configuration`);
  fail(d.issuer === issuer || d.issuer === `${issuer}/`, 502, 'sso_discovery_issuer_mismatch');
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) checkIssuerUrl(d[k] || '');
  fail((d.code_challenge_methods_supported || ['S256']).includes('S256'), 502, 'sso_provider_without_pkce_s256');
  return { authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint, jwks_uri: d.jwks_uri };
}
export const fetchJwks = uri => getJson(uri).then(j => { fail(Array.isArray(j.keys) && j.keys.length <= 50, 502, 'sso_invalid_jwks'); return j.keys; });
export async function exchangeCode({ tokenEndpoint, code, redirectUri, clientId, verifier, clientSecret }) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, ...(clientSecret ? { client_secret: clientSecret } : {}) });
  const t = await getJson(tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
  fail(typeof t.id_token === 'string' && t.id_token.length < 16384, 502, 'sso_token_response_without_id_token'); return t.id_token;
}
const algs = { RS256: { hash: 'sha256', kty: 'RSA' }, PS256: { hash: 'sha256', kty: 'RSA', padding: constants.RSA_PKCS1_PSS_PADDING }, ES256: { hash: 'sha256', kty: 'EC', dsa: 'ieee-p1363' } };
// Check a JWS signature against a JWKS and return the claims; `prefix` names the error codes (sso_..., ztna_...).
export function verifySignedJwt(token, keys, prefix = 'sso') {
  const parts = String(token).split('.'); fail(parts.length === 3, 401, `${prefix}_malformed_token`);
  let header, claims; try { header = JSON.parse(Buffer.from(parts[0], 'base64url')); claims = JSON.parse(Buffer.from(parts[1], 'base64url')); } catch { throw new AppError(401, `${prefix}_malformed_token`); }
  const alg = algs[header.alg]; fail(alg, 401, `${prefix}_unsupported_algorithm`);
  const jwk = keys.find(k => k.kid === header.kid && (!k.use || k.use === 'sig') && k.kty === alg.kty); fail(jwk, 401, `${prefix}_unknown_signing_key`);
  const ok = verifySig(alg.hash, Buffer.from(`${parts[0]}.${parts[1]}`), { key: createPublicKey({ key: jwk, format: 'jwk' }), ...(alg.padding ? { padding: alg.padding, saltLength: 32 } : {}), ...(alg.dsa ? { dsaEncoding: alg.dsa } : {}) }, Buffer.from(parts[2], 'base64url'));
  fail(ok, 401, `${prefix}_invalid_signature`);
  return claims;
}
// Verify an ID token and return its claims, or throw with the reason.
export function verifyIdToken(idToken, { keys, issuer, clientId, nonce, now = Date.now(), tenant = null, tenantClaim = 'tid', mfaAmr = ['mfa'], mfaAcr = [] }) {
  const claims = verifySignedJwt(idToken, keys, 'sso');
  const sec = Math.floor(now / 1000), aud = [].concat(claims.aud || []);
  fail(claims.iss === issuer, 401, 'sso_issuer_mismatch'); fail(aud.includes(clientId) && (aud.length === 1 || claims.azp === clientId), 401, 'sso_audience_mismatch');
  fail(Number.isFinite(claims.exp) && claims.exp > sec - 60, 401, 'sso_token_expired'); fail(!Number.isFinite(claims.iat) || claims.iat <= sec + 60, 401, 'sso_token_from_the_future');
  fail(claims.nonce === nonce, 401, 'sso_nonce_mismatch'); fail(typeof claims.sub === 'string' && claims.sub.length > 0 && claims.sub.length <= 255, 401, 'sso_missing_subject');
  if (tenant) fail(claims[tenantClaim] === tenant, 403, 'sso_tenant_mismatch');
  const amr = [].concat(claims.amr || []), mfa = amr.some(v => mfaAmr.includes(v)) || (mfaAcr.length && mfaAcr.includes(claims.acr));
  fail(mfa, 403, 'sso_mfa_required');
  return claims;
}
