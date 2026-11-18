// CG-053 Remote access only through a Zero Trust gateway or a VPN, with device restrictions.
// - loopback (default): only 127.0.0.1 / localhost / [::1], from the machine itself.
// - ztna: CyberGuard stays on loopback behind the gateway connector (for example cloudflared, a ZTNA app connector or a
//   reverse proxy on the same host). A request for a public host name is accepted only with the gateway's signed access
//   assertion (JWT) verified against the gateway JWKS for issuer and audience, and, when required, a device posture claim.
// - vpn: CyberGuard listens on the VPN interface address with TLS; only clients from the VPN address pools are accepted,
//   and with a device CA configured every client must present a device certificate issued by that CA (mutual TLS).
import { isIP } from 'node:net';
import { AppError, fail } from './common.js';
import { verifySignedJwt, checkIssuerUrl } from './oidc.js';
import { ipInCidr } from './vulnerability-intel.js';

const list = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
const loopbackIp = ip => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(String(ip));
const privateIp = ip => { const v = String(ip); if (isIP(v) === 4) { const p = v.split('.').map(Number); return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127); } return isIP(v) === 6 && /^f[cd]/i.test(v); };
const claimAt = (claims, dotted) => dotted.split('.').reduce((o, k) => (o == null ? undefined : o[k]), claims);

export function remoteAccessConfig(env = process.env, { tls = false, clientCa = false } = {}) {
  const mode = env.CG_REMOTE_ACCESS || 'loopback'; fail(['loopback', 'ztna', 'vpn'].includes(mode), 400, 'invalid_remote_access_mode');
  const cfg = { mode, public_hosts: list(env.CG_PUBLIC_HOSTS).map(h => h.toLowerCase()), ztna: null, vpn: null, device_certificates: clientCa };
  if (mode === 'ztna') {
    fail(cfg.public_hosts.length >= 1 && cfg.public_hosts.every(h => /^[a-z0-9.-]+(:\d+)?$/.test(h)), 400, 'ztna_requires_public_hosts');
    cfg.ztna = { issuer: checkIssuerUrl(env.CG_ZTNA_ISSUER || ''), audience: String(env.CG_ZTNA_AUDIENCE || ''), jwks_url: checkIssuerUrl(env.CG_ZTNA_JWKS_URL || ''), header: String(env.CG_ZTNA_HEADER || 'cf-access-jwt-assertion').toLowerCase(), device_claim: env.CG_ZTNA_DEVICE_CLAIM || null, device_value: env.CG_ZTNA_DEVICE_VALUE ?? null };
    fail(cfg.ztna.audience.length >= 1, 400, 'ztna_requires_audience');
  }
  if (mode === 'vpn') {
    fail(tls, 400, 'vpn_access_requires_tls'); const host = String(env.CG_LISTEN_HOST || ''), cidrs = list(env.CG_VPN_CIDRS);
    fail(isIP(host) && privateIp(host), 400, 'vpn_listen_host_must_be_a_private_vpn_address'); fail(cidrs.length >= 1 && cidrs.every(c => isIP(c.split('/')[0]) && /^\d+$/.test(c.split('/')[1] || '')), 400, 'vpn_requires_client_cidrs');
    cfg.vpn = { listen_host: host, cidrs };
  }
  return cfg;
}

export class RemoteAccessGate {
  constructor(cfg, { fetchJwks = null } = {}) { this.cfg = cfg; this.keys = null; this.fetchJwks = fetchJwks || (async url => { const r = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) }); fail(r.ok, 502, 'ztna_jwks_unavailable'); const j = await r.json(); fail(Array.isArray(j.keys), 502, 'ztna_jwks_unavailable'); return j.keys; }); }
  // Returns how the request arrived ({via, identity, device}) or throws 403 with the reason.
  async check(req, port) {
    const hostHeader = String(req.headers.host || '').toLowerCase(), remote = req.socket.remoteAddress;
    if ([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(hostHeader)) { fail(loopbackIp(remote), 403, 'loopback_host_from_remote_address'); return { via: 'loopback', identity: null, device: null }; }
    const { mode } = this.cfg;
    if (mode === 'ztna' && this.cfg.public_hosts.includes(hostHeader.replace(/:443$/, ''))) {
      fail(loopbackIp(remote), 403, 'ztna_traffic_must_come_from_the_local_connector');
      const z = this.cfg.ztna, token = req.headers[z.header]; fail(typeof token === 'string' && token.length < 16384, 403, 'ztna_assertion_required');
      let claims; try { this.keys ||= await this.fetchJwks(z.jwks_url); claims = verifySignedJwt(token, this.keys, 'ztna'); } catch (e) { if (e.code !== 'ztna_unknown_signing_key') throw new AppError(403, e.code || 'ztna_assertion_invalid'); this.keys = await this.fetchJwks(z.jwks_url); try { claims = verifySignedJwt(token, this.keys, 'ztna'); } catch (e2) { throw new AppError(403, e2.code || 'ztna_assertion_invalid'); } }
      const sec = Math.floor(Date.now() / 1000), aud = [].concat(claims.aud || []);
      fail(claims.iss === z.issuer, 403, 'ztna_issuer_mismatch'); fail(aud.includes(z.audience), 403, 'ztna_audience_mismatch'); fail(Number.isFinite(claims.exp) && claims.exp > sec - 30, 403, 'ztna_assertion_expired');
      let device = null; if (z.device_claim) { device = claimAt(claims, z.device_claim); fail(z.device_value === null ? Boolean(device) && device !== 'false' : String(device) === String(z.device_value), 403, 'device_not_compliant'); }
      return { via: 'ztna', identity: String(claims.email || claims.sub || ''), device: device === undefined ? null : device };
    }
    if (mode === 'vpn') {
      const [h, p] = hostHeader.startsWith('[') ? [hostHeader.slice(1, hostHeader.indexOf(']')), hostHeader.split(']:')[1]] : hostHeader.split(':');
      fail((h === this.cfg.vpn.listen_host || this.cfg.public_hosts.includes(h)) && Number(p || 443) === port, 403, 'host_not_allowed');
      const ip = String(remote).replace(/^::ffff:/, ''); fail(this.cfg.vpn.cidrs.some(c => ipInCidr(ip, c)), 403, 'source_outside_vpn_pool');
      let device = null; if (this.cfg.device_certificates) { fail(req.socket.authorized === true, 403, 'device_certificate_required'); device = req.socket.getPeerCertificate()?.subject?.CN || null; }
      return { via: 'vpn', identity: null, device };
    }
    throw new AppError(403, 'host_not_allowed');
  }
  summary() { const c = this.cfg; return { mode: c.mode, public_hosts: c.public_hosts, ztna: c.ztna ? { issuer: c.ztna.issuer, audience: c.ztna.audience, header: c.ztna.header, device_claim: c.ztna.device_claim, device_value: c.ztna.device_value } : null, vpn: c.vpn, device_certificates: c.device_certificates }; }
}
