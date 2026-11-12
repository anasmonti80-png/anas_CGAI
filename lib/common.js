import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export class AppError extends Error {
  constructor(status, code, message = code) { super(message); this.status = status; this.code = code; }
}
export const fail = (condition, status, code) => { if (!condition) throw new AppError(status, code); };
export const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
export const token = () => randomBytes(32).toString('base64url');
export function equal(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}
export function text(value, name, max = 200, optional = false) {
  if (optional && (value === undefined || value === null || value === '')) return null;
  fail(typeof value === 'string' && value.trim().length > 0 && value.length <= max && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value), 400, `invalid_${name}`);
  return value.trim();
}
export function choice(value, values, name) { fail(values.includes(value),400,`invalid_${name}`); return value; }
export function integer(value, min, max, name) { fail(Number.isInteger(value) && value >= min && value <= max,400,`invalid_${name}`); return value; }
export function object(value, keys, name) {
  fail(value && typeof value === 'object' && !Array.isArray(value),400,`invalid_${name}`);
  fail(Object.keys(value).every(k => keys.includes(k)),400,`unknown_${name}_field`);
  return value;
}
export function timestamp(value, name, now = Date.now()) {
  fail(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value),400,`invalid_${name}`);
  const date = Date.parse(value);
  fail(Number.isFinite(date) && date >= Date.UTC(2000,0,1) && date <= now + 300000,400,`invalid_${name}`);
  fail(new Date(date).toISOString().slice(0,19)===value.slice(0,19),400,`invalid_${name}`);
  return new Date(date).toISOString();
}
export function redact(value) {
  if (typeof value === 'string') return value
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/gi,'[REDACTED PRIVATE KEY]')
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.\-]+/gi,'[REDACTED AUTHORIZATION]')
    .replace(/\b(password|passwd|secret|token|api[_-]?key|authorization|cookie|community)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,'$1=[REDACTED]');
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, /password|passwd|secret|token|api.?key|authorization|cookie|community|private.?key/i.test(k)&&k!=='authorization_ref' ? '[REDACTED]' : redact(v)]));
  return value;
}
export function page(params) {
  const limit = Number(params.get('limit') || 25), offset = Number(params.get('offset') || 0);
  integer(limit,1,100,'limit'); integer(offset,0,1000000,'offset');
  const q = String(params.get('q') || '').slice(0,150);
  return {limit,offset,q};
}
