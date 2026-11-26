// CG-129 Budget and capacity model. Inputs are the planned event rate and retention; the per-event cost of storage and
// CPU comes from the measured capacity profile (scripts/capacity-benchmark.js), not from assumptions. Cloud and API cost
// is computed only from unit prices the operator enters, because prices differ per contract and region.
import fs from 'node:fs';
import { fail } from './common.js';

const HEADROOM = 2; // capacity planned at half of the measured maximum so detection keeps up during bursts
export function loadProfile(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
const num = (v, name, min, max, optional = true) => { if ((v === undefined || v === null || v === '') && optional) return null; const n = Number(v); fail(Number.isFinite(n) && n >= min && n <= max, 400, `invalid_${name}`); return n; };
export function plan(input, profile) {
  fail(profile, 409, 'capacity_profile_missing_run_capacity_benchmark');
  const eps = num(input.eps, 'eps', 1, 10000000, false), retention = num(input.retention_days, 'retention_days', 1, 3650, false), sources = num(input.sources, 'sources', 0, 100000) ?? 0;
  const perDayEvents = eps * 86400, gbPerDay = perDayEvents * profile.bytes_per_event / 1e9, storageGb = gbPerDay * retention;
  const cores = Math.max(1, Math.ceil(eps * HEADROOM / profile.eps_per_cpu_core)), memoryGb = Math.max(2, Math.ceil((profile.rss_mb / 1024) * Math.max(1, eps / profile.eps) * HEADROOM + 1));
  const prices = { storage_gb_month: num(input.price_storage_gb_month, 'price_storage_gb_month', 0, 1000), api_call: num(input.price_api_call, 'price_api_call', 0, 100), ai_1k_tokens: num(input.price_ai_1k_tokens, 'price_ai_1k_tokens', 0, 1000) };
  const apiCalls = num(input.api_calls_per_day, 'api_calls_per_day', 0, 1e9) ?? 0, aiAnalyses = num(input.ai_analyses_per_day, 'ai_analyses_per_day', 0, 100000) ?? 0, aiTokens = aiAnalyses * 600;
  const monthly = { storage: prices.storage_gb_month === null ? null : Math.round(storageGb * prices.storage_gb_month * 100) / 100, api: prices.api_call === null ? null : Math.round(apiCalls * 30 * prices.api_call * 100) / 100, ai: prices.ai_1k_tokens === null ? null : Math.round(aiTokens * 30 / 1000 * prices.ai_1k_tokens * 100) / 100 };
  const single = eps * HEADROOM <= profile.eps;
  return { inputs: { eps, retention_days: retention, sources, api_calls_per_day: apiCalls, ai_analyses_per_day: aiAnalyses },
    volume: { events_per_day: perDayEvents, gb_per_day: Math.round(gbPerDay * 100) / 100, storage_gb_for_retention: Math.round(storageGb * 10) / 10 },
    compute: { cpu_cores: cores, memory_gb: memoryGb, gpu: 'not required: the analyst is local and deterministic; a cloud model is optional and billed per token', fits_one_measured_node: single, headroom_factor: HEADROOM },
    cost_monthly: { ...monthly, ai_tokens_per_month: aiTokens * 30, total: Object.values(monthly).every(v => v === null) ? null : Math.round(Object.values(monthly).reduce((a, v) => a + (v || 0), 0) * 100) / 100, currency_note: 'In the currency of the unit prices entered; empty when no price was entered.' },
    basis: { profile_measured_at: profile.measured_at, machine: profile.machine, measured_eps: profile.eps, bytes_per_event: profile.bytes_per_event, eps_per_cpu_core: profile.eps_per_cpu_core, detection_reliability_under_load: profile.detection_under_load.reliability },
    reliability_guard: profile.detection_under_load.reliability === 1 ? (single ? 'Planned load is within half of the measured maximum on which every injected attack was detected.' : 'Planned load exceeds one measured node: split sources across collectors or tenants (CG-059) before relying on detection at this rate.') : 'The last benchmark missed detections under load: do not raise the rate until it passes.' };
}
// What this installation actually receives now, and when its storage limit is reached at that rate.
export function live(store, { maxDbMb, dbBytes, retentionDays }) {
  const since = new Date(Date.now() - 86400000).toISOString(), rows = store.all("SELECT kind,payload FROM events WHERE received_at>=?", since);
  const events = rows.reduce((n, r) => n + (r.kind === 'log.batch' ? (JSON.parse(r.payload).details.record_count || 0) : 1), 0), perDayBytes = rows.reduce((n, r) => n + r.payload.length, 0);
  const daysLeft = perDayBytes > 0 ? Math.floor((maxDbMb * 1048576 - dbBytes) / perDayBytes) : null;
  return { events_last_24h: events, average_eps: Math.round(events / 86400 * 100) / 100, stored_bytes_last_24h: perDayBytes, database_mb: Math.round(dbBytes / 1048576 * 10) / 10, max_database_mb: maxDbMb, retention_days: retentionDays, days_until_storage_limit: daysLeft };
}
