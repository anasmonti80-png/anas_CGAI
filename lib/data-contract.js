// CG-162 Event data contract. For every connector (source) CyberGuard shows:
//  - what the connector declares with its batches: connector and version, event source, time zone of the raw records
//    and clock source (contract object on POST /api/ingest);
//  - what is measured from stored events: schema versions, parser versions, raw event hash coverage (every stored event
//    keeps the SHA-256 of the record as received and, for parsed logs, of the raw line), field completeness per kind,
//    and the delay between observation and receipt;
//  - parse failure: batches and events refused by validation are recorded with their error code (they were invisible
//    before), and log batches report lines that no parser recognised. The failure rate is rejected / (accepted + rejected).
import { fail, object, text, choice } from './common.js';

export const CLOCK_SOURCES = ['ntp', 'ptp', 'cloud-provider', 'domain-time', 'host-unsynced', 'unknown'];
export function validateContract(c) {
  object(c, ['connector', 'connector_version', 'event_source', 'time_zone', 'clock_source'], 'contract');
  const tz = text(c.time_zone, 'contract_time_zone', 64);
  fail(tz === 'UTC' || /^[+-]\d\d:\d\d$/.test(tz) || (() => { try { new Intl.DateTimeFormat('en', { timeZone: tz }); return true; } catch { return false; } })(), 400, 'invalid_contract_time_zone');
  return { connector: text(c.connector, 'contract_connector', 100), connector_version: text(c.connector_version, 'contract_connector_version', 50), event_source: text(c.event_source, 'contract_event_source', 200), time_zone: tz, clock_source: choice(c.clock_source, CLOCK_SOURCES, 'contract_clock_source') };
}

const present = v => !(v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0));
const pct = (n, d) => d ? Math.round(n / d * 1000) / 10 : null;
const quantile = (xs, q) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(q * s.length))]; };

export function contractView(store, { clock = () => Date.now(), days = 30 } = {}) {
  const since = new Date(clock() - days * 86400000).toISOString();
  const sources = store.all('SELECT id,name,kind,revoked,last_received FROM sources ORDER BY name').map(src => {
    const contract = store.get('SELECT connector,connector_version,event_source,time_zone,clock_source,declared_at FROM source_contracts WHERE source_id=?', src.id) || null;
    const counts = store.all('SELECT kind,schema_version,parser_version,COUNT(*) n FROM events WHERE source_id=? AND received_at>=? GROUP BY kind,schema_version,parser_version', src.id, since);
    const accepted = counts.reduce((a, r) => a + r.n, 0);
    const rej = store.all('SELECT code,COUNT(*) batches,SUM(events) events FROM ingest_rejections WHERE source_id=? AND at>=? GROUP BY code ORDER BY events DESC', src.id, since), rejectedEvents = rej.reduce((a, r) => a + r.events, 0);
    const sample = store.all('SELECT kind,observed_at,received_at,original_sha256,payload FROM events WHERE source_id=? AND received_at>=? ORDER BY received_at DESC LIMIT 2000', src.id, since).map(r => ({ ...r, p: JSON.parse(r.payload) }));
    const byKind = new Map();
    for (const r of sample) { const k = byKind.get(r.kind) || { kind: r.kind, events: 0, fields: 0, filled: 0, asset_fields: 0, asset_filled: 0, missing: new Map() };
      k.events++; for (const [f, v] of Object.entries(r.p.details || {})) { k.fields++; if (present(v)) k.filled++; else k.missing.set(f, (k.missing.get(f) || 0) + 1); }
      for (const f of ['hostname', 'addresses']) { k.asset_fields++; if (present(r.p.asset?.[f])) k.asset_filled++; }
      byKind.set(r.kind, k); }
    const completeness = [...byKind.values()].map(k => ({ kind: k.kind, events: k.events, field_completeness: pct(k.filled, k.fields), asset_completeness: pct(k.asset_filled, k.asset_fields), most_missing: [...k.missing.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([field, n]) => ({ field, missing_pct: pct(n, k.events) })) }));
    const lags = sample.map(r => Math.round((Date.parse(r.received_at) - Date.parse(r.observed_at)) / 1000));
    const raw = sample.filter(r => /^[a-f0-9]{64}$/.test(r.original_sha256)).length, origin = sample.filter(r => r.p.origin?.raw_sha256).length;
    const logs = sample.filter(r => r.kind === 'log.batch').reduce((a, r) => ({ lines: a.lines + r.p.details.line_count, rejected: a.rejected + r.p.details.rejected_count }), { lines: 0, rejected: 0 });
    const failure = pct(rejectedEvents, accepted + rejectedEvents);
    const issues = [];
    if (!contract) issues.push('no-declared-contract');
    if (contract && ['host-unsynced', 'unknown'].includes(contract.clock_source)) issues.push('clock-source-unverified');
    if (failure !== null && failure > 1) issues.push('parse-failures');
    if (rej.some(r => r.code === 'invalid_observed_at')) issues.push('clock-ahead-or-invalid-time');
    if (logs.lines && pct(logs.rejected, logs.lines) > 5) issues.push('unparsed-log-lines');
    if (completeness.some(c => c.field_completeness !== null && c.field_completeness < 80)) issues.push('low-field-completeness');
    return { id: src.id, name: src.name, source_type: src.kind, revoked: !!src.revoked, last_received: src.last_received, contract,
      schema_versions: [...new Set(counts.map(r => r.schema_version))], parser_versions: [...new Set(counts.map(r => r.parser_version))], kinds: [...new Set(counts.map(r => r.kind))],
      accepted_events: accepted, rejected_events: rejectedEvents, rejected_batches: rej.reduce((a, r) => a + r.batches, 0), parse_failure_pct: failure, rejections: rej,
      raw_hash_pct: pct(raw, sample.length), raw_record_hash_pct: pct(origin, sample.length), log_lines: logs.lines, log_lines_unparsed_pct: pct(logs.rejected, logs.lines),
      completeness, delay_seconds: { median: quantile(lags, 0.5), p95: quantile(lags, 0.95), max: lags.length ? Math.max(...lags) : null }, sampled_events: sample.length, issues };
  });
  return { days, sources,
    claim: 'Each connector shows its declared data contract (connector version, event source, time zone and clock source) beside what is measured from stored events: schema and parser versions, raw event hash coverage, field completeness per kind, observation-to-receipt delay, and the parse failure rate from batches refused by validation and log lines no parser recognised.',
    claim_ar: 'يعرض كل موصل عقد بياناته المعلن (نسخة الموصل ومصدر الأحداث والمنطقة الزمنية ومصدر الساعة) بجانب ما يُقاس من الأحداث المخزنة: نسخ المخطط والمحلل، وتغطية بصمة الحدث الخام، واكتمال الحقول لكل نوع، والتأخر بين الرصد والاستلام، ونسبة فشل التحليل من الدفعات التي رفضها التحقق وسطور السجلات التي لم يتعرف عليها أي محلل.' };
}
