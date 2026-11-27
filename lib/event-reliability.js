// CG-168 Event volume and detection reliability, per hour over the last 24 hours:
//  - input, processed, rejected, duplicate and late events and their rates per second (EPS); late means received more
//    than five minutes after it was observed;
//  - batch processing time (validation, storage and correlation of one batch) and queue lag reported by store-and-forward
//    senders (CG-060);
//  - parser errors: batches refused by validation (CG-162) by code, and log lines no parser recognised;
//  - detection time: from the first evidence event being observed to the alert being raised, and from receipt to alert;
//  - the effect of the data rate: detection time in the busier half of the hours compared with the quieter half.
// CG-PIPELINE-168 alerts when the last hour refuses more than 5% of input, has more than 10% late events, or its p95
// detection time from receipt exceeds five minutes.
const q = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
export const LATE_SECONDS = 300;

export function reliability(store, { clock = () => Date.now(), hours = 24 } = {}) {
  const now = clock(), start = now - hours * 3600000, iso = new Date(start).toISOString(), hourOf = t => Math.floor((Date.parse(t) - start) / 3600000);
  const buckets = Array.from({ length: hours }, (_, i) => ({ hour: new Date(start + i * 3600000).toISOString(), input: 0, processed: 0, rejected: 0, duplicates: 0, late: 0, batches: 0, processing_ms: [], detection_s: [], pipeline_s: [], alerts: 0 }));
  const at = t => { const ms = Date.parse(t), h = ms === now ? hours - 1 : hourOf(t); return ms <= now && h >= 0 && h < hours ? buckets[h] : null; };
  for (const b of store.all('SELECT at,accepted,duplicates,processing_ms FROM ingest_batches WHERE at>=?', iso)) { const k = at(b.at); if (!k) continue; k.batches++; k.processed += b.accepted; k.duplicates += b.duplicates; k.input += b.accepted + b.duplicates; k.processing_ms.push(b.processing_ms); }
  for (const r of store.all('SELECT at,events FROM ingest_rejections WHERE at>=?', iso)) { const k = at(r.at); if (k) { k.rejected += r.events; k.input += r.events; } }
  for (const e of store.all("SELECT observed_at,received_at FROM events WHERE received_at>=? AND kind!='visibility.loss'", iso)) { const k = at(e.received_at); if (k && (Date.parse(e.received_at) - Date.parse(e.observed_at)) / 1000 > LATE_SECONDS) k.late++; }
  for (const a of store.all('SELECT first_seen,evidence_ids FROM alerts WHERE first_seen>=?', iso)) { const k = at(a.first_seen); if (!k) continue; k.alerts++;
    const ev = JSON.parse(a.evidence_ids)[0], e = ev && store.get('SELECT observed_at,received_at FROM events WHERE id=?', ev); if (!e) continue;
    k.detection_s.push(Math.max(0, (Date.parse(a.first_seen) - Date.parse(e.observed_at)) / 1000)); k.pipeline_s.push(Math.max(0, (Date.parse(a.first_seen) - Date.parse(e.received_at)) / 1000)); }
  const rate = n => Math.round(n / 3600 * 1000) / 1000, r1 = v => v === null ? null : Math.round(v * 10) / 10;
  const rows = buckets.map(b => ({ hour: b.hour, input: b.input, processed: b.processed, rejected: b.rejected, duplicates: b.duplicates, late: b.late, batches: b.batches, alerts: b.alerts,
    eps: { input: rate(b.input), processed: rate(b.processed), rejected: rate(b.rejected), late: rate(b.late) }, processing_ms_p95: q(b.processing_ms, 0.95), detection_s_p50: r1(q(b.detection_s, 0.5)), detection_s_p95: r1(q(b.detection_s, 0.95)), pipeline_s_p95: r1(q(b.pipeline_s, 0.95)), _d: b.detection_s, _p: b.pipeline_s }));
  // Rate effect: hours with alerts split at the median input rate.
  // Hours with alerts ranked by input: the busier half against the quieter half.
  const ranked = rows.filter(r => r._p.length).sort((a, b) => b.input - a.input), half = Math.ceil(ranked.length / 2), busyH = ranked.length > 1 ? ranked.slice(0, half) : [], quietH = ranked.length > 1 ? ranked.slice(half) : [];
  const busy = busyH.flatMap(r => r._p), quiet = quietH.flatMap(r => r._p);
  const busyP = q(busy, 0.5), quietP = q(quiet, 0.5), ratio = busyP !== null && quietP !== null ? Math.round((busyP + 1) / (quietP + 1) * 100) / 100 : null;
  const rate_effect = { busy_hours: busyH.length, quiet_hours: quietH.length, busy_pipeline_s_p50: r1(busyP), quiet_pipeline_s_p50: r1(quietP), ratio, verdict: ratio === null ? 'not-enough-data' : ratio <= 1.5 ? 'stable' : 'slower-when-busy' };
  const last = rows.at(-1), issues = [];
  if (last.input && last.rejected / last.input > 0.05) issues.push('rejected-over-5-percent');
  if (last.processed && last.late / last.processed > 0.1) issues.push('late-over-10-percent');
  if (last.pipeline_s_p95 !== null && last.pipeline_s_p95 > 300) issues.push('detection-over-5-minutes');
  const queues = store.all('SELECT d.source_id,s.name,d.queue_depth,d.oldest_queued_at,d.delivery_attempt,d.reported_at,d.max_delay_minutes FROM source_delivery d JOIN sources s ON s.id=d.source_id ORDER BY d.max_delay_minutes DESC')
    .map(r => ({ ...r, lag_minutes: r.oldest_queued_at ? Math.max(0, Math.round((now - Date.parse(r.oldest_queued_at)) / 60000)) : 0 }));
  const parser = { refused: store.all('SELECT code,SUM(events) events,COUNT(*) batches FROM ingest_rejections WHERE at>=? GROUP BY code ORDER BY events DESC', iso),
    log_lines: store.all("SELECT payload FROM events WHERE kind='log.batch' AND received_at>=?", iso).reduce((a, r) => { const d = JSON.parse(r.payload).details; return { lines: a.lines + d.line_count, unrecognised: a.unrecognised + d.rejected_count }; }, { lines: 0, unrecognised: 0 }) };
  const total = k => rows.reduce((n, r) => n + r[k], 0);
  return { hours: rows.map(({ _d, _p, ...r }) => r), totals: { input: total('input'), processed: total('processed'), rejected: total('rejected'), duplicates: total('duplicates'), late: total('late'), alerts: total('alerts') }, late_seconds: LATE_SECONDS, queues, parser, rate_effect, last_hour_issues: issues,
    claim: 'Event volume and detection reliability are measured, not assumed: input, processed, rejected, duplicate and late events per hour and per second, batch processing time, queue lag from senders, parser refusals and unrecognised log lines, and the time from an event to its alert, compared between busy and quiet hours.',
    claim_ar: 'يُقاس حجم الأحداث وموثوقية الكشف ولا يُفترض: الأحداث المدخلة والمعالجة والمرفوضة والمكررة والمتأخرة لكل ساعة ولكل ثانية، وزمن معالجة الدفعة، وتأخر الطوابير لدى المرسلين، ورفض المحلل والسطور غير المعروفة، والزمن من الحدث إلى تنبيهه، مع مقارنته بين الساعات المزدحمة والهادئة.' };
}
