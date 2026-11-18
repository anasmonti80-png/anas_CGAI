// CG-060 Store-and-forward delivery for collectors and converters that run where CyberGuard may be unreachable.
// Files wait in a durable local queue (spool/outbox), are sent in order with exponential backoff and jitter while the
// server or network is down, and are safe to resend: the server stores each (source, event_id) once and answers a
// repeat as a duplicate, so a response lost in an outage never creates a second copy. A file the server refuses for a
// content reason (4xx other than 408/429) is moved to spool/rejected with the reason, never retried forever or dropped.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { MAX_INGEST_BYTES } from './common.js';

const RETRYABLE = s => s === 408 || s === 429 || s >= 500;
export class Forwarder {
  constructor({ spool, url, sourceId, token, fetchImpl = fetch, clock = () => Date.now(), random = Math.random, baseDelayMs = 2000, maxDelayMs = 300000, maxQueueFiles = 10000 }) {
    if (!/^[a-f0-9-]{36}$/.test(sourceId || '')) throw new Error('source id required');
    if (!token) throw new Error('source token required (CG_SOURCE_TOKEN)');
    Object.assign(this, { spool, url: String(url).replace(/\/$/, ''), sourceId, token, fetchImpl, clock, random, baseDelayMs, maxDelayMs, maxQueueFiles });
    for (const d of ['outbox', 'sent', 'rejected']) fs.mkdirSync(path.join(spool, d), { recursive: true, mode: 0o700 });
  }
  dir(name) { return path.join(this.spool, name); }
  state() { try { return JSON.parse(fs.readFileSync(this.dir('state.json'), 'utf8')); } catch { return { attempts: 0, next_attempt_at: null, last_error: null, delivered_files: 0, rejected_files: 0 }; } }
  saveState(s) { const tmp = this.dir(`state.${randomBytes(4).toString('hex')}.tmp`); fs.writeFileSync(tmp, JSON.stringify(s, null, 2), { mode: 0o600 }); fs.renameSync(tmp, this.dir('state.json')); }
  queued() { return fs.readdirSync(this.dir('outbox')).filter(f => f.endsWith('.json')).sort(); }
  // Atomic enqueue: written to a temporary name, then renamed, so a crash never leaves half a file in the queue.
  enqueue(batch) {
    const text = typeof batch === 'string' ? batch : JSON.stringify(batch), parsed = JSON.parse(text);
    if (parsed.schema_version !== 'cg.telemetry/1' && parsed.schema_version !== 'cg.windows-export/1') throw new Error('unsupported schema_version');
    if (Buffer.byteLength(text) > MAX_INGEST_BYTES) throw new Error('file larger than the ingest limit; split it');
    if (this.queued().length >= this.maxQueueFiles) throw new Error('queue full; delivery has been failing, check the server and the source token');
    const name = `${new Date(this.clock()).toISOString().replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}.json`, tmp = this.dir(`outbox/${name}.tmp`);
    fs.writeFileSync(tmp, text, { mode: 0o600 }); fs.renameSync(tmp, this.dir(`outbox/${name}`)); return name;
  }
  depth() {
    const files = this.queued(); let bytes = 0; for (const f of files) bytes += fs.statSync(this.dir(`outbox/${f}`)).size;
    const m = files[0] && files[0].match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z/), oldest = m ? `${m[1]}T${m[2]}:${m[3]}:${m[4]}.${m[5]}Z` : null;
    return { files: files.length, bytes, oldest_queued_at: oldest };
  }
  delay(attempts) { const d = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** Math.max(0, attempts - 1)); return Math.round(d * (0.5 + this.random() * 0.5)); }
  // X-CG-Queue-Depth is what remains queued behind this file; X-CG-Oldest-Queued-At is when this file (the oldest) was queued.
  // One pass over the queue in order. Stops at the first retryable failure so later files never overtake earlier ones.
  async drainOnce() {
    const state = this.state(), now = this.clock();
    if (state.next_attempt_at && now < Date.parse(state.next_attempt_at)) return { status: 'waiting', next_attempt_at: state.next_attempt_at, ...this.depth() };
    let delivered = 0, rejected = 0, duplicates = 0;
    for (const f of this.queued()) {
      const file = this.dir(`outbox/${f}`), body = fs.readFileSync(file, 'utf8'), depth = this.depth();
      let status = 0, result = null, error = null;
      try {
        const r = await this.fetchImpl(`${this.url}/api/sources/${this.sourceId}/events`, { method: 'POST', headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json', 'X-CG-Queue-Depth': String(depth.files - 1), 'X-CG-Oldest-Queued-At': depth.oldest_queued_at || '', 'X-CG-Delivery-Attempt': String(state.attempts + 1) }, body });
        status = r.status; try { result = await r.json(); } catch { result = null; }
      } catch (e) { error = e.cause?.code || e.code || e.message; }
      if (status >= 200 && status < 300) {
        fs.appendFileSync(this.dir('sent/receipts.jsonl'), JSON.stringify({ file: f, at: new Date(this.clock()).toISOString(), accepted: result?.accepted ?? null, duplicates: result?.duplicates ?? null }) + '\n', { mode: 0o600 });
        fs.unlinkSync(file); delivered++; duplicates += result?.duplicates || 0; state.attempts = 0; state.next_attempt_at = null; state.last_error = null; state.delivered_files++; continue;
      }
      if (status && !RETRYABLE(status)) {
        fs.renameSync(file, this.dir(`rejected/${f}`)); fs.writeFileSync(this.dir(`rejected/${f}.reason.txt`), `${status} ${result?.error || 'refused'}\n`, { mode: 0o600 }); rejected++; state.rejected_files++; continue;
      }
      state.attempts++; state.last_error = error || `${status} ${result?.error || ''}`.trim(); state.next_attempt_at = new Date(this.clock() + this.delay(state.attempts)).toISOString();
      this.saveState(state); return { status: 'backoff', delivered, rejected, duplicates, attempts: state.attempts, last_error: state.last_error, next_attempt_at: state.next_attempt_at, ...this.depth() };
    }
    this.saveState(state); return { status: 'drained', delivered, rejected, duplicates, ...this.depth() };
  }
}
