// CG-060 Store-and-forward delivery to CyberGuard with a durable local queue, retry with backoff and safe resend.
//   node scripts/forwarder.js enqueue <file.json>...  --spool <dir>
//   node scripts/forwarder.js status                   --spool <dir>
//   node scripts/forwarder.js run [--once]             --spool <dir> --url http://127.0.0.1:4310 --source <source-id>
// The source token is read only from the CG_SOURCE_TOKEN environment variable (never from arguments or files).
import fs from 'node:fs';
import { Forwarder } from '../lib/forwarder.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const [command] = args, spool = flag('--spool');
if (!spool) { console.error('--spool <dir> is required'); process.exit(2); }
const fwd = new Forwarder({ spool, url: flag('--url') || 'http://127.0.0.1:4310', sourceId: flag('--source') || '00000000-0000-0000-0000-000000000000', token: process.env.CG_SOURCE_TOKEN || (command === 'run' ? '' : 'not-used') });
if (command === 'enqueue') {
  const files = args.slice(1).filter((a, i, all) => !a.startsWith('--') && !(all[i - 1] || '').startsWith('--'));
  for (const f of files) console.log(`queued ${fwd.enqueue(fs.readFileSync(f, 'utf8'))}`);
} else if (command === 'status') {
  console.log(JSON.stringify({ ...fwd.depth(), ...fwd.state() }, null, 2));
} else if (command === 'run') {
  const once = args.includes('--once'); let stop = false; for (const s of ['SIGINT', 'SIGTERM']) process.once(s, () => { stop = true; });
  do {
    const r = await fwd.drainOnce(); console.log(JSON.stringify(r));
    if (once) process.exit(r.status === 'backoff' ? 1 : 0);
    const wait = r.next_attempt_at ? Math.max(1000, Date.parse(r.next_attempt_at) - Date.now()) : 5000;
    await new Promise(res => setTimeout(res, wait));
  } while (!stop);
} else { console.error('usage: forwarder.js enqueue <file>... | status | run [--once]  (--spool <dir> --url <url> --source <id>)'); process.exit(2); }
