// CG-059 Run several isolated tenants on one host (Windows, macOS or Linux without systemd). Each tenant is a separate
// CyberGuard process with its own data directory (database, secret-store key, audit chain, setup token) and port.
//   node scripts/tenants.js add <tenant-id> --port <port> [--root <dir>]
//   node scripts/tenants.js list [--root <dir>]
//   node scripts/tenants.js run  [--root <dir>]          (starts every tenant; Ctrl+C stops them)
// On Linux with systemd use deploy/linux/add-tenant.sh instead (one service user per tenant).
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TENANT_ID } from '../lib/tenancy.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const root = path.resolve(flag('--root') || path.join(ROOT, 'tenants')), registryFile = path.join(root, 'tenants.json');
const load = () => fs.existsSync(registryFile) ? JSON.parse(fs.readFileSync(registryFile, 'utf8')) : { schema_version: 'cg.tenants/1', tenants: [] };
const die = m => { console.error(m); process.exit(2); };
const [command, id] = args;
if (command === 'add') {
  if (!TENANT_ID.test(id || '')) die('tenant id: 3-40 lowercase letters, digits or dashes');
  const port = Number(flag('--port')); if (!Number.isInteger(port) || port < 1024 || port > 65535) die('--port 1024-65535');
  const reg = load();
  if (reg.tenants.some(t => t.tenant === id)) die(`tenant ${id} already exists`);
  if (reg.tenants.some(t => t.port === port)) die(`port ${port} is already used by ${reg.tenants.find(t => t.port === port).tenant}`);
  const dataDir = path.join(root, id); fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  reg.tenants.push({ tenant: id, port, data_dir: id, added_at: new Date().toISOString() });
  fs.mkdirSync(root, { recursive: true, mode: 0o700 }); fs.writeFileSync(registryFile, JSON.stringify(reg, null, 2) + '\n', { mode: 0o600 });
  console.log(`Added tenant ${id}: port ${port}, data ${dataDir}`);
} else if (command === 'list') {
  console.log(JSON.stringify(load().tenants.map(t => ({ ...t, data_dir: path.join(root, t.data_dir) })), null, 2));
} else if (command === 'run') {
  const tenants = load().tenants; if (!tenants.length) die('no tenants; add one with: node scripts/tenants.js add <tenant-id> --port <port>');
  const children = tenants.map(t => {
    const env = { ...process.env, CG_TENANT: t.tenant, CG_PORT: String(t.port), CG_DATA_DIR: path.join(root, t.data_dir) };
    const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', d => process.stdout.write(String(d).split('\n').filter(Boolean).map(l => `[${t.tenant}] ${l}\n`).join('')));
    child.on('exit', code => console.log(`[${t.tenant}] stopped (${code})`));
    return child;
  });
  for (const s of ['SIGINT', 'SIGTERM']) process.once(s, () => { for (const c of children) c.kill('SIGTERM'); });
} else die('usage: node scripts/tenants.js add <tenant-id> --port <port> | list | run [--root <dir>]');
