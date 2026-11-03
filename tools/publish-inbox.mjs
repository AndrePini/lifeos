#!/usr/bin/env node
// LIFEOS inbox feed publisher.
// Usage: LIFEOS_KEY=<passcode> node tools/publish-inbox.mjs /tmp/triage.json
// triage.json: {"items":[{id,from,subject,cat,why,url?}], "tasks":[{t,due,src}]}
// Merges with the previous feed, encrypts (PBKDF2-SHA256 -> AES-256-GCM, WebCrypto-compatible),
// force-pushes a single commit to branch `inbox-data`, prints a JSON summary.
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const KEY = process.env.LIFEOS_KEY;
if (!KEY) { console.error('LIFEOS_KEY is not set'); process.exit(1); }
const REPO = process.env.LIFEOS_REPO || 'https://github.com/AndrePini/lifeos';
const BRANCH = 'inbox-data', FILE = 'inbox.enc.json', ITER = 210000, TZ = 'America/Sao_Paulo';
const CATS = ['school', 'deadline', 'apps', 'money', 'people', 'account', 'other'];

const today = new Intl.DateTimeFormat('en-CA', { timeZone: TZ }).format(new Date());
const addDays = (k, n) => { const d = new Date(k + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
const s = (v, n) => String(v ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

function encrypt(obj) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(KEY, salt, ITER, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  return { v: 1, alg: 'PBKDF2-SHA256/AES-256-GCM', iter: ITER, salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64'), updated: obj.updated };
}
function decrypt(f) {
  const all = Buffer.from(f.ct, 'base64');
  const key = pbkdf2Sync(KEY, Buffer.from(f.salt, 'base64'), f.iter || ITER, 32, 'sha256');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(f.iv, 'base64'));
  d.setAuthTag(all.subarray(all.length - 16));
  return JSON.parse(Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]).toString('utf8'));
}

const input = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const work = mkdtempSync(join(tmpdir(), 'lifeos-'));
let prev = { items: [], tasks: [] }, hadPrev = false;
try {
  execSync(`git clone -q --depth 1 --branch ${BRANCH} ${REPO} ${work}/prev`, { stdio: 'pipe' });
  prev = decrypt(JSON.parse(readFileSync(`${work}/prev/${FILE}`, 'utf8'))); hadPrev = true;
} catch (e) { /* first run, or key changed */ }

const now = new Date().toISOString();
const prevIds = new Set((prev.items || []).map(i => i.id));
const items = new Map((prev.items || []).map(i => [i.id, i]));
for (const i of input.items || []) {
  if (!i || !i.id) continue;
  const id = s(i.id, 64), old = items.get(id);
  items.set(id, { id, from: s(i.from, 120), subject: s(i.subject, 200) || '(no subject)', cat: CATS.includes(i.cat) ? i.cat : 'other', why: s(i.why, 100), url: s(i.url, 300) || `https://mail.google.com/mail/u/0/#all/${id}`, seen: old ? old.seen : now });
}
const cutoff = Date.now() - 4 * 864e5;
const keepItems = [...items.values()].filter(i => Date.parse(i.seen) >= cutoff).sort((a, b) => b.seen.localeCompare(a.seen)).slice(0, 60);

const tasks = new Map((prev.tasks || []).map(t => [t.src, t]));
for (const t of input.tasks || []) {
  if (!t || !t.t) continue;
  const src = s(t.src, 64) || s(t.t, 64), old = tasks.get(src);
  const due = /^\d{4}-\d{2}-\d{2}$/.test(t.due || '') ? t.due : (old ? old.due : null);
  tasks.set(src, { t: s(t.t, 120), due, src, seen: old ? old.seen : now });
}
const keepTasks = [...tasks.values()].filter(t => t.due ? t.due >= addDays(today, -3) : Date.parse(t.seen) >= Date.now() - 14 * 864e5).slice(0, 80);

const feed = { updated: now, items: keepItems, tasks: keepTasks };
const out = `${work}/out`;
execSync(`git init -q -b ${BRANCH} ${out}`);
writeFileSync(`${out}/${FILE}`, JSON.stringify(encrypt(feed)));
writeFileSync(`${out}/README.md`, 'Encrypted LIFEOS inbox feed, written by a scheduled Claude task. Unreadable without the passcode.\n');
execSync(`git -C ${out} add -A && git -C ${out} -c user.name="LIFEOS sync" -c user.email="noreply@anthropic.com" commit -q -m "inbox ${now}"`);
execSync(`git -C ${out} push -q --force ${REPO} ${BRANCH}:${BRANCH}`, { stdio: 'pipe' });

const due = d => keepTasks.filter(t => t.due === d).map(t => t.t);
console.log(JSON.stringify({
  ok: true, updated: now, previousFeedRead: hadPrev, important: keepItems.length,
  newImportant: keepItems.filter(i => !prevIds.has(i.id)).map(i => `${i.subject} — ${i.from}`),
  dueToday: due(today), dueTomorrow: due(addDays(today, 1)),
  overdue: keepTasks.filter(t => t.due && t.due < today).map(t => t.t)
}, null, 1));
