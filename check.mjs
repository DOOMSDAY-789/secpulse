// Scheduled PC check: load the feeds, push anything new to ntfy, remember what was sent.
//   node check.mjs          normal run (Task Scheduler runs this every 3 hours, hidden)
//   node check.mjs --test   send a test alert to the topic
// Settings and memory live in check-config.json next to this file (edit topic/stack/watch/severity there).
// Not %APPDATA%: Task Scheduler runs without it set.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEFAULTS, SOURCES, loadBreaches, loadKev, loadNvd, idOf, summary, ntfy } from './feeds.js';

const file = fileURLToPath(new URL('check-config.json', import.meta.url));
let saved = {};
try { saved = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* first run */ }
const cfg = { ...DEFAULTS, topic: `secpulse-${crypto.randomBytes(6).toString('hex')}`, seen: {}, ...saved };
const save = () => fs.writeFileSync(file, JSON.stringify(cfg, null, 1));

if (process.argv.includes('--test')) {
  await ntfy(cfg.topic, 'SecPulse PC check', 'Scheduled checks on your PC can reach your phone.');
  save();
  console.log(`Test sent to topic ${cfg.topic}`);
  process.exit(0);
}

const loaders = { breaches: loadBreaches, kev: loadKev, nvd: () => loadNvd(cfg.stack) };
const data = { breaches: [], kev: [], nvd: [] };
const errors = [];
for (const src of SOURCES) {
  try { data[src] = await loaders[src](); } catch (e) { errors.push(`${src}: ${e.message}`); }
  if (data[src].length && !cfg.seen[src]) cfg.seen[src] = data[src].map(idOf[src]); // first run: seed quietly
}

const lines = summary(data, cfg, cfg.seen);
let result = lines.length ? `pushed: ${lines.join(' | ')}` : 'nothing new';
try {
  if (lines.length) await ntfy(cfg.topic, `SecPulse: ${lines.length} update(s)`, lines.join('\n'));
  for (const src of SOURCES) if (data[src].length) cfg.seen[src] = data[src].map(idOf[src]);
} catch (e) {
  errors.push(e.message); // not marked seen, so the next run tries again
  result = 'push failed';
}
Object.assign(cfg, { lastRun: new Date().toISOString(), lastResult: result, lastErrors: errors });
save();
console.log(`[${cfg.lastRun}] topic ${cfg.topic}: ${result}${errors.length ? `\nerrors: ${errors.join('; ')}` : ''}`);
process.exitCode = errors.length ? 1 : 0;
