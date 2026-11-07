#!/usr/bin/env node
// Report on QR scans from printed pieces (business card -> /c, capability statement -> /cs).
//
//   npm run scans                      summary + the 25 most recent scans
//   npm run scans -- --csv scans.csv   also write every scan to a CSV file (opens in Excel)
//   npm run scans -- --days 30         only the last 30 days
//   npm run scans -- --all             include bots, link previews and ?test scans
//   npm run scans -- --local           read the local dev KV (for testing with `npm run dev`)
//
// Reads the KV keys "scan:<time>:<rand>" written by src/worker.js; every scan's details are in the key metadata,
// so one `wrangler kv key list` call returns everything. Needs `npx wrangler login` once (except with --local).
import { writeFileSync } from 'node:fs';
import { parseArgs, runWrangler, ensureLoggedIn, extractJson, KV_BINDING } from './lib.mjs';

const args = parseArgs(process.argv.slice(2));
const where = args.local ? '--local' : '--remote';
const SOURCES = { card: 'Business card (/c)', 'capability-statement': 'Capability statement (/cs)' };
const COLS = ['t', 'src', 'country', 'region', 'city', 'zip', 'metro', 'lat', 'lon', 'org', 'asn', 'conn', 'rtt', 'colo', 'proto',
  'device', 'model', 'os', 'browser', 'lang', 'ref', 'vid', 'bot', 'test', 'restored', 'ua'];

if (!args.local) await ensureLoggedIn();
const out = await runWrangler(['kv', 'key', 'list', '--binding', KV_BINDING, where, '--prefix', 'scan:'], { quiet: true });
let scans = (extractJson(out, '[') || []).map((k) => ({ ...(k.metadata || {}), t: (k.metadata && k.metadata.t) || k.name.split(':').slice(1, -1).join(':') }));
const total = scans.length;
if (!args.all) scans = scans.filter((s) => !s.bot && !s.test);
if (args.days) {
  const since = Date.now() - Number(args.days) * 86400000;
  scans = scans.filter((s) => Date.parse(s.t) >= since);
}
scans.sort((a, b) => (a.t < b.t ? 1 : -1));

const count = (key) => {
  const m = new Map();
  for (const s of scans) { const k = key(s) || '(unknown)'; m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
};
const show = (title, rows, max = 10) => {
  console.log(`\n${title}`);
  if (!rows.length) { console.log('  (none)'); return; }
  for (const [k, n] of rows.slice(0, max)) console.log(`  ${String(n).padStart(4)}  ${k}`);
};

console.log(`\nQR scans: ${scans.length} shown` + (args.all ? '' : ` (${total - scans.length} bots/tests hidden; --all to include)`) +
  (args.days ? `, last ${args.days} days` : ''));
console.log(`Different visitors: ${new Set(scans.map((s) => s.vid)).size}`);
show('By printed piece', count((s) => SOURCES[s.src] || s.src));
show('By network owner (companies and agencies show here on office Wi-Fi; phones on cellular show the carrier)', count((s) => s.org));
show('By place', count((s) => [s.city, s.region, s.country].filter(Boolean).join(', ')));
show('By device', count((s) => s.device));
show('By day', count((s) => (s.t || '').slice(0, 10)).sort((a, b) => (a[0] < b[0] ? 1 : -1)), 14);

console.log('\nMost recent');
for (const s of scans.slice(0, 25)) {
  const when = (s.t || '').replace('T', ' ').slice(0, 16) + ' UTC';
  const place = [s.city, s.region, s.country].filter(Boolean).join(', ');
  console.log(`  ${when}  ${(SOURCES[s.src] || s.src).padEnd(27)}  ${place.padEnd(28)}  ${(s.org || '').slice(0, 34).padEnd(34)}  ${s.device || ''}`);
}

if (args.csv) {
  const esc = (v) => { const s = v === undefined ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const lines = [COLS.join(','), ...scans.map((s) => COLS.map((c) => esc(c === 'src' ? (SOURCES[s.src] || s.src) : s[c])).join(','))];
  writeFileSync(String(args.csv), lines.join('\n') + '\n');
  console.log(`\nWrote ${scans.length} scans to ${args.csv}`);
}
console.log('');
