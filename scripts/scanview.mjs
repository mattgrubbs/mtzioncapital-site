#!/usr/bin/env node
// Manage private links to the QR scan log page (/scans?k=KEY).
//
//   npm run scanview:create -- --label "Matthew laptop"   prints a new private link (shown once; save it)
//   npm run scanview:list                                 lists links by label and date (keys are never stored)
//   npm run scanview:revoke -- <first 8+ characters of the hash shown by list>
//
// Only a SHA-256 hash of each key is stored, as the KV key "scanview:<hash>"; the page checks the hash. Needs
// Cloudflare access (`npx wrangler login`, or CLOUDFLARE_API_TOKEN set). Add --local to work against the dev KV.
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs, runWrangler, ensureLoggedIn, tomlVar, extractJson, fail, KV_BINDING } from './lib.mjs';

const [command, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
const where = args.local ? '--local' : '--remote';
const site = tomlVar('PUBLIC_SITE_URL', 'https://www.mtzioncapital.com').replace(/\/$/, '');
const kv = (sub, extra = []) => runWrangler(['kv', 'key', sub, '--binding', KV_BINDING, where, ...extra], { quiet: true });

if (!args.local && !process.env.CLOUDFLARE_API_TOKEN) await ensureLoggedIn();

if (command === 'create') {
  const key = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(key).digest('hex');
  const dir = mkdtempSync(path.join(tmpdir(), 'scanview-'));
  const empty = path.join(dir, 'empty');
  writeFileSync(empty, '');
  const meta = JSON.stringify({ label: String(args.label || 'scan log link').slice(0, 80), created: new Date().toISOString() });
  try {
    await kv('put', [`scanview:${hash}`, '--path', empty, '--metadata', meta]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(`\n  Private scan log link (save it now; it is not stored anywhere):\n\n  ${site}/scans?k=${key}\n`);
} else if (command === 'list') {
  const keys = extractJson(await kv('list', ['--prefix', 'scanview:']), '[') || [];
  if (!keys.length) console.log('\n  No scan log links.\n');
  for (const k of keys) console.log(`  ${k.name.slice('scanview:'.length, 'scanview:'.length + 12)}  ${(k.metadata && k.metadata.created) || ''}  ${(k.metadata && k.metadata.label) || ''}`);
} else if (command === 'revoke') {
  const prefix = String(args._[0] || '');
  if (prefix.length < 8) fail('Give at least the first 8 characters of the hash shown by `npm run scanview:list`.');
  const keys = (extractJson(await kv('list', ['--prefix', `scanview:${prefix}`]), '[') || []);
  if (keys.length !== 1) fail(keys.length ? 'That matches more than one link; give more characters.' : 'No link matches that.');
  await kv('delete', [keys[0].name]);
  console.log(`\n  Revoked ${keys[0].name.slice(9, 21)}  ${(keys[0].metadata && keys[0].metadata.label) || ''}\n`);
} else {
  fail('Usage: npm run scanview:create -- --label "..." | npm run scanview:list | npm run scanview:revoke -- <hash prefix>');
}
