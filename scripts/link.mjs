#!/usr/bin/env node
// Manage per-client upload links. Each link is a random token stored in KV.
//
//   npm run link:create -- --label "Acme HVAC (Bob Smith)"            never expires
//   npm run link:create -- --label "Acme HVAC" --days 30              expires in 30 days
//   npm run link:create -- --label "Acme HVAC" --no-password          link alone is enough (no shared password)
//   npm run link:list
//   npm run link:revoke -- <token or first 8+ characters>
//   npm run link:delete -- <token or first 8+ characters>
//
// Add --local to any command to work against the local dev KV (for testing).
import { parseArgs, runWrangler, ensureLoggedIn, tomlVar, linkToken, extractJson, fail, KV_BINDING } from './lib.mjs';

const [command, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
const where = args.local ? '--local' : '--remote';
const site = (tomlVar('PUBLIC_SITE_URL', 'https://www.mtzioncapital.com')).replace(/\/$/, '');

const kv = (sub, extra = [], opts = {}) =>
  runWrangler(['kv', 'key', sub, '--binding', KV_BINDING, where, ...extra], { quiet: true, ...opts });

async function getLink(token) {
  const out = await kv('get', [`link:${token}`]).catch((e) => e.output || '');
  return extractJson(out, '{');
}

async function listLinks() {
  const out = await kv('list', ['--prefix', 'link:']);
  const keys = extractJson(out, '[') || [];
  const links = [];
  for (const k of keys) {
    const token = k.name.slice('link:'.length);
    const data = await getLink(token);
    if (data) links.push({ token, ...data });
  }
  return links;
}

async function resolveToken(prefix) {
  if (!prefix) fail('Give the link token (or at least its first 8 characters).');
  if (prefix.length >= 40) return prefix;
  const matches = (await listLinks()).filter((l) => l.token.startsWith(prefix));
  if (matches.length === 0) fail(`No link starts with "${prefix}".`);
  if (matches.length > 1) fail(`More than one link starts with "${prefix}". Use more characters.`);
  return matches[0].token;
}

function printLink(l) {
  const status = l.revoked ? 'REVOKED' : (l.expiresAt && Date.parse(l.expiresAt) < Date.now()) ? 'EXPIRED' : 'active';
  console.log(`  ${status.padEnd(8)}  ${l.label}`);
  console.log(`            link:    ${site}/upload?c=${l.token}`);
  console.log(`            created: ${l.createdAt.slice(0, 10)}   expires: ${l.expiresAt ? l.expiresAt.slice(0, 10) : 'never'}   uses: ${l.uses || 0}${l.noPassword ? '   (no password required)' : ''}`);
  console.log('');
}

if (!args.local) await ensureLoggedIn();

switch (command) {
  case 'create': {
    const label = String(args.label || '').trim();
    if (!label) fail('A label is required, e.g.  npm run link:create -- --label "Acme HVAC (Bob Smith)"');
    const days = args.days ? parseInt(args.days, 10) : null;
    if (args.days && !(days > 0)) fail('--days must be a positive number.');
    const token = linkToken();
    const record = {
      label: label.slice(0, 80),
      createdAt: new Date().toISOString(),
      expiresAt: days ? new Date(Date.now() + days * 86400000).toISOString() : null,
      revoked: false,
      noPassword: Boolean(args['no-password']),
      uses: 0,
    };
    await kv('put', [`link:${token}`, JSON.stringify(record)]);
    console.log('\n  Created. Send this link to the client:\n');
    console.log(`      ${site}/upload?c=${token}\n`);
    console.log(`  Label: ${record.label}   Expires: ${record.expiresAt ? record.expiresAt.slice(0, 10) : 'never'}${record.noPassword ? '   No password required' : '   They will also need the shared password'}\n`);
    break;
  }
  case 'list': {
    const links = await listLinks();
    if (!links.length) { console.log('\n  No client links yet.\n'); break; }
    console.log('');
    links.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)).forEach(printLink);
    break;
  }
  case 'revoke': {
    const token = await resolveToken(args._[0]);
    const data = await getLink(token);
    if (!data) fail('Link not found.');
    await kv('put', [`link:${token}`, JSON.stringify({ ...data, revoked: true, revokedAt: new Date().toISOString() })]);
    console.log(`\n  Revoked "${data.label}". That link no longer works.\n`);
    break;
  }
  case 'delete': {
    const token = await resolveToken(args._[0]);
    await kv('delete', [`link:${token}`]);
    console.log('\n  Deleted.\n');
    break;
  }
  default:
    fail('Usage: node scripts/link.mjs <create|list|revoke|delete> [options]');
}
