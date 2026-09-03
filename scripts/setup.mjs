#!/usr/bin/env node
// One-time setup for the secure upload portal. Safe to re-run.
//
//   npx wrangler login      (once, opens your browser)
//   npm run setup
//
// Creates the private R2 bucket, the KV namespace (and writes its id into
// wrangler.toml), the 90-day auto-delete rule, the session-signing secret, and
// prompts you for the upload password. Turnstile is a separate optional step.
import {
  parseArgs, runWrangler, ensureLoggedIn, currentKvId, setKvId, extractJson,
  randomSecret, hashPassword, promptHidden, tomlVar, fail, BUCKET, PLACEHOLDER_KV_ID,
} from './lib.mjs';

const args = parseArgs(process.argv.slice(2));
const retentionDays = parseInt(args['retention-days'] || tomlVar('RETENTION_DAYS', '90'), 10) || 90;
const workerName = tomlVar('name', 'mtzioncapital');

const step = (n, msg) => console.log(`\n[${n}/6] ${msg}`);
const note = (msg) => console.log(`      ${msg}`);

console.log('\nMt. Zion Capital secure upload portal: setup');
await ensureLoggedIn();

// 1. Private R2 bucket
step(1, `R2 bucket "${BUCKET}"`);
try {
  await runWrangler(['r2', 'bucket', 'create', BUCKET], { quiet: true });
  note('created');
} catch (e) {
  if (/already exists|already own/i.test(e.output || '')) note('already exists, keeping it');
  else if (/enable R2|10042/i.test(e.output || '')) {
    fail(`R2 Object Storage is not enabled on your Cloudflare account yet (a one-time step).
      1. Open https://dash.cloudflare.com and pick your account.
      2. In the left menu choose "R2 Object Storage", then "Get started" / "Enable R2".
      3. Accept the terms. Cloudflare asks for a payment method on file even for the free
         tier (10 GB of storage and millions of requests per month at $0; you only pay if
         you exceed that, which a handful of client documents will not).
      4. Come back here and run:  npm run setup`);
  }
  else { console.log(e.output); fail('Could not create the R2 bucket. See the message above.'); }
}

// 2. Auto-delete rule
step(2, `Auto-delete uploads after ${retentionDays} days`);
if (args['skip-lifecycle']) note('skipped (--skip-lifecycle)');
else {
  try {
    await runWrangler(['r2', 'bucket', 'lifecycle', 'add', BUCKET, 'expire-client-uploads', 'uploads/', '--expire-days', String(retentionDays), '--force'], { quiet: true });
    note('rule added');
  } catch (e) {
    if (/already exists/i.test(e.output || '')) note('rule already exists');
    else {
      note('could not add the rule automatically. Add it in the dashboard instead:');
      note(`R2 -> ${BUCKET} -> Settings -> Object lifecycle rules -> Add rule: prefix "uploads/", delete after ${retentionDays} days.`);
    }
  }
}

// 3. KV namespace
step(3, 'KV namespace for client links and rate limits');
let kvId = currentKvId();
if (kvId && kvId !== PLACEHOLDER_KV_ID) note(`wrangler.toml already has id ${kvId}`);
else {
  let out = '';
  try { out = await runWrangler(['kv', 'namespace', 'create', 'PORTAL_KV'], { quiet: true }); }
  catch (e) { out = e.output || ''; }
  let m = out.match(/"?id"?\s*[=:]\s*"([0-9a-f]{32})"/);
  if (!m) {
    // Probably exists already: find it by title.
    const listOut = await runWrangler(['kv', 'namespace', 'list'], { quiet: true }).catch((e) => e.output || '');
    const all = extractJson(listOut, '[') || [];
    const found = all.find((n) => n.title === `${workerName}-PORTAL_KV`);
    if (found) m = [null, found.id];
  }
  if (!m) { console.log(out); fail('Could not create or find the KV namespace.'); }
  kvId = m[1];
  setKvId(kvId);
  note(`created; wrangler.toml updated with id ${kvId} (commit this change)`);
}

// 4. Session-signing secret
step(4, 'Session signing secret (SESSION_SECRET)');
if (args['keep-session-secret']) note('kept existing (--keep-session-secret)');
else {
  await runWrangler(['secret', 'put', 'SESSION_SECRET'], { input: randomSecret(32), quiet: true });
  note('new random secret stored (any existing upload sessions are signed out)');
}

// 5. Upload password
step(5, 'Upload password (UPLOAD_PASSWORD_HASH)');
if (args['skip-password']) note('skipped (--skip-password). Run  npm run set-password  later.');
else if ((tomlVar('ACCESS_MODE', 'link') || 'link').toLowerCase() === 'link') note('not needed: ACCESS_MODE is "link" (personal links are the key). If you switch modes later, run  npm run set-password');
else {
  const pw = await promptHidden('      Choose the upload password (at least 12 characters): ');
  if (pw.length < 12) fail('Password must be at least 12 characters. Re-run setup, or use: npm run set-password');
  const again = await promptHidden('      Type it again to confirm: ');
  if (pw !== again) fail('The two entries did not match. Re-run setup, or use: npm run set-password');
  await runWrangler(['secret', 'put', 'UPLOAD_PASSWORD_HASH'], { input: await hashPassword(pw, 100000), quiet: true });
  note('stored (only the hash; the password itself is not saved anywhere)');
}

// 6. Turnstile (optional)
step(6, 'Turnstile bot protection (optional, recommended)');
note(tomlVar('TURNSTILE_SITE_KEY') ? 'already configured' : 'not configured yet. When ready:  npm run set-turnstile');

console.log(`
Setup complete. Next:

  1. Commit the wrangler.toml change and push to main:
       git add wrangler.toml && git commit -m "Portal: KV namespace id" && git push
     Cloudflare auto-deploys in a few minutes.

  2. Test at ${tomlVar('PUBLIC_SITE_URL', 'https://www.mtzioncapital.com')}/upload

  3. Create a link for a client whenever you need one:
       npm run link:create -- --label "Client or deal name"
`);
