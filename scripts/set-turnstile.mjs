#!/usr/bin/env node
// Enable Cloudflare Turnstile (bot protection) on the password step.
//
//   1. In the Cloudflare dashboard: Turnstile -> Add widget
//        Domain: mtzioncapital.com     Widget mode: Managed
//   2. Copy the Site Key and Secret Key it gives you, then run:
//        npm run set-turnstile
//
// The site key is public and goes in wrangler.toml. The secret key is stored as
// the Cloudflare secret TURNSTILE_SECRET_KEY and never touches the repo.
import { promptVisible, promptHidden, setTomlVar, runWrangler, ensureLoggedIn, fail } from './lib.mjs';

const siteKey = await promptVisible('Turnstile Site Key: ');
if (!/^[0-9A-Za-z_-]{10,}$/.test(siteKey)) fail('That does not look like a Turnstile site key.');
const secret = await promptHidden('Turnstile Secret Key (hidden): ');
if (secret.length < 10) fail('That does not look like a Turnstile secret key.');

await ensureLoggedIn();
setTomlVar('TURNSTILE_SITE_KEY', siteKey);
console.log('\n  wrangler.toml updated with the site key (commit and push this change).');
console.log('  Storing the secret key as Cloudflare secret TURNSTILE_SECRET_KEY ...');
await runWrangler(['secret', 'put', 'TURNSTILE_SECRET_KEY'], { input: secret });
console.log('\n  Done. Turnstile is active once the wrangler.toml change is deployed.\n');
