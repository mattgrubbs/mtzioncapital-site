#!/usr/bin/env node
// Set (or rotate) the shared upload password.
//
//   npm run set-password                      prompts for a new password
//   npm run set-password -- --generate        generates a strong one and shows it once
//   npm run set-password -- --iterations 600000   (Workers Paid plan only; Free plan max is 100000)
//   npm run set-password -- --print           print the hash instead of storing it (for .dev.vars)
//
// The password itself is never written anywhere. Only a PBKDF2-SHA256 hash is
// stored, as the Cloudflare secret UPLOAD_PASSWORD_HASH.
import { parseArgs, promptHidden, hashPassword, generatePassword, runWrangler, ensureLoggedIn, ensureWorkerExists, fail } from './lib.mjs';

const args = parseArgs(process.argv.slice(2));
const iterations = Math.max(10000, parseInt(args.iterations || '100000', 10) || 100000);

let password;
if (args.generate) {
  password = generatePassword();
  console.log('\n  Generated upload password (copy it now, it will not be shown again):\n');
  console.log(`      ${password}\n`);
} else {
  password = await promptHidden('New upload password (at least 12 characters): ');
  if (password.length < 12) fail('Password must be at least 12 characters.');
  const again = await promptHidden('Type it again to confirm: ');
  if (password !== again) fail('The two entries did not match. Nothing was changed.');
}

const hash = await hashPassword(password, iterations);

if (args.print) {
  console.log(hash);
  process.exit(0);
}

await ensureLoggedIn();
await ensureWorkerExists();
console.log('\n  Storing the password hash as Cloudflare secret UPLOAD_PASSWORD_HASH ...');
await runWrangler(['secret', 'put', 'UPLOAD_PASSWORD_HASH'], { input: hash });
console.log('\n  Done. New logins use the new password immediately. Existing sessions expire on their own.\n');
