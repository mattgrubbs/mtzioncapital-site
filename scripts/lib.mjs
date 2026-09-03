// Shared helpers for the operator scripts (setup, passwords, client links).
// Node 20+ only. No dependencies beyond wrangler, which is called as a child process.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const TOML_PATH = path.join(ROOT, 'wrangler.toml');
export const KV_BINDING = 'PORTAL_KV';
export const BUCKET = 'mtzion-client-uploads';
export const PLACEHOLDER_KV_ID = '00000000000000000000000000000000';

export function fail(msg) {
  console.error(`\n  ${msg}\n`);
  process.exit(1);
}

// ---------- tiny CLI arg parser: --key value | --key=value | --flag ----------
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > -1) { out[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out[key] = next; i++; }
      else out[key] = true;
    } else {
      out._.push(a);
    }
  }
  return out;
}

// ---------- wrangler ----------
export function wranglerCmd() {
  const local = path.join(ROOT, 'node_modules', '.bin', 'wrangler');
  return existsSync(local) ? { cmd: local, pre: [] } : { cmd: 'npx', pre: ['wrangler'] };
}

/**
 * Run a wrangler command. Returns combined stdout+stderr text.
 * `input` (if given) is written to wrangler's stdin, used for `secret put`.
 * `quiet` suppresses echoing output to the terminal.
 */
export function runWrangler(args, { input, quiet = false } = {}) {
  return new Promise((resolve, reject) => {
    const { cmd, pre } = wranglerCmd();
    const child = spawn(cmd, [...pre, ...args], {
      cwd: ROOT,
      stdio: [input !== undefined ? 'pipe' : 'inherit', 'pipe', 'pipe'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
    });
    let out = '';
    const onData = (d) => { out += d.toString(); if (!quiet) process.stdout.write(d); };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    if (input !== undefined) { child.stdin.write(input); child.stdin.end(); }
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve(out);
      else { const err = new Error(`wrangler ${args.join(' ')} exited with code ${code}`); err.output = out; reject(err); }
    });
  });
}

export async function ensureLoggedIn() {
  const out = await runWrangler(['whoami'], { quiet: true }).catch((e) => e.output || '');
  if (/not authenticated/i.test(out) || !/account/i.test(out)) {
    fail('You are not logged in to Cloudflare. Run this first, then try again:\n\n      npx wrangler login');
  }
}

// ---------- wrangler.toml helpers ----------
export function readToml() { return readFileSync(TOML_PATH, 'utf8'); }
export function writeToml(text) { writeFileSync(TOML_PATH, text); }

export function tomlVar(name, fallback = '') {
  const m = readToml().match(new RegExp(`^\\s*${name}\\s*=\\s*"([^"]*)"`, 'm'));
  return m ? m[1] : fallback;
}

export function setTomlVar(name, value) {
  const toml = readToml();
  const re = new RegExp(`^(\\s*${name}\\s*=\\s*")[^"]*(")`, 'm');
  if (!re.test(toml)) fail(`Could not find ${name} in wrangler.toml`);
  writeToml(toml.replace(re, `$1${value}$2`));
}

export function currentKvId() {
  const m = readToml().match(/\[\[kv_namespaces\]\][\s\S]*?binding\s*=\s*"PORTAL_KV"[\s\S]*?id\s*=\s*"([0-9a-f]{32})"/);
  return m ? m[1] : null;
}

export function setKvId(id) {
  const toml = readToml();
  const re = /(\[\[kv_namespaces\]\][\s\S]*?binding\s*=\s*"PORTAL_KV"[\s\S]*?id\s*=\s*")[0-9a-f]{32}(")/;
  if (!re.test(toml)) fail('Could not find the PORTAL_KV namespace block in wrangler.toml');
  writeToml(toml.replace(re, `$1${id}$2`));
}

// ---------- crypto ----------
const b64u = (bytes) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** PBKDF2-SHA256 hash in the exact format src/worker.js verifies. */
export async function hashPassword(password, iterations = 100000) {
  const salt = randomBytes(16);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return `pbkdf2$sha256$${iterations}$${b64u(salt)}$${b64u(new Uint8Array(bits))}`;
}

export function randomSecret(bytes = 32) { return b64u(randomBytes(bytes)); }

/** A strong, typeable password: 4 groups of 5 unambiguous characters. */
export function generatePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const buf = randomBytes(20);
  let s = '';
  for (let i = 0; i < 20; i++) {
    if (i && i % 5 === 0) s += '-';
    s += alphabet[buf[i] % alphabet.length];
  }
  return s;
}

export function linkToken() { return b64u(randomBytes(32)); }

// ---------- prompts ----------
export function promptVisible(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a.trim()); }));
}


// When stdin is piped (not a terminal), each prompt consumes the next line.
let pipedLines = null;
function readPipedLine() {
  if (pipedLines) return Promise.resolve(pipedLines.shift() ?? '');
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => { data += d; });
    process.stdin.on('end', () => { pipedLines = data.split(/\r?\n/); resolve(pipedLines.shift() ?? ''); });
  });
}

export function promptHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stderr.write(question);
    if (!stdin.isTTY) {
      readPipedLine().then((v) => { process.stderr.write('\n'); resolve(v); });
      return;
    }
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (chunk) => {
      for (const ch of String(chunk)) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stderr.write('\n');
          resolve(value);
          return;
        }
        if (ch === '\u0003') { process.stderr.write('\n'); process.exit(130); }
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else if (ch >= ' ') value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

// ---------- misc ----------
export function extractJson(text, opener) {
  const start = text.indexOf(opener);
  if (start === -1) return null;
  const closer = opener === '[' ? ']' : '}';
  const end = text.lastIndexOf(closer);
  if (end === -1) return null;
  try { return JSON.parse(text.slice(start, end + 1)); } catch { return null; }
}
