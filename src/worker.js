/**
 * Mt. Zion Capital — secure client document upload (Cloudflare Worker)
 *
 * Handles /api/upload/* on the server. Every other request falls through to the
 * static site (wrangler.toml [assets]).
 *
 * Security model (details in README, "Secure client upload portal"):
 *  - ACCESS_MODE decides the credential: "link" (default) = a personal URL
 *    (/upload?c=TOKEN) is the credential, no password; "password" = a shared
 *    password; "link+password" = both. Links live in KV: revocable, expirable,
 *    and every upload is attributed to the link it came through.
 *  - Passwords (when used) are verified server-side against a PBKDF2-SHA256
 *    hash stored as a Worker secret (UPLOAD_PASSWORD_HASH). Constant-time compare.
 *  - A successful login issues a short-lived HMAC-signed HttpOnly cookie.
 *  - Cloudflare Turnstile (when configured) blocks bots on the password step.
 *  - Per-IP rate limits on login attempts and on uploads (KV counters).
 *  - Same-origin + custom-header checks on every POST (CSRF).
 *  - Uploads are checked by extension AND file signature, size-capped, renamed
 *    to unguessable keys, and written to a PRIVATE R2 bucket (encrypted at rest).
 *  - This Worker never serves an uploaded file back to anyone.
 */

const TEXT = new TextEncoder();
const COOKIE = '__Secure-mzc_up';
const COOKIE_PATH = '/api/upload';

// ---------- Accepted file types: extension -> canonical MIME + signature ----------
const isOLE   = (b) => startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const isZIP   = (b) => startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06]);
const isJPEG  = (b) => startsWith(b, [0xff, 0xd8, 0xff]);
const isTIFF  = (b) => startsWith(b, [0x49, 0x49, 0x2a, 0x00]) || startsWith(b, [0x4d, 0x4d, 0x00, 0x2a]);
const isHEIF  = (b) => ascii(b, 4, 8) === 'ftyp';
const looksText = (b) => {
  const n = Math.min(b.length, 2048);
  for (let i = 0; i < n; i++) if (b[i] === 0) return false;
  return true;
};

const TYPES = {
  pdf:  { mime: 'application/pdf',  check: (b) => findAscii(b, '%PDF', 1024) },
  png:  { mime: 'image/png',        check: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47]) },
  jpg:  { mime: 'image/jpeg',       check: isJPEG },
  jpeg: { mime: 'image/jpeg',       check: isJPEG },
  gif:  { mime: 'image/gif',        check: (b) => ascii(b, 0, 4) === 'GIF8' },
  webp: { mime: 'image/webp',       check: (b) => ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WEBP' },
  heic: { mime: 'image/heic',       check: isHEIF },
  heif: { mime: 'image/heif',       check: isHEIF },
  tif:  { mime: 'image/tiff',       check: isTIFF },
  tiff: { mime: 'image/tiff',       check: isTIFF },
  doc:  { mime: 'application/msword',       check: isOLE },
  xls:  { mime: 'application/vnd.ms-excel', check: isOLE },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', check: isZIP },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',       check: isZIP },
  csv:  { mime: 'text/csv',         check: looksText },
  txt:  { mime: 'text/plain',       check: looksText },
  zip:  { mime: 'application/zip',  check: isZIP },
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/upload/')) {
      try {
        return await handleApi(request, env, ctx, url);
      } catch (err) {
        log('error', { path: url.pathname, message: errMsg(err) });
        return json({ ok: false, error: 'server_error', message: 'Something went wrong on our end. Please try again.' }, 500);
      }
    }
    // Everything else is the static site (404 handling is configured in wrangler.toml).
    return env.ASSETS.fetch(request);
  },
};

// ---------- Routing ----------
async function handleApi(request, env, ctx, url) {
  const route = url.pathname.slice('/api/upload/'.length);
  const method = request.method;

  if (method === 'GET' && route === 'config')  return getConfig(env);
  if (method === 'GET' && route === 'session') return getSession(request, env);

  if (method === 'POST') {
    // CSRF: must come from our own page, and carry the custom header that
    // browsers never add on a cross-site request.
    if (!sameOrigin(request, url) || request.headers.get('X-Requested-With') !== 'mzc-upload') {
      return json({ ok: false, error: 'bad_origin', message: 'Request rejected.' }, 403);
    }
    if (route === 'auth')   return postAuth(request, env, ctx);
    if (route === 'file')   return postFile(request, env);
    if (route === 'logout') return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
  }
  return json({ ok: false, error: 'not_found' }, 404);
}

// ---------- GET /api/upload/config ----------
function getConfig(env) {
  return json({
    ok: true,
    ready: portalReady(env),
    accessMode: accessMode(env),
    turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
    maxFileMB: maxFileMB(env),
    allowedExt: Object.keys(TYPES),
    requireClientLink: accessMode(env) !== 'password',
    retentionDays: parseInt(env.RETENTION_DAYS || '90', 10) || 90,
  });
}

// ---------- GET /api/upload/session ----------
async function getSession(request, env) {
  const s = await readSession(request, env);
  if (!s) return json({ ok: false, error: 'no_session' }, 401);
  return json({ ok: true, attribution: s.att, label: s.lbl, expiresAt: s.exp });
}

// ---------- POST /api/upload/auth ----------
async function postAuth(request, env, ctx) {
  const mode = accessMode(env);
  if (!portalReady(env)) {
    log('config_error', { missing: !env.SESSION_SECRET ? 'SESSION_SECRET' : 'UPLOAD_PASSWORD_HASH', mode });
    return json({ ok: false, error: 'not_configured', message: 'The upload portal is not set up yet.' }, 503);
  }

  const ip = clientIp(request);
  const iph = await ipHash(ip, env.SESSION_SECRET);

  // 10 login attempts per 10 minutes per IP. Fail CLOSED if KV is unavailable.
  if (!(await rateLimit(env, 'auth', iph, 10, 600, true))) {
    log('auth_ratelimited', { iph });
    return json({ ok: false, error: 'rate_limited', message: 'Too many attempts. Please wait a few minutes and try again.' }, 429);
  }

  const body = await readJson(request);
  if (!body) return json({ ok: false, error: 'bad_request', message: 'Malformed request.' }, 400);

  // Enforce Turnstile only once BOTH halves are configured (the public site key
  // reaches production via a git deploy, the secret via `wrangler secret put`,
  // and they can land minutes apart). Enforcing on the secret alone would lock
  // everyone out until the page can render the widget.
  if (env.TURNSTILE_SECRET_KEY && env.TURNSTILE_SITE_KEY) {
    if (!(await verifyTurnstile(env, body.turnstile, ip))) {
      log('turnstile_failed', { iph });
      return json({ ok: false, error: 'turnstile_failed', message: 'We could not confirm you are a person. Please reload the page and try again.' }, 400);
    }
  }

  // Per-client link: the credential in "link" mode, required in "link+password",
  // optional (attribution only) in "password" mode.
  let link = null;
  let linkKey = null;
  const token = typeof body.c === 'string' ? body.c.trim() : '';
  if (token) {
    if (!/^[A-Za-z0-9_-]{20,128}$/.test(token)) {
      return json({ ok: false, error: 'link_invalid', message: 'This upload link is not valid.' }, 403);
    }
    linkKey = `link:${token}`;
    const raw = await env.PORTAL_KV.get(linkKey);
    link = raw ? safeJson(raw) : null;
    const problem = !link ? 'unknown'
      : link.revoked ? 'revoked'
      : (link.expiresAt && Date.parse(link.expiresAt) < Date.now()) ? 'expired'
      : null;
    if (problem) {
      log('link_rejected', { iph, reason: problem, tid: token.slice(0, 8) });
      return json({ ok: false, error: 'link_invalid', message: 'This upload link is no longer active. Please contact us for a new one.' }, 403);
    }
  } else if (mode !== 'password') {
    return json({ ok: false, error: 'link_required', message: 'A personal upload link is required. Please use the link we sent you.' }, 403);
  }

  const needPassword = mode === 'password' ? true
    : mode === 'link' ? false
    : !(link && link.noPassword === true);
  if (needPassword && !(await verifyPassword(env, body.password))) {
    log('auth_failed', { iph, viaLink: Boolean(link) });
    return json({ ok: false, error: 'bad_password', message: 'That password is not correct.' }, 401);
  }

  const ttl = sessionTtlSec(env);
  const payload = {
    v: 1,
    exp: Math.floor(Date.now() / 1000) + ttl,
    att: link ? 'link' : 'general',
    lbl: link ? sanitizeText(link.label, 80) : '',
    tid: link ? token.slice(0, 8) : '',
  };
  const cookie = await issueCookie(env, payload, ttl);

  if (link) {
    const updated = { ...link, uses: (Number(link.uses) || 0) + 1, lastUsedAt: new Date().toISOString() };
    ctx.waitUntil(env.PORTAL_KV.put(linkKey, JSON.stringify(updated)).catch(() => {}));
  }

  log('auth_ok', { iph, att: payload.att, tid: payload.tid });
  return json({ ok: true, attribution: payload.att, label: payload.lbl, expiresAt: payload.exp }, 200, { 'Set-Cookie': cookie });
}

// ---------- POST /api/upload/file ----------
async function postFile(request, env) {
  const session = await readSession(request, env);
  if (!session) {
    return json({ ok: false, error: 'session_expired', message: 'Your session has expired. Please enter the password again.' }, 401);
  }

  const ip = clientIp(request);
  const iph = await ipHash(ip, env.SESSION_SECRET);

  // 60 files per hour per IP. Fail OPEN if KV hiccups (a logged-in user should not be blocked).
  if (!(await rateLimit(env, 'upload', iph, 60, 3600, false))) {
    return json({ ok: false, error: 'rate_limited', message: 'Upload limit reached for now. Please try again in a little while.' }, 429);
  }

  const maxBytes = maxFileMB(env) * 1024 * 1024;
  const declared = parseInt(request.headers.get('Content-Length') || '', 10);
  if (Number.isFinite(declared) && declared > maxBytes) return tooLarge(env);

  const name = safeFileName(decodeHeader(request.headers.get('X-File-Name')));
  const ext = extOf(name);
  const type = Object.hasOwn(TYPES, ext) ? TYPES[ext] : null;
  if (!type) {
    return json({ ok: false, error: 'type_not_allowed', message: `"${name}" is not an accepted file type.` }, 415);
  }

  const buf = new Uint8Array(await request.arrayBuffer());
  if (buf.byteLength === 0) return json({ ok: false, error: 'empty', message: 'That file is empty.' }, 400);
  if (buf.byteLength > maxBytes) return tooLarge(env);
  if (!type.check(buf)) {
    log('content_mismatch', { iph, ext });
    return json({ ok: false, error: 'content_mismatch', message: `"${name}" does not look like a valid .${ext} file.` }, 415);
  }

  const uploaderName = sanitizeText(decodeHeader(request.headers.get('X-Uploader-Name')), 120);
  const company      = sanitizeText(decodeHeader(request.headers.get('X-Uploader-Company')), 120);
  const note         = sanitizeText(decodeHeader(request.headers.get('X-Uploader-Note')), 300);

  const now = new Date();
  const folder = session.att === 'link' ? slug(session.lbl) : 'general';
  const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const key = `uploads/${now.toISOString().slice(0, 10)}/${folder}/${id}__${name}`;

  await env.UPLOADS.put(key, buf, {
    httpMetadata: {
      contentType: type.mime,
      contentDisposition: `attachment; filename="${name.replace(/"/g, '')}"`,
      cacheControl: 'private, no-store',
    },
    customMetadata: {
      originalName: name,
      uploaderName,
      company,
      note,
      attribution: session.att,
      linkLabel: session.lbl || '',
      linkId: session.tid || '',
      uploadedAt: now.toISOString(),
      ipHash: iph,
      sizeBytes: String(buf.byteLength),
    },
  });

  log('upload_ok', { iph, key, bytes: buf.byteLength, att: session.att, tid: session.tid });
  return json({ ok: true, file: { name, size: buf.byteLength } });
}

function tooLarge(env) {
  return json({ ok: false, error: 'too_large', message: `Files must be under ${maxFileMB(env)} MB.` }, 413);
}

// ---------- Password (PBKDF2-SHA256, constant-time compare) ----------
// Stored format: pbkdf2$sha256$<iterations>$<salt b64url>$<hash b64url>
async function verifyPassword(env, password) {
  if (typeof password !== 'string' || password.length === 0 || password.length > 512) return false;
  const parts = String(env.UPLOAD_PASSWORD_HASH || '').trim().split('$');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha256') {
    log('config_error', { message: 'UPLOAD_PASSWORD_HASH is not in the expected format' });
    return false;
  }
  const iterations = parseInt(parts[2], 10);
  if (!Number.isFinite(iterations) || iterations < 1000) return false;
  const salt = b64uDecode(parts[3]);
  const expected = b64uDecode(parts[4]);

  const key = await crypto.subtle.importKey('raw', TEXT.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, expected.byteLength * 8),
  );
  return constantTimeEqual(derived, expected);
}

function constantTimeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  if (typeof crypto.subtle.timingSafeEqual === 'function') return crypto.subtle.timingSafeEqual(a, b);
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- Session cookie (HMAC-SHA256 signed, HttpOnly, short-lived) ----------
async function issueCookie(env, payload, ttl) {
  const data = b64uEncode(TEXT.encode(JSON.stringify(payload)));
  const sig = await hmacSign(env.SESSION_SECRET, data);
  return `${COOKIE}=${data}.${sig}; Path=${COOKIE_PATH}; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Strict`;
}

function clearCookie() {
  return `${COOKIE}=; Path=${COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

async function readSession(request, env) {
  if (!env.SESSION_SECRET) return null;
  const raw = getCookie(request, COOKIE);
  if (!raw) return null;
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const data = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!(await hmacVerify(env.SESSION_SECRET, data, sig))) return null;
  const payload = safeJson(bytesToString(b64uDecode(data)));
  if (!payload || payload.v !== 1 || typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) return null;
  return payload;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', TEXT.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function hmacSign(secret, data) {
  const key = await hmacKey(secret);
  return b64uEncode(new Uint8Array(await crypto.subtle.sign('HMAC', key, TEXT.encode(data))));
}
async function hmacVerify(secret, data, sig) {
  try {
    const key = await hmacKey(secret);
    return await crypto.subtle.verify('HMAC', key, b64uDecode(sig), TEXT.encode(data));
  } catch {
    return false;
  }
}

// ---------- Turnstile ----------
async function verifyTurnstile(env, token, ip) {
  if (typeof token !== 'string' || !token) return false;
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', token);
  if (ip && ip !== 'unknown') form.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = await res.json().catch(() => ({}));
  return data.success === true;
}

// ---------- Rate limiting (KV counters per IP hash, per time window) ----------
async function rateLimit(env, bucket, id, limit, windowSec, failClosed) {
  const win = Math.floor(Date.now() / 1000 / windowSec);
  const key = `rl:${bucket}:${id}:${win}`;
  try {
    const cur = parseInt((await env.PORTAL_KV.get(key)) || '0', 10) || 0;
    if (cur >= limit) return false;
    await env.PORTAL_KV.put(key, String(cur + 1), { expirationTtl: windowSec + 60 });
    return true;
  } catch (err) {
    log('ratelimit_error', { bucket, message: errMsg(err) });
    return !failClosed;
  }
}

// ---------- Request helpers ----------
function sameOrigin(request, url) {
  const origin = request.headers.get('Origin');
  if (origin) return origin === url.origin;
  return request.headers.get('Sec-Fetch-Site') === 'same-origin';
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// Logs and metadata keep a keyed hash of the IP, never the IP itself.
async function ipHash(ip, secret) {
  const digest = await crypto.subtle.digest('SHA-256', TEXT.encode(`${secret}|${ip}`));
  return hex(new Uint8Array(digest)).slice(0, 16);
}

async function readJson(request) {
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.includes('application/json')) return null;
  const text = await request.text();
  if (text.length > 10000) return null;
  const parsed = safeJson(text);
  return parsed && typeof parsed === 'object' ? parsed : null;
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

function decodeHeader(value) {
  if (!value) return '';
  try { return decodeURIComponent(value); } catch { return value; }
}

// ---------- Sanitizers ----------
function safeFileName(raw) {
  let name = String(raw || '').split(/[\\/]/).pop().trim();
  name = name.replace(/[^A-Za-z0-9._\- ()]/g, '_').replace(/\s+/g, ' ').replace(/^\.+/, '').slice(0, 120);
  return name || 'upload';
}

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i + 1).toLowerCase() : '';
}

function sanitizeText(value, max) {
  return String(value || '').replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, max);
}

function slug(label) {
  const s = String(label || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return s || 'client';
}

// ---------- Config helpers ----------
// ACCESS_MODE: "link" (personal URL is the credential, no password),
// "password" (shared password; links optional, for attribution), or
// "link+password" (both; a link created with --no-password skips the password).
function accessMode(env) {
  const m = String(env.ACCESS_MODE || 'link').toLowerCase().replace(/\s+/g, '');
  return m === 'password' || m === 'link+password' ? m : 'link';
}

function portalReady(env) {
  return Boolean(env.SESSION_SECRET) && (accessMode(env) === 'link' || Boolean(env.UPLOAD_PASSWORD_HASH));
}

function maxFileMB(env) {
  const n = parseInt(env.MAX_FILE_MB || '50', 10) || 50;
  return Math.min(Math.max(n, 1), 95); // stay under the Workers request body limit
}

function sessionTtlSec(env) {
  const min = parseInt(env.SESSION_TTL_MIN || '30', 10) || 30;
  return Math.min(Math.max(min, 5), 240) * 60;
}

// ---------- Bytes / encoding ----------
function startsWith(bytes, sig) {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false;
  return true;
}
function ascii(bytes, start, end) {
  let s = '';
  for (let i = start; i < end && i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}
function findAscii(bytes, needle, within) {
  const n = Math.min(bytes.length, within);
  outer: for (let i = 0; i + needle.length <= n; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle.charCodeAt(j)) continue outer;
    return true;
  }
  return false;
}
function hex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
function b64uEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToString(bytes) { return new TextDecoder().decode(bytes); }
function safeJson(text) { try { return JSON.parse(text); } catch { return null; } }
function errMsg(err) { return String((err && err.message) || err); }

// ---------- Responses / logging ----------
function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extra,
    },
  });
}

// Structured logs, visible in Cloudflare "Workers Logs". No secrets, no raw IPs, no file contents.
function log(evt, data) {
  console.log(JSON.stringify({ evt, t: new Date().toISOString(), ...data }));
}
