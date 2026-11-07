/**
 * Mt. Zion Capital — secure client document upload (Cloudflare Worker)
 *
 * Handles /api/upload/* and the QR scan links (/c, /cs) on the server. Every other request falls through to the
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

// ---------- QR scan links on printed pieces (Matthew 2026-11-07) ----------
// Each printed piece carries its own short link. A scan is logged (no IP stored, no cookies) and the visitor is sent
// straight on to /gov. The paths must also be listed in wrangler.toml [assets] run_worker_first.
const SCAN_LINKS = { '/c': 'card', '/cs': 'capability-statement' };
const SCAN_TARGET = '/gov';
const SCAN_RETENTION_DAYS = 400;          // about 13 months; matches the privacy page
// Every scan is stored and counted, repeats included (Matthew 2026-11-07: no dedupe).

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const scanSrc = SCAN_LINKS[url.pathname.toLowerCase().replace(/\/+$/, '')];
    if (scanSrc && (request.method === 'GET' || request.method === 'HEAD')) {
      return scanRedirect(request, env, ctx, url, scanSrc);
    }
    if ((url.pathname === '/scans' || url.pathname === '/scans.csv') && request.method === 'GET') {
      try {
        return await scanLogPage(request, env, url);
      } catch (err) {
        log('scanlog_error', { message: errMsg(err) });
        return new Response('Something went wrong.', { status: 500, headers: { 'Cache-Control': 'no-store' } });
      }
    }
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
  if (!s) return json({ ok: false, error: 'no_session' }); // 200: a normal state, keeps the browser console clean
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

// ---------- QR scan logging ----------
// Records one small entry per scan in KV, then redirects to /gov. What is kept: time, which printed piece, the
// approximate place and network owner Cloudflare derives from the connection (country, region, city, ASN and its
// organization), a short device/browser summary, the browser language, the referring site if any, and a keyed hash
// of the IP (to count repeat visitors). The IP itself is never stored. The whole entry rides in the KV key's metadata
// (under 1 KB) so `npm run scans` can list everything in one call. Bots and link previews are logged but flagged, and
// requests with ?test are flagged as tests so they can be left out of the report. Every scan is stored, including
// repeats from the same person or network (no dedupe, at Matthew's request); `vid` lets the report tell them apart.
async function scanRedirect(request, env, ctx, url, src) {
  const target = `${url.origin}${SCAN_TARGET}`;
  const headers = {
    Location: target, 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex', 'Referrer-Policy': 'no-referrer',
    // Ask Chromium browsers (Chrome, Edge, Samsung Internet) for the phone model and OS version. Critical-CH makes
    // them repeat this request at once with those hints; the two requests are merged into one scan (see storeScan).
    'Accept-CH': SCAN_CH_ACCEPT, 'Critical-CH': SCAN_CH_CRITICAL, Vary: SCAN_CH_CRITICAL,
  };
  try {
    const cf = request.cf || {};
    const ua = request.headers.get('User-Agent') || '';
    const h = (n) => unq(request.headers.get(n));
    const chromium = request.headers.has('Sec-CH-UA');
    const hinted = request.headers.has('Sec-CH-UA-Model') || request.headers.has('Sec-CH-UA-Platform-Version');
    const vid = await ipHash(clientIp(request), env.SESSION_SECRET || 'mzc-scan');
    const model = h('Sec-CH-UA-Model').slice(0, 40);
    const org = String(cf.asOrganization || '').slice(0, 80);
    const event = {
      t: new Date().toISOString(),
      src,
      test: url.searchParams.has('test') || undefined,
      bot: isBot(ua) || undefined,
      vid,
      country: cf.country || '',
      region: cf.region || '',
      city: cf.city || '',
      zip: cf.postalCode || '',
      metro: cf.metroCode || '',
      lat: cf.latitude || '',
      lon: cf.longitude || '',
      tz: cf.timezone || '',
      asn: cf.asn || '',
      org,
      conn: connectionGuess(org, cf.asn),
      rtt: cf.clientTcpRtt || '',
      colo: cf.colo || '',
      proto: cf.httpProtocol || '',
      device: deviceSummary(ua, model),
      model: model ? `${model}${phoneName(model) ? ` (${phoneName(model)})` : ''}` : '',
      os: osVersion(ua, h('Sec-CH-UA-Platform'), h('Sec-CH-UA-Platform-Version')),
      browser: browserVersion(ua, request.headers.get('Sec-CH-UA-Full-Version-List') || ''),
      lang: (request.headers.get('Accept-Language') || '').split(',')[0].slice(0, 20),
      ref: refOrigin(request.headers.get('Referer')),
      ua: ua.slice(0, 200),
    };
    log('qr_scan', { ...event, pass: chromium ? (hinted ? 'hints' : 'first') : 'only' });
    if (request.method === 'GET' && env.PORTAL_KV) {
      const marker = new Request(`https://scan-retry.invalid/${src}/${vid}/${await sha256Hex(ua)}`);
      if (chromium && !hinted) {
        // First pass from a Chromium browser: park it for a few seconds in case the hinted repeat arrives.
        await caches.default.put(marker, new Response(JSON.stringify(event), { headers: { 'Cache-Control': 'max-age=30' } }));
        ctx.waitUntil(storeAfterWait(env, marker, event));
      } else if (chromium && hinted) {
        ctx.waitUntil(storeHinted(env, marker, event));
      } else {
        ctx.waitUntil(storeScan(env, event));
      }
    }
  } catch (err) {
    log('qr_scan_error', { src, message: errMsg(err) });   // never block the visitor
  }
  return new Response(null, { status: 302, headers });
}

const SCAN_CH_ACCEPT = 'Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List';
const SCAN_CH_CRITICAL = 'Sec-CH-UA-Model, Sec-CH-UA-Platform-Version';
const SCAN_MERGE_WAIT_MS = 4000;

// The browser repeated the request with hints: take over the parked first pass (keeping its time) and store once.
async function storeHinted(env, marker, event) {
  const parked = await caches.default.match(marker);
  if (parked) {
    const first = await parked.json().catch(() => null);
    await caches.default.delete(marker);
    if (first && first.t) event.t = first.t;
  }
  await storeScan(env, event);
}

// No hinted repeat arrived (Chromium that does not retry, or a desktop browser): store the first pass as it is.
async function storeAfterWait(env, marker, event) {
  await new Promise((r) => setTimeout(r, SCAN_MERGE_WAIT_MS));
  if (await caches.default.match(marker)) {
    await caches.default.delete(marker);
    await storeScan(env, event);
  }
}

async function storeScan(env, event) {
  const rand = hex(crypto.getRandomValues(new Uint8Array(4)));
  const meta = {};
  for (const [k, v] of Object.entries(event)) if (v !== undefined && v !== '') meta[k] = v;
  while (JSON.stringify(meta).length > 1000 && meta.ua) meta.ua = meta.ua.slice(0, meta.ua.length - 40);
  await env.PORTAL_KV.put(`scan:${event.t}:${rand}`, '', {
    metadata: meta,
    expirationTtl: SCAN_RETENTION_DAYS * 86400,
  });
}

function unq(v) { return String(v || '').replace(/^"|"$/g, '').trim(); }

function isBot(ua) {
  return /bot|crawl|spider|slurp|preview|facebookexternalhit|embedly|whatsapp|telegram|discord|skype|curl|wget|python|httpclient|headless/i.test(ua);
}

function deviceSummary(ua, model) {
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android'
    : /Windows/.test(ua) ? 'Windows' : /Macintosh|Mac OS X/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'ChromeOS'
    : /Linux/.test(ua) ? 'Linux' : 'other';
  const browser = /Edg\//.test(ua) ? 'Edge' : /SamsungBrowser/.test(ua) ? 'Samsung' : /CriOS|Chrome\//.test(ua) ? 'Chrome'
    : /FxiOS|Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'other';
  const name = model ? (phoneName(model) || model) : '';
  return name ? `${name} ${browser}` : `${os} ${browser}`;
}

// Samsung reports model codes; map the common recent ones to their names (Pixel and most others report names).
const SAMSUNG = [['SM-S93', { 1: 'Galaxy S25', 6: 'Galaxy S25+', 8: 'Galaxy S25 Ultra', 7: 'Galaxy S25 Edge' }],
  ['SM-S92', { 1: 'Galaxy S24', 6: 'Galaxy S24+', 8: 'Galaxy S24 Ultra' }], ['SM-S72', { 1: 'Galaxy S24 FE' }],
  ['SM-S91', { 1: 'Galaxy S23', 6: 'Galaxy S23+', 8: 'Galaxy S23 Ultra' }], ['SM-S71', { 1: 'Galaxy S23 FE' }],
  ['SM-S90', { 1: 'Galaxy S22', 6: 'Galaxy S22+', 8: 'Galaxy S22 Ultra' }],
  ['SM-F95', { 6: 'Galaxy Z Fold6' }], ['SM-F94', { 6: 'Galaxy Z Fold5' }], ['SM-F74', { 1: 'Galaxy Z Flip6' }],
  ['SM-F73', { 1: 'Galaxy Z Flip5' }], ['SM-A16', { 6: 'Galaxy A16 5G' }], ['SM-A15', { 6: 'Galaxy A15 5G' }],
  ['SM-A25', { 6: 'Galaxy A25 5G' }], ['SM-A35', { 6: 'Galaxy A35 5G' }], ['SM-A55', { 6: 'Galaxy A55 5G' }]];
function phoneName(model) {
  for (const [prefix, map] of SAMSUNG) {
    if (model.startsWith(prefix)) { const d = model.charAt(prefix.length); if (map[d]) return map[d]; }
  }
  return '';
}

function osVersion(ua, chPlatform, chVersion) {
  if (chPlatform && chVersion) return `${chPlatform} ${chVersion}`.slice(0, 30);
  const ios = ua.match(/(?:iPhone|CPU) OS (\d+)_(\d+)/);
  if (ios) {
    // iOS 26 and later freeze the "OS 18_x" token; Safari's own version then matches the real iOS version.
    const safari = ua.match(/Version\/(\d+)\.(\d+)/);
    if (safari && Number(safari[1]) >= 26) return `iOS ${safari[1]}.${safari[2]}`;
    return `iOS ${ios[1]}.${ios[2]}`;
  }
  const android = ua.match(/Android (\d+(?:\.\d+)?)/);
  if (android) return `Android ${android[1]}`;
  const win = ua.match(/Windows NT (\d+\.\d+)/);
  if (win) return `Windows ${win[1]}`;
  const mac = ua.match(/Mac OS X (\d+)[_.](\d+)/);
  if (mac) return `macOS ${mac[1]}.${mac[2]}`;
  return '';
}

function browserVersion(ua, fullList) {
  const brands = [...fullList.matchAll(/"([^"]+)";v="([^"]+)"/g)].map((m) => [m[1], m[2]])
    .filter(([b]) => !/Not.?A.?Brand|Chromium/i.test(b));
  if (brands.length) return `${brands[0][0]} ${brands[0][1]}`.slice(0, 40);
  const m = ua.match(/(Edg|SamsungBrowser|CriOS|FxiOS|Firefox|Chrome)\/([\d.]+)/) || ua.match(/Version\/([\d.]+).*Safari/);
  if (!m) return '';
  return m.length === 3 ? `${{ Edg: 'Edge', SamsungBrowser: 'Samsung Internet', CriOS: 'Chrome', FxiOS: 'Firefox' }[m[1]] || m[1]} ${m[2]}`
    : `Safari ${m[1]}`;
}

// A rough guess from the network owner: big US mobile carriers mean cellular; anything else is Wi-Fi or wired.
function connectionGuess(org, asn) {
  if (/T-Mobile|Cellco|Verizon Wireless|AT&T Mobility|Sprint|U\.?S\.? Cellular|Cricket|Boost|Dish Wireless|Visible|Mint Mobile|Metro ?PCS/i.test(org)
      || [21928, 22394, 6167, 20057].includes(Number(asn))) return 'cellular';
  return org ? 'Wi-Fi or wired' : '';
}

function refOrigin(ref) {
  if (!ref) return '';
  try { return new URL(ref).origin.slice(0, 80); } catch { return ''; }
}

// ---------- Private scan log page: /scans?k=KEY (and /scans.csv?k=KEY) ----------
// The link's key is the credential, like the upload portal's client links. Only a SHA-256 hash of each key is kept,
// as the KV key "scanview:<hash>", so the key itself is stored nowhere on Cloudflare. A missing or wrong key gets the
// site's normal 404, so the page does not reveal that it exists. Delete the KV key to revoke a link.
// Options: &days=7|30|90 (default all), &all=1 (include bots, link previews and ?test scans).
const SCAN_SOURCES = { card: 'Business card (/c)', 'capability-statement': 'Capability statement (/cs)' };

async function scanLogPage(request, env, url) {
  const key = url.searchParams.get('k') || '';
  const ok = key.length >= 32 && env.PORTAL_KV &&
    (await env.PORTAL_KV.get(`scanview:${await sha256Hex(key)}`)) !== null;
  if (!ok) return env.ASSETS.fetch(new Request(`${url.origin}/404`)).then((r) => new Response(r.body, {
    status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }));

  const days = parseInt(url.searchParams.get('days') || '', 10) || 0;
  const all = url.searchParams.get('all') === '1';
  let scans = [];
  let cursor;
  for (let i = 0; i < 20; i++) {                         // up to 20,000 scans
    const page = await env.PORTAL_KV.list({ prefix: 'scan:', limit: 1000, cursor });
    for (const k of page.keys) scans.push({ ...(k.metadata || {}), t: (k.metadata && k.metadata.t) || '' });
    if (page.list_complete) break;
    cursor = page.cursor;
  }
  const total = scans.length;
  if (!all) scans = scans.filter((s) => !s.bot && !s.test);
  if (days) { const since = Date.now() - days * 86400000; scans = scans.filter((s) => Date.parse(s.t) >= since); }
  scans.sort((a, b) => (a.t < b.t ? 1 : -1));

  const headers = {
    'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow', 'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
  };
  if (url.pathname === '/scans.csv') {
    const cols = ['time_eastern', 'time_utc', 'piece', 'city', 'region', 'zip', 'metro_code', 'country', 'latitude', 'longitude',
      'network_owner', 'asn', 'connection_guess', 'round_trip_ms', 'cloudflare_data_center', 'http', 'device', 'model', 'os',
      'browser', 'language', 'referrer', 'visitor', 'bot', 'test', 'restored', 'user_agent'];
    const csv = (v) => { const s = v === undefined || v === null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const lines = [cols.join(',')].concat(scans.map((s) => [eastern(s.t), s.t, SCAN_SOURCES[s.src] || s.src, s.city, s.region,
      s.zip, s.metro, s.country, s.lat, s.lon, s.org, s.asn, s.conn, s.rtt, s.colo, s.proto, s.device, s.model, s.os, s.browser,
      s.lang, s.ref, s.vid, s.bot ? 'yes' : '', s.test ? 'yes' : '', s.restored ? 'yes' : '', s.ua]
      .map(csv).join(',')));
    return new Response(lines.join('\n') + '\n', { headers: { ...headers, 'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="qr-scans.csv"' } });
  }

  const count = (fn) => {
    const m = new Map();
    for (const s of scans) { const k = fn(s) || '(unknown)'; m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };
  const place = (s) => [s.city, [s.region, s.zip].filter(Boolean).join(' '), s.country].filter(Boolean).join(', ');
  const link = (extra) => {
    const p = new URLSearchParams({ k: key });
    for (const [a, b] of Object.entries(extra)) if (b) p.set(a, b);
    return `/scans?${p.toString()}`;
  };
  const tally = (title, rows, max = 12) => `<section class="card"><h2>${esc(title)}</h2>` +
    (rows.length ? `<table>${rows.slice(0, max).map(([k, n]) => `<tr><td>${esc(k)}</td><td class="n">${n}</td></tr>`).join('')}</table>`
      : '<p class="muted">None yet.</p>') + '</section>';
  const visitors = new Set(scans.map((s) => s.vid)).size;
  const byPiece = Object.keys(SCAN_SOURCES).map((src) => [SCAN_SOURCES[src], scans.filter((s) => s.src === src).length]);
  const rangeLinks = [['All time', 0], ['Last 7 days', 7], ['Last 30 days', 30], ['Last 90 days', 90]]
    .map(([label, d]) => `<a class="${d === days ? 'on' : ''}" href="${esc(link({ days: d || '', all: all ? '1' : '' }))}">${label}</a>`).join('');
  const toggle = `<a class="${all ? 'on' : ''}" href="${esc(link({ days: days || '', all: all ? '' : '1' }))}">${all ? 'Hide' : 'Show'} bots and tests</a>`;
  const rows = scans.map((s) => `<tr>
      <td class="nowrap">${esc(eastern(s.t))}</td><td>${esc(SCAN_SOURCES[s.src] || s.src || '')}</td><td>${esc(place(s))}</td>
      <td>${esc(s.org || '')}<div class="muted small">${esc([s.conn, s.rtt ? `${s.rtt} ms` : ''].filter(Boolean).join(', '))}</div></td>
      <td class="nowrap">${esc(s.device || '')}<div class="muted small">${esc([s.model && !String(s.device || '').includes(String(s.model).split(' (')[0]) ? s.model : '', s.os, s.browser].filter(Boolean).join(', '))}</div></td>
      <td>${esc(s.lang || '')}</td>
      <td class="mono">${esc((s.vid || '').slice(0, 8))}</td>
      <td>${[s.bot ? 'bot' : '', s.test ? 'test' : '', s.restored ? 'restored' : ''].filter(Boolean).map((f) => `<span class="tag">${f}</span>`).join(' ')}</td>
    </tr>`).join('');

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" /><meta name="robots" content="noindex, nofollow" />
<title>QR scan log | Mt. Zion Capital</title><link rel="icon" href="/favicon.svg" type="image/svg+xml" />
<style>
  :root { --pine:#1f3d34; --brass:#c19a4b; --cream:#faf7f2; --cream2:#f2ece1; --ink:#22201c; --muted:#6b6459; --line:#e7e0d3; }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--cream); color: var(--ink); font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Calibri, Arial, sans-serif; }
  header { background: var(--pine); color: var(--cream); padding: 18px 20px; }
  header h1 { margin: 0; font-size: 22px; } header p { margin: 4px 0 0; color: #d8b96f; font-size: 13px; }
  main { max-width: 1100px; margin: 0 auto; padding: 18px 16px 40px; }
  .bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; }
  .bar a { text-decoration: none; color: var(--pine); border: 1px solid var(--line); background: #fff; padding: 6px 10px; border-radius: 6px; font-size: 13px; }
  .bar a.on { background: var(--pine); color: var(--cream); border-color: var(--pine); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-bottom: 14px; }
  .stat { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
  .stat b { display: block; font-size: 26px; color: var(--pine); } .stat span { color: var(--muted); font-size: 13px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-bottom: 14px; }
  .card { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; overflow-x: auto; }
  .card h2 { margin: 0 0 8px; font-size: 14px; color: var(--pine); text-transform: uppercase; letter-spacing: .06em; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td, th { padding: 6px 8px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; border-top: 0; }
  td.n { text-align: right; font-weight: 700; color: var(--pine); width: 3em; }
  .small { font-size: 12px; } .nowrap { white-space: nowrap; } .mono { font-family: ui-monospace, Menlo, monospace; font-size: 12px; } .muted { color: var(--muted); }
  .tag { display: inline-block; background: var(--cream2); color: var(--muted); border-radius: 4px; padding: 0 6px; font-size: 12px; }
  footer { color: var(--muted); font-size: 12px; margin-top: 16px; }
</style></head><body>
<header><h1>QR scan log</h1><p>Mt. Zion Capital &middot; private page, keep this link to yourself &middot; updated ${esc(eastern(new Date().toISOString()))} Eastern</p></header>
<main>
  <div class="bar">${rangeLinks}${toggle}<a href="${esc(link({ days: days || '', all: all ? '1' : '' }).replace('/scans?', '/scans.csv?'))}">Download CSV</a></div>
  <div class="stats">
    <div class="stat"><b>${scans.length}</b><span>scans shown${all ? '' : ` (${total - scans.length} bots or tests hidden)`}</span></div>
    <div class="stat"><b>${visitors}</b><span>different visitors</span></div>
    ${byPiece.map(([label, n]) => `<div class="stat"><b>${n}</b><span>${esc(label)}</span></div>`).join('')}
  </div>
  <div class="grid">
    ${tally('Network owner', count((s) => s.org))}
    ${tally('Place', count(place))}
    ${tally('Device', count((s) => s.device))}
    ${tally('Connection (guess)', count((s) => s.conn))}
    ${tally('By day (Eastern)', count((s) => eastern(s.t).slice(0, 10)).sort((a, b) => (a[0] < b[0] ? 1 : -1)), 14)}
  </div>
  <section class="card"><h2>Every scan</h2>
    ${scans.length ? `<table><tr><th>Time (Eastern)</th><th>Piece</th><th>Place</th><th>Network owner</th><th>Device</th><th>Language</th><th>Visitor</th><th></th></tr>${rows}</table>`
      : '<p class="muted">No scans yet.</p>'}
  </section>
  <footer>Place, ZIP and the CSV's map point come from the visitor's internet provider, so they are approximate (often a few
  miles off). Network owner is the company or agency on office Wi-Fi, or the mobile carrier on cellular; the connection
  guess and round-trip time follow from it. iPhones never report their model; Android phones in Chrome do. Visitor is a scrambled code
  from the network address (the address itself is never stored), so the same code means the same network. Entries delete
  themselves about 13 months after the scan.</footer>
</main></body></html>`;
  return new Response(html, { headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" } });
}

async function sha256Hex(s) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', TEXT.encode(s))));
}

function eastern(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour === '24' ? '00' : p.hour}:${p.minute}`;
}

function esc(v) {
  return String(v === undefined || v === null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

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
