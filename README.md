# Mt. Zion Capital LLC — website

Multi-page marketing site for Mt. Zion Capital LLC, plus a secure client document upload
portal. The site is plain HTML + CSS with no build step. The portal is a small Cloudflare
Worker (`src/worker.js`).

**All public site files live in `public/`.** That folder is the only thing Cloudflare
serves; server code, scripts, and config sit outside it on purpose.

## Pages (in `public/`)

| File | Purpose |
|------|---------|
| `index.html` | Home — hero, who we are, what we do, seller process, values, contact CTA |
| `about.html` | About us — story, the name (Psalm 125:1), founder bio |
| `careers.html` | Careers — open roles (currently the confidential GM search) |
| `contact.html` | Contact — email, phone (spam-protected), in-person |
| `404.html` | Not-found page |
| `upload.html` / `upload.js` / `upload.css` | **Secure client document upload** (unlisted; see section below) |
| `_headers` | Security headers (CSP, HSTS, noindex for the upload page) |

Outside `public/` (never served): `src/worker.js` (the Worker), `scripts/` (operator
commands: setup, set password, manage client links), `wrangler.toml`, `package.json`.
| `site.css` | Shared stylesheet — pine + brass + cream palette |
| `favicon.svg` | Browser-tab icon (mountain mark) |
| `robots.txt` / `sitemap.xml` | SEO plumbing (archive/ is excluded from crawling) |
| `archive/` | The previous one-page site, kept for reference |

## Hosting — how the live site actually works

The **live site at www.mtzioncapital.com is served by Cloudflare** (Workers static
assets, configured by `wrangler.toml`), NOT by GitHub Pages. GitHub hosts the code,
and a copy also renders at https://mattgrubbs.github.io/mtzioncapital-site/, but the
custom domain points at Cloudflare.

**To publish: just `git push` to `main`.** The Cloudflare project is connected to
this GitHub repo and auto-deploys in about 2–3 minutes (verified 2026-08-25).

Cloudflare serves clean extensionless URLs — `mtzioncapital.com/careers.html`
redirects to `mtzioncapital.com/careers`. Share the extensionless form.

## Editing content

- **Job postings** — `careers.html`. It currently shows a coming-soon panel; to
  publish a role, replace that panel with an `<article class="job-card">` block
  (the format is in git history) and update the page's `meta description`.
- **Founder bio** — `about.html`, the `founder` section.
- **Contact email** — search all pages for `sales@mtzioncapital.com`.
- **Phone number** — `contact.html` only. It's stored base64-encoded so bots can't
  harvest it. To change it:
  ```bash
  python3 -c "import base64; print(base64.b64encode('+18595551234'.encode()).decode())"
  ```
  then replace the `enc = '...'` value in the script at the bottom of `contact.html`.

## Preview locally

The full site including the upload portal runs locally with simulated storage:

```bash
npm install          # once
cp .dev.vars.example .dev.vars   # once, then fill in a local password hash (see file)
npm run dev          # http://localhost:8787
```

For a quick static-only look (upload page will not function): `cd public && python3 -m http.server 8000`.

---

## Secure client upload portal (`/upload`)

An unlisted page where clients send financial documents instead of emailing them:
**https://www.mtzioncapital.com/upload**. It is not in the menu, not in the sitemap,
and marked `noindex`. Each client gets a **personal link**; the link itself is the key, so
there is nothing for them to type and no shared password to leak.

### How it protects documents

| Layer | What happens |
|-------|--------------|
| In transit | HTTPS with modern TLS, terminated at Cloudflare's edge. |
| Access | Default `link` mode: a personal URL per client (`/upload?c=<token>`, a 256-bit random token that cannot be guessed) checked **on the server**, revocable one at a time, with optional expiry. Password modes (optional) use a PBKDF2-SHA256 hash held in a Cloudflare secret with constant-time comparison. |
| Bots | Cloudflare Turnstile on the password step (once you enable it). |
| Brute force | 10 login attempts per IP per 10 minutes, then a 429. |
| Session | 30-minute signed (HMAC-SHA256) cookie, HttpOnly, Secure, SameSite=Strict, scoped to `/api/upload`. |
| Cross-site abuse | Every POST must come from our own origin and carry a custom header browsers never add cross-site. |
| Files | Extension allowlist **and** file-signature check (a renamed .exe is refused), 50 MB cap, filenames sanitized, stored under random unguessable keys. |
| At rest | Private R2 bucket `mtzion-client-uploads`, encrypted at rest, no public access, never served back by the site. |
| Retention | Lifecycle rule deletes uploads after 90 days. |
| Privacy in logs | Only a keyed hash of the uploader's IP is logged or stored, never the IP itself. No file contents in logs. |

What it does **not** do: end-to-end encryption in the browser. Cloudflare (as the storage
provider) and anyone with your Cloudflare login can read the files. That makes **your
Cloudflare account the crown jewels**: turn on two-factor authentication there.

### One-time setup

```bash
cd "~/Desktop/Jesus is Lord/mtzioncapital-site"
npm install
npx wrangler login        # opens your browser; approve once
npm run setup             # creates bucket, KV, retention rule, secrets (asks for a password only in password modes)
```

`npm run setup` edits `wrangler.toml` (fills in the KV namespace id). Commit and push it:

```bash
git add wrangler.toml && git commit -m "Portal: KV namespace id" && git push
```

Cloudflare auto-deploys in a few minutes. Then open `/upload`, enter the password, and
send yourself a test PDF. Find it under **Cloudflare dashboard -> R2 -> mtzion-client-uploads**.

Recommended follow-ups:

- **Turnstile** (bot protection): dashboard -> Turnstile -> Add widget (domain
  `mtzioncapital.com`, mode Managed), then `npm run set-turnstile`, then commit and push
  `wrangler.toml`.
- **Two-factor auth on your Cloudflare account** (My Profile -> Authentication).
- **Workers Paid plan ($5/month)** if you expect steady use. The free plan is fine to start,
  but Paid removes the tight CPU budget and raises the request body limit.

### Day-to-day

**Give a client access.** Create a personal link per client or deal and send it to them.
The link is the key: nothing to type, and you can shut off any one link without affecting
anyone else.

```bash
npm run link:create -- --label "Acme HVAC (Bob Smith)"
npm run link:create -- --label "Acme HVAC" --days 30        # expires in 30 days
```

It prints a link like `https://www.mtzioncapital.com/upload?c=<token>`. Files uploaded
through it land in a folder named after the label, so you can tell who sent what. Send
links by text or a separate message when you can: a link forwarded to the wrong person can
upload (never read) until you revoke it.

```bash
npm run link:list
npm run link:revoke -- <first 8+ characters of the token>
npm run link:delete -- <token>
```

**Access modes** (`ACCESS_MODE` in `wrangler.toml`; change it, commit, push):

| Mode | Who gets in |
|------|-------------|
| `link` (default) | Anyone who opens a valid personal link. No password. |
| `password` | Anyone with the shared password at `/upload`. Links are optional and only label who sent what. |
| `link+password` | Both a valid personal link and the shared password. `--no-password` on a link exempts that one client. |

Password modes need a password set first: `npm run set-password`.

**Get the files.** Dashboard -> R2 -> `mtzion-client-uploads` -> `uploads/YYYY-MM-DD/<client>/`.
Click a file to download. Its **custom metadata** shows the uploader's name, company, note,
and which link they used. Download what you need and delete what you don't; the 90-day rule
handles the rest.

**Change the password** (password modes only). `npm run set-password` (or
`npm run set-password -- --generate` to have a strong one made for you). Takes effect immediately.

**Watch activity.** Dashboard -> Workers & Pages -> mtzioncapital -> Logs, or live:
`npm run tail`. Events: `auth_ok`, `auth_failed`, `auth_ratelimited`, `link_rejected`,
`upload_ok`, `content_mismatch`, `turnstile_failed`.

### Settings (`wrangler.toml` -> `[vars]`)

| Var | Default | Meaning |
|-----|---------|---------|
| `MAX_FILE_MB` | 50 | Per-file size cap (keep under 95). |
| `SESSION_TTL_MIN` | 30 | Minutes a login lasts. |
| `ACCESS_MODE` | link | `link` (personal URL is the key), `password` (shared password), or `link+password` (both). |
| `RETENTION_DAYS` | 90 | Shown on the page. The actual deletion is the R2 lifecycle rule created by setup (change both). |
| `TURNSTILE_SITE_KEY` | empty | Public Turnstile key; empty = Turnstile off. |

Secrets (never in the repo): `UPLOAD_PASSWORD_HASH`, `SESSION_SECRET`, `TURNSTILE_SECRET_KEY`.

### Troubleshooting

- Page says **"Almost ready"**: a secret is missing (`SESSION_SECRET`, or `UPLOAD_PASSWORD_HASH` in a password mode). Run `npm run setup` (or `npm run set-password`).
- Page says **"A personal upload link is required"**: the visitor opened `/upload` without their `?c=` link. Send them their link (`npm run link:list` shows all of them).
- Deploy fails mentioning **KV namespace** or `00000000…`: `npm run setup` has not been run, or its `wrangler.toml` change was not pushed.
- Logins fail with **CPU limit** errors in the logs (free plan): `npm run set-password -- --iterations 50000`, or move to Workers Paid.
- Turnstile shows an error locally: expected; leave `TURNSTILE_SITE_KEY` empty for local dev.
- Never commit `.dev.vars`. It is gitignored and excluded from the deployed assets.
