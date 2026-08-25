# Mt. Zion Capital LLC — website

Multi-page marketing site for Mt. Zion Capital LLC. Plain HTML + CSS, no build step, no dependencies.

## Pages

| File | Purpose |
|------|---------|
| `index.html` | Home — hero, who we are, what we do, seller process, values, contact CTA |
| `about.html` | About us — story, the name (Psalm 125:1), founder bio |
| `careers.html` | Careers — open roles (currently the confidential GM search) |
| `contact.html` | Contact — email, phone (spam-protected), in-person |
| `404.html` | Not-found page |
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

- **Job postings** — `careers.html`, inside the `<article class="job-card">` block.
  Copy the block to add a second posting; delete it when a search closes.
- **Founder bio** — `about.html`, the `founder` section.
- **Contact email** — search all pages for `sales@mtzioncapital.com`.
- **Phone number** — `contact.html` only. It's stored base64-encoded so bots can't
  harvest it. To change it:
  ```bash
  python3 -c "import base64; print(base64.b64encode('+18595551234'.encode()).decode())"
  ```
  then replace the `enc = '...'` value in the script at the bottom of `contact.html`.

## Preview locally

```bash
python3 -m http.server 8000
```

Then open <http://localhost:8000>.
