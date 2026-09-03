# Mt. Zion Capital LLC — website

A single-page marketing site for Mt. Zion Capital LLC. Plain HTML + CSS, no build step, no dependencies. Hosted on **GitHub Pages**.

## Files

| File | Purpose |
|------|---------|
| `index.html` | The page (all content lives here) |
| `style.css` | Styling — warm pine + brass + cream palette |
| `favicon.svg` | Browser-tab icon (mountain mark) |
| `.nojekyll` | Tells GitHub Pages to serve files as-is (no Jekyll processing) |

> `wrangler.toml` and `.assetsignore` are leftovers from a Cloudflare scaffold. They're harmless on GitHub Pages — delete them if you don't plan to use Cloudflare.

## Editing content

Everything you'll want to change is plain text in `index.html`:

- **Headline / intro** — the `<section id="home">` block near the top.
- **About / What we do / Values** — the sections below it.
- **Contact email** — search the file for `sales@mtzioncapital.com` and replace (appears in the "Email us" button and the line beneath it).
- **Location** — search for `Union, KY` / `Union, Kentucky`.
- **Footer verse** — the `footer-verse` line (remove it if you'd rather not have it).

## Setting the phone number (spam-resistant)

The phone number is **not** written into the page as plain text — spam bots scrape
static HTML for phone patterns, so instead the number is stored **base64-encoded**
and assembled by JavaScript at load time (see the `<script>` at the bottom of
`index.html`). Bots that don't run JavaScript never see the digits.

To set your real number:

1. Encode it in `+1XXXXXXXXXX` form:
   ```bash
   python3 -c "import base64; print(base64.b64encode('+18595551234'.encode()).decode())"
   ```
2. Copy the output and replace the `enc = '...'` value in the `<script>` block of `index.html`.

The current value is already set to the site's live number — follow the steps above to change it.

> **Tip:** For the best real-world spam protection, point the site at a free
> **Google Voice** number (pick an **859** area code to reinforce "local"), and
> forward it to your cell. Google Voice screens spam calls and keeps your personal
> number private — so even if the number is ever harvested, you stay in control.

## Turning on GitHub Pages (one-time)

1. Push this repo to GitHub (branch `main`).
2. On GitHub: **Settings → Pages**.
3. Under **Build and deployment → Source**, choose **Deploy from a branch**.
4. Set **Branch** to `main` and folder to **`/ (root)`**, then **Save**.
5. Wait ~1 minute. Your site goes live at:
   **https://mattgrubbs.github.io/mtzioncapital-site/**

## Optional: use your own domain (mtzioncapital.com)

You already own `mtzioncapital.com` (you have email there), so you can serve the
site from it instead of the long github.io URL:

1. Create a file named `CNAME` in this repo containing one line: `mtzioncapital.com`
   (or `www.mtzioncapital.com`).
2. At your domain registrar / DNS host, add records pointing to GitHub Pages:
   - **A** records for the apex `mtzioncapital.com` → `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - or a **CNAME** for `www` → `mattgrubbs.github.io`
3. In **Settings → Pages → Custom domain**, enter the domain and enable **Enforce HTTPS**.
4. Update the `<link rel="canonical">` and `og:url` tags in `index.html` to the new domain.

## Preview locally

From this folder:

```bash
python3 -m http.server 8000
```

Then open <http://localhost:8000>.
