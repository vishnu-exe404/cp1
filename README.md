# Cyber Security Awareness Platform

A multi-page security operations hub: a home dashboard linking out to six real-time defense tools, each on its own page. No login required.

## Pages

| File | What it is |
|---|---|
| `index.html` | Home dashboard — hero, live metrics, and cards linking to each tool |
| `scanner.html` | Scam & SMS Scanner — risk score, extracted risk tokens, 1930 complaint draft |
| `email.html` | Email Scanner — same engine, tuned for phishing emails |
| `url-hunter.html` | URL Hunter — flags lookalike domains, risky TLDs, IP-based links |
| `apk-scanner.html` | APK Scanner — flags sideloaded/impersonating APKs and dangerous permission combos |
| `password-vault.html` | Password Vault — entropy and estimated crack-time |
| `quiz.html` | Quiz Challenge — spot-the-scam practice quiz |
| `cyber-theme.css` | Shared styling used by every page |
| `cyber-engine.js` | Shared detection logic used by every page |

No build step, no framework, no backend. Plain HTML/CSS/JS — each page is a normal link, so it works as a real multi-page website (and navigates with full page loads, not JS tab-switching).

## Run it locally

Open `index.html` in a browser and click through from there. On Windows you can also double-click `run-platform.bat`.

For a closer-to-production feel (some browsers restrict local file access for fonts/scripts), serve it with any static server, e.g.:

```bash
python3 -m http.server 8000
# then open http://localhost:8000
```

## Deploy for free with GitHub Pages

1. Push this repo to GitHub (see below).
2. On GitHub, go to **Settings → Pages**.
3. Under **Source**, choose the `main` branch and `/ (root)` folder, then **Save**.
4. GitHub gives you a live URL within a minute or two — `index.html` loads automatically at the root, and every other page is reachable at `/scanner.html`, `/email.html`, etc.

## Push this to GitHub

```bash
git init
git add .
git commit -m "Initial commit: cyber security awareness platform"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

Create the empty repo on GitHub first (github.com → New repository), then swap in its URL above.
