# PhishGuard – Phishing Detection System for LTC

A web-based phishing detection system for **Liberia Telecommunications Corporation (LTC)**. It analyses a website's URL, host and page content in real time and warns users before they enter sensitive information.

**Stack:** PHP 8.2 · MySQL/MariaDB (PDO) · vanilla JavaScript (ES2022) · HTML5 · modern CSS (nesting, `:has()`, `color-mix()`, `<dialog>`)

## Setup (XAMPP)
1. Start **Apache** and **MySQL** in the XAMPP Control Panel.
2. Open http://localhost/PhishGuard/install.php (or run `php install.php`).
3. Sign in at http://localhost/PhishGuard/login.php  
   Default admin: `admin@ltc.com.lr` / `Admin@123`. **Change it straight away** under Profile.
4. Delete or rename `install.php` once setup is done.

Settings (database, thresholds, timeouts) are in `config/config.php`.

## How the objectives map to the system
| Objective (Ch. 1.3.2) | Where it is implemented |
|---|---|
| Examine phishing characteristics | `awareness.php`: signs, examples, quiz |
| Design a detection model (URL + website analysis) | `includes/Detector.php`: weighted feature model |
| Develop a web-based detection system | `index.php`, `api/scan.php`, `result.php` |
| Real-time alert mechanism | Live check while typing + full-screen warning `<dialog>` |
| Evaluate performance & accuracy | `admin/evaluate.php`: accuracy, precision, recall, F1, confusion matrix |

## Detection model
Each feature adds risk points. The total (0–100) gives the verdict: **< 25 safe**, **25–49 suspicious**, **≥ 50 phishing**.

- **Reputation:** blacklist (always phishing), trusted list (always safe)
- **Lexical (URL):** length, IP-address host, `@` trick, `//` redirect, hyphens, sub-domain depth, missing HTTPS, abused TLDs, URL shorteners, sensitive keywords, **brand impersonation**, **look-alike domains** (Levenshtein distance + homoglyphs such as g00gle, paypa1), punycode, non-standard ports, digits, entropy, percent-encoding
- **Host:** DNS resolution, SSL certificate validity and age
- **Content:** password fields, forms posting to other domains, hidden iframes, brand name in the page title on a non-brand domain, meta-refresh, cross-domain redirects, empty or external links

Brand detection is driven by the **trusted domains** list (Admin → Blacklist & trusted). Give each domain a brand keyword and the engine flags any other domain that uses or imitates it.

## Roles
- **Guest:** scan, read awareness content, report sites
- **User:** everything a guest can do, plus a personal dashboard, scan history and profile
- **Admin:** threat overview, all scans (CSV export), review reports (confirming one blacklists the domain), manage lists and users, run evaluations

## Security measures
Prepared statements (PDO), `password_hash`, CSRF tokens on every POST, session regeneration on login, login throttling, scan rate limiting, output escaping, SSRF guard (no fetching of private/internal IPs), and `.htaccess` denying access to `config/`, `includes/` and `database/`.

## Evaluation dataset
`data/sample_dataset.csv` is a small demonstration set (30 phishing, 30 legitimate). The phishing examples are made up for illustration. For the Chapter 4 results, evaluate against a public dataset (e.g. PhishTank, OpenPhish, or the UCI / Mendeley phishing URL datasets) exported as `url,label`.
