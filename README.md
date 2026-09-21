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
- **Domain (every full scan):** does the domain really exist? (DNS-over-HTTPS via Google/Cloudflare, so ISP resolvers cannot fake it) · is it registered, and how old is it? (RDAP, cached 12 h) · does a website actually respond? · optional **Google Safe Browsing** (set `SAFE_BROWSING_API_KEY` in `config/config.php`). A domain that does not exist or does not respond is **never** reported as safe.
- **Host (deep scan):** SSL certificate validity and age
- **Content:** password fields, forms posting to other domains, hidden iframes, brand name in the page title on a non-brand domain, meta-refresh, cross-domain redirects, empty or external links

Brand detection is driven by the **trusted domains** list (Admin → Blacklist & trusted). Give each domain a brand keyword and the engine flags any other domain that uses or imitates it.

## Layouts
Each area has its own navigation, and links never cross between them (`includes/header.php`):
- **Public site** (`index.php`, `awareness.php`, `report.php` for guests): top navigation bar.
- **User area** (`dashboard.php`, `scan.php`, `history.php`, `report.php`, `profile.php`): user sidebar.
- **Admin console** (`admin/*`): admin sidebar with a pending-reports badge.

Sidebars collapse to icons on desktop (the choice is remembered) and become a slide-in drawer below 1024px. On phones, tables turn into stacked cards.

## Roles
- **Guest:** scan, read awareness content, report sites
- **Staff user:** everything a guest can do, plus a personal dashboard (position, responsibilities, assigned investigations), **My tasks** for submitting findings, scan history and profile
- **Admin:** threat overview, all scans (CSV export), reports (assign to staff, read findings, confirm/reject; confirming blacklists the domain), lists, users (position and responsibilities per staff member), evaluations

### Staff responsibilities and investigations
When an admin creates a staff member, they choose a **position** (e.g. Cybersecurity Analyst, ICT Support Officer, Customer Care Officer). This pre-fills that position's standard **responsibilities**, which can be edited. Both appear on the staff member's dashboard. New accounts must replace their temporary password at first sign-in.

Admins can assign any pending report to a staff member. It appears on that person's dashboard and under **My tasks**, where they scan the URL and submit a finding with a note. The admin then makes the final decision.

## Tests and demo data
```
C:\xampp\php\php.exe tests\run_tests.php            # 33 unit, network, integration and performance tests
C:\xampp\php\php.exe database\demo_seed.php          # load demo staff, scans, reports
C:\xampp\php\php.exe database\demo_seed.php --remove # remove demo data
```
Existing installs: apply `database/migrate_v2.sql` and `database/migrate_v3.sql`. Re-running `install.php` also applies them.

## Documentation assets
- `docs/figures/`: system screenshots and design diagrams used in the report
- `docs/diagrams/`: editable HTML/SVG sources of the diagrams
- `docs/report-builder/`: script that generated the Chapters 1–6 Word document (`npm install docx@9`, then `node build.js out.docx`)

## Security measures
Prepared statements (PDO), `password_hash`, CSRF tokens on every POST, session regeneration on login, login throttling, scan rate limiting, output escaping, SSRF guard (no fetching of private/internal IPs), and `.htaccess` denying access to `config/`, `includes/` and `database/`.

## Evaluation dataset
`data/sample_dataset.csv` is a small demonstration set (30 phishing, 30 legitimate). The phishing examples are made up for illustration. For the Chapter 4 results, evaluate against a public dataset (e.g. PhishTank, OpenPhish, or the UCI / Mendeley phishing URL datasets) exported as `url,label`.
