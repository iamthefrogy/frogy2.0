<div align="center">

# Orbis - Attack Surface Intelligence
### Full-Spectrum Attack Surface Intelligence

[![BlackHat](https://img.shields.io/badge/BlackHat%20Arsenal-Presented-black?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsOSA1IDktNXYtNUwyIDEyeiIvPjwvc3ZnPg==)](https://www.youtube.com/watch?v=LHlU4CYNj1M)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)

**Orbis** automatically maps your organisation's entire internet-facing attack surface, subdomains, open ports, web applications, cloud infrastructure, TLS certificates, email posture, exposed secrets, login panels, and more, then scores and ranks every discovered asset so you know exactly where to focus first.

<img width="801" height="831" alt="image" src="https://github.com/user-attachments/assets/9e012767-ae54-4ee1-87dc-add602ecd0c8" />

<div align="left">
  
## What it does

You give it a list of domains. It does the rest.

```
google.com          →   Frogy 2.0 discovers:
apple.com                  • 2,000+ subdomains (passive + active enumeration)
example.com                • Every open port across all live hosts
                           • Every web application — status, tech stack, redirects
                           • Login panels, exposed .env files, leaked JS secrets
                           • TLS certificates, cipher strengths, expiry dates
                           • Subdomain takeover candidates (55+ service fingerprints)
                           • Cloud asset inventory (AWS / Azure / GCP / Cloudflare)
                           • SPF / DKIM / DMARC / DNSSEC coverage
                           • Screenshots of every website
                           → Risk-scored, prioritised, searchable HTML report
```

## Pipeline Overview

Frogy 2.0 runs a **22-step bash pipeline** against your targets, fully automated from discovery to report:

| Phase | Steps | What happens |
|-------|-------|-------------|
| **Discovery** | 1–6 | Subfinder + Assetfinder + crt.sh + GAU → merge + DNS resolve (A, AAAA, CNAME, MX, NS, SPF, DMARC, DNSSEC) |
| **Takeover** | 7 | CNAME chains checked against 55+ dangling-DNS fingerprints — Confirmed / Potential / Safe |
| **Port + Web** | 8–10 | Naabu port scan → HTTPX web fingerprint (follow redirects, tech stack, server, CORS, TLS) |
| **Exposed Files** | 11 | 100+ sensitive paths probed per site (`.env`, `.git/config`, `swagger.json`, private keys, backups…) |
| **Crawl + JS** | 12–13 | Katana deep crawl → JS file analysis (API keys, cloud credentials, internal URLs) |
| **Screenshots** | 14 | Visual snapshot of every live endpoint |
| **Security Analysis** | 15–18 | Login panel detection · TLS/cipher grading · header compliance · CORS / email auth checks |
| **Intelligence** | 19–21 | API surface mapping · employee portal classification · full cloud infrastructure inventory |
| **Score + Report** | 22 | Three-bucket risk scoring → change detection → self-contained HTML report |

> **Runtime estimates** (Docker, 2 vCPU / 4–8 GB, 50–100 Mbps):
> `≤100 subdomains` ~20–40 min · `100–999` ~45–120 min · `1k–10k` ~3–6 hrs · `10k+` ~8–18 hrs

## Key Features

<details>
<summary><b>Subdomain Discovery & DNS Intelligence</b></summary>

- Aggregates from **Subfinder**, **Assetfinder**, **crt.sh**, and **GAU** (Wayback Machine)
- Full DNS resolution: A, AAAA, CNAME, MX, NS, SPF, DMARC, DKIM, DNSSEC
- WHOIS registrar, creation date, expiry per domain
- Change detection — new assets, disappeared assets, new findings vs. previous scan
</details>

<details>
<summary><b>Web Fingerprinting with Redirect Intelligence</b></summary>

- HTTPX with `-follow-redirects` captures **final-hop metadata** (not the redirect page)
- **Redirect deduplication** in reports: HTTP:80 suppressed when HTTPS:443 exists for the same host — eliminates double-counting
- Technology stack, web server + version, CDN/WAF, content-length, status codes
</details>

<details>
<summary><b>Subdomain Takeover Detection</b></summary>

- 55+ service fingerprints: GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Azure, Fastly, Fly.io, and more
- Verified by fetching the expected error-page body
- **Confirmed** / **Potential** / **Safe** classification
- Takeover status feeds directly into the risk score
</details>

<details>
<summary><b>TLS / SSL Deep Analysis</b></summary>

- Cipher suite inspection: flags NULL, ANON, RC4, DES, 3DES, CBC
- Protocol version (TLS 1.3 down to SSL 3.0)
- Self-signed detection, wildcard SAN detection, broken handshakes
- Certificate expiry with colour-coded urgency (expired → within 7d → within 30d → ok)
</details>

<details>
<summary><b>Login Surface Detection</b></summary>

- Multi-signal heuristics: password/username fields, CSRF tokens, HTTP 401/403/407, JS auth libraries, multilingual sign-in keywords, CAPTCHA indicators
- Structured JSON output including **login panel type** (phpMyAdmin, Jenkins, Kubernetes Dashboard, Grafana, CMS admin, remote-access gateways)
- Type used by scoring engine to apply higher penalties for high-value panels
</details>

<details>
<summary><b>Cloud Infrastructure Mapping</b></summary>

- Covers AWS, Azure, GCP, Cloudflare, Vercel, Netlify, Fastly, Heroku, Fly.io, DigitalOcean, Hetzner
- Resource type classification: CDN, load balancer, object storage, managed DB, API gateway, serverless
- Shielding status: WAF/CDN-protected vs. direct-origin exposure
</details>

<details>
<summary><b>Crawl-Based Complexity Scoring</b></summary>

- Katana crawls every live site (configurable depth)
- **Deduplicated unique page count** per endpoint: numeric path segments normalised (`/users/123` → `/users/{id}`), query strings stripped
- Log-scaled score contribution (+2 to +12) — measures real application complexity, not URL count inflation
</details>

## Risk Scoring

Every endpoint is scored through **three capped buckets** (max 100). The aggregate report score is the **mean of the top-5 domain endpoint scores**.

| Bucket | Cap | Measures |
|--------|-----|----------|
| **Exposure** | 45 | Directly dangerous or reachable attack surfaces |
| **Hygiene** | 35 | Misconfigurations, certificate health, compliance gaps |
| **Sensitivity** | 20 | Asset criticality, stack complexity, data-handling classification |

<details>
<summary><b>Exposure signals</b></summary>

| Signal | Points |
|--------|--------|
| Login interface served over HTTP | +20 |
| Authenticated surface (HTTPS login) | +12 |
| High-value login panel (phpMyAdmin, Jenkins, k8s, Portainer, Grafana, remote-access) | +8 – +10 bonus |
| Confirmed subdomain takeover | +15 – +20 |
| Potential subdomain takeover (dangling CNAME) | +8 – +12 |
| Admin tool visible in page title (Kibana, Grafana, Jenkins…) | +10 |
| Directory listing enabled (`Index of /`) | +10 |
| Management port(s) exposed | up to +15 |
| Database port(s) exposed | up to +12 |
| Open internet services (port count) | up to +14 |
| Unique crawlable pages (log-scaled) | up to +12 |
| Cloud workload / CDN without WAF shielding | +8 – +12 |
| Infrastructure management interface in tech stack | +6 |
| TLS handshake failure | +6 |
| HTTP 403 (resource exists, blocked by auth) | +4 |
| 5xx server error | +4 |
</details>

<details>
<summary><b>Hygiene signals</b></summary>

| Signal | Points |
|--------|--------|
| TLS certificate expired | +20 |
| Deprecated SSL 3.0 protocol | +18 |
| NULL / anonymous cipher suite | +18 |
| RC4 / DES / 3DES broken cipher | +12 |
| Legacy TLS 1.0 / 1.1 | +12 |
| CORS wildcard `*` | +12 |
| CORS null-origin allowed | +10 |
| End-of-life server (Apache 2.x / nginx ≤1.17 / PHP 5–7) | +10 |
| Certificate expires within 7 days | +12 |
| Self-signed certificate | +8 |
| Error / debug / stack trace page public | +8 |
| Legacy protocol / deprecated cipher support | +8 |
| CBC cipher in use (BEAST / POODLE) | +6 |
| Development server exposed (Werkzeug, Flask dev) | +6 |
| Certificate expires within 30 days | +6 |
| Missing security headers (HSTS, CSP, X-Frame-Options…) | up to +12 |
| DMARC not published | +6 |
| SPF not published | +4 |
| Certificate validity unknown | +4 |
| Wildcard TLS certificate | +4 |
| DKIM not published | +3 |
| DNSSEC not enabled | +2 |
| Server version disclosed in headers | +5 |
</details>

<details>
<summary><b>Sensitivity signals</b></summary>

| Signal | Points |
|--------|--------|
| Employee-facing / internal asset | +12 |
| Admin / monitoring tool in stack (Kibana, Grafana, Jenkins, phpMyAdmin, k8s Dashboard) | +12 |
| Crawl surface size — unique deduplicated pages (log-scaled) | up to +12 |
| Identity / auth service (Keycloak, Okta, Auth0, LDAP, SAML) | +8 |
| Object storage endpoint exposed | +8 |
| Error / debug page publicly visible | +8 |
| Non-production environment in title (dev / staging / test / UAT) | +6 |
| API surface detected | +6 |
| CMS admin surface (WordPress, Drupal, Magento) | +6 |
| Managed database footprint reachable | +7 |
| Cloud API / serverless resource | +5 |
| Cloud managed surface | +3 |
| Full-stack framework detected (dynamic app indicator) | +2 |
| Authentication-protected surface (HTTP 401) | +3 |
</details>

> **Why it matters:** - An internal admin panel with an expired self-signed cert, a wildcard CORS header, and port 3306 exposed scores far higher than a static marketing page — so your team skips the noise and starts where it matters.

**Why This Matters** - This approach helps you quickly **prioritize** which assets warrant deeper testing. Subdomains with high counts of open ports, advanced internal usage, missing headers, or login panels are more complex, more privileged, or more likely to be misconfigured—therefore, your security team can focus on those first.


# Screenshots

<img width="1236" height="747" alt="image" src="https://github.com/user-attachments/assets/55361436-bd53-4913-ac97-e6afb892a769" />
<img width="1217" height="755" alt="image" src="https://github.com/user-attachments/assets/db8992c2-26e4-491a-bcf2-5eb7c0a39bfa" />
<img width="1219" height="755" alt="image" src="https://github.com/user-attachments/assets/877a7f2e-6738-43d1-9597-6c49bd85539b" />
<img width="1218" height="743" alt="image" src="https://github.com/user-attachments/assets/89fde7f5-0000-49d4-98df-dc961d9083df" />

## Quick Start

### 1. Build the Docker image

```bash
git clone https://github.com/iamthefrogy/frogy2.0.git
cd frogy2.0
chmod 777 *
docker build -t frogy:latest .
```

### 2. Run the container

**Linux** (native Docker — `--network host` works):
```bash
docker run --rm --network host --privileged --cap-add=NET_RAW \
  -v "$(pwd)/output:/opt/frogy/output" \
  frogy:latest
```

**macOS / Windows** (Docker Desktop — no `--network host`):
```bash
docker run --rm --privileged --cap-add=NET_RAW \
  -p 8787:8787 \
  -v "$(pwd)/output:/opt/frogy/output" \
  frogy:latest
```

> `-v "$(pwd)/output:/opt/frogy/output"` persists scan history across container restarts.

### 3. Open the dashboard

```
http://localhost:8787
```

Access-key authentication is required on first load. The key is printed to container stdout on startup.

## Report Tour

The generated report is a **self-contained HTML file** — no server needed, open it in any browser.

| Tab | Contents |
|-----|----------|
| **Overview** | Executive banner (risk score + grade + 4 metric groups) · 9-chart analytics grid · risk leaderboard |
| **Domain Intelligence** | All subdomains · DNS records · email auth posture (SPF/DKIM/DMARC/DNSSEC) · WHOIS |
| **Application Endpoints** | Every live endpoint — status, title, tech stack, login detection, security headers, CORS, CDN, screenshots · Table or Gallery view |
| **IP Addresses** | Reverse DNS · ASN · network blocks · geolocation |
| **TLS Certificates** | Cipher · protocol version · expiry (colour-coded) · SANs · issuer · grade |
| **Cloud Infrastructure** | Asset map by provider · resource type · shielding status |
| **Subdomain Takeover** | Confirmed + potential findings with provider + evidence |
| **Exposed Files** | Sensitive paths reachable on live hosts |
| **JS Findings** | Secrets and internal URLs extracted from JavaScript |
| **Changes** | Delta vs. previous scan — new / disappeared assets, new findings |

**Every table** has full-text search, column filters, and CSV + JSON export.

---

## Orbis Dashboard

The web UI at `localhost:8787` is branded **Orbis — Full-Spectrum Attack Surface Intelligence**.

- **Project cards** — status badge, live progress bar (`Step X of 22`), elapsed/total duration
- **KPI row** — Total projects · Active scans · Completed · Queued
- **Filter tabs** — All / Running / Done / Queued
- **View Logs** — live log streaming side panel, polls every 1.5 s during active scans
- **Project detail page** — full per-project run history with individual report + log access
- **Bulk operations** — select multiple projects for batch deletion
- **Modify / Rescan / Cancel** any project from the `···` context menu
- **Dark / Light theme** — persisted via `frogyTheme` localStorage key (shared with reports)

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web dashboard | Python · Flask 3.x |
| Scanner pipeline | Bash 5.x · 22-step workflow |
| Subdomain discovery | Subfinder · Assetfinder · crt.sh · GAU |
| DNS resolution | DNSX |
| Port scanning | Naabu |
| Web fingerprinting | HTTPX |
| Web crawling | Katana |
| TLS analysis | tlsx |
| System utilities | jq · curl · whois · dnsutils · openssl |
| Container base | Ubuntu 24.04 · Go 1.24 (tool compilation) |

## BlackHat Arsenal

Frogy was presented at **BlackHat Arsenal**. Watch the full demo:

[![BlackHat Demo](https://img.shields.io/badge/▶%20Watch%20on%20YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=IayqiBe21h4)


## Acknowledgements

Special thanks to the [Project Discovery](https://projectdiscovery.io) team for building the open-source tools that power this pipeline (Subfinder, DNSX, Naabu, HTTPX, Katana, tlsx), and to [tomnomnom](https://github.com/tomnomnom) for Assetfinder. Keep rocking the community!

Built by [Chintan Gurjar](https://chintangurjar.com)



# Future Roadmap

- Completed ✅ ~~Adding security and compliance-related data (SSL/TLS hygiene, SPF, DMARC, Headers etc)~~
- Completed ✅ ~~Allow to filter column data.~~
- Completed ✅ ~~Add more analytics based on new data.~~
- Completed ✅ ~~Identify login portals.~~
- Completed ✅ ~~Basic dashboard/analytics if possible.~~
- Completed ✅ ~~Display all open ports in one of the table columns.~~
- Completed ✅ ~~Pagination to access information faster without choking or lagging on the home page.~~
- Completed ✅ ~~Change font color in darkmode.~~
- Completed ✅ ~~Identify traditional endpoints vs. API endpoints.~~
- Completed ✅ ~~Identifying customer-intended vs colleague-intended applications.~~
- Completed ✅ ~~Enhance prioritisation for target picking. (Scoring based on management ports, login found, customer vs colleague intended apps, security headers not set, ssl/tls usage, etc.)~~
- Completed ✅ ~~Implement parallel run, time out functionality.~~
- Completed ✅ ~~Scan SSL/TLS for the url:port pattern and not just domain:443 pattern.-~~
- Completed ✅ ~~Using mouseover on the attack surface column's score, you can now know why and how score is calculated-~~
- Completed ✅ ~~Generate CSV output same as HTML table.~~
- Completed ✅ ~~Self-contained HTML output is generated now. So no need to host a file on web server to access results.~~
- Completed ✅ ~~To add all DNS records (A, MX, SOA, SRV, CNAME, CAA, etc.)~~
- Completed ✅ ~~Consolidate the two CDN charts into one.~~
- Completed ✅ ~~Added PTR record column to the main table.~~
- Completed ✅ ~~Implemented horizontal and vertical scrolling for tables and charts, with the first title row frozen for easier data reference while scrolling.~~
- Completed ✅ ~~Added screenshot functionality.~~
- Completed ✅ ~~Added logging functionality. Logs are stored at /logs/logs.log~~
- Completed ✅ ~~Added extra score for the management and database ports exposed.~~
- Completed ✅ ~~Create Dockerized version.~~
- Completed ✅ ~~Added new subdomain enum capability using GAU (waybackurls).~~
- Completed ✅ ~~Now capable of crawling links per live application and also it adds the score of total crawled links to the main score.~~
- Completed ✅ ~~Added check_dependencies to verify all required tools are installed (subfinder, assetfinder, dnsx, naabu, httpx, katana, jq, curl, whois, dig, openssl, xargs, unzip, grep, sed, awk). The script now aborts with a clear list of missing tools.~~
- Completed ✅ ~~Added check_dependencies to verify all required tools are installed (subfinder, assetfinder, dnsx, naabu, httpx, katana, jq, curl, whois, dig, openssl, xargs, unzip, grep, sed, awk). The script now aborts with a clear list of missing tools.~~
- Completed ✅ ~~New trap on ERR with contextual message (exit code, command, file:line). New script_cleanup hooked to EXIT prints success/failure summary and points to the trace log.~~
- Completed ✅ ~~Improved CLI validation (usage message, file existence & readability checks).~~
- Completed ✅ ~~Added (optional) domain-line sanity validation.~~
- Completed ✅ ~~Verifies run/log directories are writable; keeps xtrace only in logs.log.~~
- Completed ✅ ~~Assetfinder: switched to parallel execution via xargs -P 10 over input domains.~~
- Completed ✅ ~~dnsx: added rate limit and thread tuning (-rl 50 -t 25).~~
- Completed ✅ ~~katana: added concurrency/rate limits and timeouts (-c 5 -rl 30 -timeout 15), still honors KATANA_DEPTH/KATANA_TIMEOUT.~~
- Completed ✅ ~~httpx: added tuned threads/rate-limit/timeouts (-t 25 -rl 80 -timeout 15).~~
- Completed ✅ ~~naabu Skips scanning with a clear warning when master_subdomains.txt is empty.~~
- Completed ✅ ~~httpx now runs a JSON pass first to build httpx.json and live counts, then a second pass for screenshots.~~
- Completed ✅ ~~Verifies default artifact directories are writable before capture.~~
- Completed ✅ ~~Introduced BLOCK_DETECTION_THRESHOLD (default 20%). If fewer than the threshold of web targets respond (derived from httpx.json vs naabu live targets), the run halts with guidance to rotate IP/VPN.~~
- Completed ✅ ~~Login surface detection overhaul - Uses per‑request mktemp files and explicit curl timeouts.~~
- Completed ✅ ~~Expanded heuristics (password/username fields, form attributes, submit labels, CSRF tokens, meta hints, CAPTCHA, modal hints, multilingual keywords, JS auth libraries, 401/403/407, WWW-Authenticate, session cookies, login redirects, URL patterns & query params).~~
- Completed ✅ ~~Emits structured JSON and increments LOGIN_FOUND_COUNT when detected.~~
- Completed ✅ ~~Colourised error output; clearer progress steps (e.g., [n/15]).~~
- Completed ✅ ~~Completeley revamped design for easy navigation.~~
- Completed ✅ ~~Added side panel to distribute data among Domain intel, application intel, cert intel, IP intel and cloud intel.~~
- Completed ✅ ~~Enforce data quality checks (valid domain syntax, duplicate detection, enrichment completion) before persisting records.~~
- Completed ✅ ~~Provide an option to hide the side panel.~~
- Completed ✅ ~~Export report in CSV + JSON format.~~
- Completed ✅ ~~Add the same search bar to all side panel reporting.~~
- Completed ✅ ~~User should be allowed to directly open UI and add targets there only.~~
- Completed ✅ ~~Implement brand new scoring logic.~~
- Completed ✅ ~~Implement brand new GUI, slick design and more adaptability~~
- Completed ✅ ~~Fix the URL redirection issue which was bumping score and no. of endpoints.~~

