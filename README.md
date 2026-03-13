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
                           • SPF / DKIM / DMARC / DNSSEC / BIMI / MTA-STS / DANE
                           • Third-party vendor dependencies across all surfaces
                           • Interactive asset relationship graph
                           → Risk-scored, prioritised, searchable HTML report
```

## Pipeline Overview

Frogy 2.0 runs a **31-step bash pipeline** against your targets — fully automated from discovery to report, all stages run unconditionally.

| Phase | Steps | What happens |
|-------|-------|-------------|
| **Seed Expansion** | 1–3 | crt.sh org filter · ARIN RDAP ASN→CIDR · TLD sweep · brand variation · SEC EDGAR · WhoisXML registrant pivot (API-optional) |
| **Discovery** | 4–9 | Subfinder + Assetfinder + crt.sh + GAU + Wayback CDX + RapidDNS + OTX/VT (API-optional) → merge + exclusion filter |
| **DNS & Takeover** | 10–11 | DNSX full resolution (A/AAAA/CNAME/MX/NS/SPF/DMARC/DKIM/DNSSEC/BIMI/MTA-STS/DANE) · CDN/cloud tier classify · 55+ dangling-DNS fingerprints |
| **Port + Web** | 12–16 | IPv6 discovery · Naabu port scan (~500 ports, CDN-aware) · web-port URL expansion · HTTPX fingerprinting · Shodan banner enrichment (API-optional) |
| **Crawl + JS** | 18–19 | Katana deep crawl (JS-aware, depth 3) → JS file analysis (secrets, endpoints, SDK refs) |
| **Security Analysis** | 21–23 | Login panel detection · TLS/cipher grading · security header compliance · CORS / BIMI / MTA-STS / DANE / WHOIS structured fields |
| **Intelligence** | 24–29 | SaaS tenants · third-party vendor intel (100+ patterns) · API surface · colleague identification · GitHub org surface · favicon hash clustering |
| **Cloud** | 30 | Cloud infra inventory + WAF shielding status · open storage check · bucket permutation |
| **Score + Report** | 31 | Three-bucket risk scoring (70+ signals) → self-contained HTML report with 11 tabs |

---

## Key Features

<details>
<summary><b>Subdomain Discovery & DNS Intelligence</b></summary>

- Aggregates from **Subfinder**, **Assetfinder**, **crt.sh**, **GAU** (Wayback Machine), RapidDNS, OTX, VirusTotal
- Full DNS resolution: A, AAAA, CNAME, MX, NS, SPF, DMARC, DKIM, DNSSEC
- BIMI, MTA-STS, DANE/TLSA records per domain
- WHOIS: Registrar, creation date, expiry, RegistrantOrg, RegistrantCountry per domain
- **Per-project Exclusion List** — assets marked out-of-scope are filtered before DNS resolution and from all future rescans
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
- **Key algorithm** (RSA / ECDSA) and **key size** (colour-coded: red < 2048, yellow = 2048, green ≥ 4096 / any ECDSA)
- **CA type** detection: Let's Encrypt vs. paid CA
- **Cert Score A–F** (0–100) per certificate — TLS version + cipher + expiry + key + self-signed + wildcard
</details>

<details>
<summary><b>Mail Infrastructure Mapping</b></summary>

- Per-domain **MX record** collection + automatic mail provider detection (Google Workspace, Microsoft 365, ProofPoint, Mimecast, etc.)
- **SPF / DKIM / DMARC / DNSSEC** evaluated per domain
- **BIMI** record detection, **MTA-STS** mode (enforce/testing/none), **DANE/TLSA** records (ports 443 and 25)
- Dedicated **Mail Infrastructure** report tab with per-domain **Email Risk Score 0–100**
</details>

<details>
<summary><b>Domain Intelligence Enrichment</b></summary>

- Structured **WHOIS fields** per domain: Registrar, DomainCreated, DomainExpires, DomainAge, RegistrantOrg, RegistrantCountry
- **NS cluster badge** — groups domains sharing the same nameservers
- **Shodan service banners** surfaced in the IP Addresses table (port · protocol · service pills)
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

- Katana crawls every live site (depth 3)
- **Deduplicated unique page count** per endpoint: numeric path segments normalised (`/users/123` → `/users/{id}`), query strings stripped
- Log-scaled score contribution (+2 to +12) — measures real application complexity, not URL count inflation
</details>

<details>
<summary><b>Third-Party Vendor Intelligence</b></summary>

- Multi-source collection: CSP headers, Katana JS analysis, MX/SPF/CNAME records, HTTP response headers
- **100+ vendor patterns** classify into Analytics, CDN, Auth/Identity, Payment, Marketing, Cloud, Monitoring, and more
- Dedicated **Third Parties** report tab with per-category summary and full vendor detail table
</details>

<details>
<summary><b>Asset Topology Graph</b></summary>

- Interactive **D3 v7 force-directed graph** in the report — no external dependencies
- **8 node types**: Domain · IP · ASN · NS · MX · Cloud · TLS Cert · Vendor
- **11 edge types**: DNS · CNAME · NS · MX · ASN · Cloud · TLS SAN · Vendor · Takeover · Redirect · Favicon
- Click any node for ego-network highlight; filter by node type or edge type; search by name
</details>

<details>
<summary><b>Interactive Report UX</b></summary>

- **Clickable per-endpoint scorecard** — click any Attack Surface Score to see a breakdown of every contributing signal
- **Column visibility toggle** per table — hide/show columns, state persisted in localStorage
- **Section intelligence drawer** — ⓘ About button in each section opens an analyst-written explanation with red flags to look for
- **Column micro-tooltips** — hover the `?` chip on any column header for a one-sentence definition and attacker use case
- **9-chart analytics grid** in the Overview
- **Dark / Light theme** — shared between dashboard and report
</details>

## Risk Scoring

Every endpoint is scored through **three capped buckets** (max 100). The aggregate report score is the **mean of the top-5 domain endpoint scores**.

| Bucket | Cap | Measures |
|--------|-----|----------|
| **Sensitivity** | 40 | Asset criticality, stack complexity, data-handling classification |
| **Exposure** | 35 | Directly dangerous or reachable attack surfaces |
| **Hygiene** | 25 | Misconfigurations, certificate health, compliance gaps |

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
| Business-critical TLD / financial-themed path in crawl | up to +8 |
| High-risk third-party vendor in use | up to +6 |
| Cloud API / serverless resource | +5 |
| SaaS tenant footprint detected | +3 |
| Cloud managed surface | +3 |
| Full-stack framework detected | +2 |
| Authentication-protected surface (HTTP 401) | +3 |
</details>

<details>
<summary><b>Exposure signals</b></summary>

| Signal | Points |
|--------|--------|
| Open / publicly accessible cloud storage bucket | +20 |
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
| CBC cipher in use (BEAST / POODLE) | +6 |
| Development server exposed (Werkzeug, Flask dev) | +6 |
| Certificate expires within 30 days | +6 |
| HTTP → HTTPS redirect downgrade detected | +6 |
| Weak RSA key < 2048 bits | +8 |
| Missing security headers (HSTS, CSP, X-Frame-Options…) | up to +12 |
| DMARC not published | +6 |
| SPF not published | +4 |
| Certificate validity unknown | +4 |
| Wildcard TLS certificate | +4 |
| DKIM not published | +3 |
| DNSSEC not enabled | +2 |
| Server version disclosed in headers | +5 |
</details>

> **Why it matters:** An internal admin panel with an expired self-signed cert, a wildcard CORS header, and port 3306 exposed scores far higher than a static marketing page — so your team skips the noise and starts where it matters.

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

### 4. Start your first scan

1. Click **+ New Scan** — enter a project name and paste your domains (one per line)
2. Optionally paste any **out-of-scope assets** in the Exclusion List textarea (exact or suffix match)
3. Click **Run Now** or **Add to Queue**
4. Watch live progress: `Step X of 31`, elapsed timer, real-time log streaming
5. When complete, click **Report →** to open the self-contained HTML report


Results are written to `output/run-<timestamp>/`.

## Report Tour

The generated report is a **self-contained HTML file** — no server needed, open it in any browser.

| Tab | Contents |
|-----|----------|
| **Overview** | Executive banner (Asset Tiers + 5 metric groups) · 9-chart analytics grid · risk leaderboard with clickable Attack Surface Score |
| **Domain Intelligence** | All subdomains · DNS records · NS cluster badge · Registrar · Domain Age · BIMI/MTA-STS/DANE badges · WHOIS structured fields |
| **Application Endpoints** | Every live endpoint — status, title, tech stack, login detection, security headers, CORS, CDN |
| **IP Addresses** | Reverse DNS · ASN · network blocks · geolocation · Shodan service banners (port/protocol/service/version pills) |
| **Mail Infrastructure** | Per-domain: MX routing · auto-detected mail provider · SPF/DKIM/DMARC/BIMI/MTA-STS/DANE badges · Email Risk Score 0–100 |
| **TLS Certificates** | Cipher · protocol version · expiry (colour-coded) · SANs · issuer · Cert Score A–F · Key Algorithm · Key Size · Wildcard flag · Self-Signed flag · CA Type |
| **Cloud Infrastructure** | Asset map by provider · resource type · shielding status |
| **Internet Footprint** | CIDR blocks · crt.sh org subdomains · TLD sweep results · WHOIS registrant pivot candidates |
| **SaaS Tenants** | SaaS tenant footprint · open/accessible cloud storage buckets |
| **Third Parties** | Vendor classification from CSP, JS refs, MX/SPF/CNAME, and response headers · 100+ vendor patterns |
| **Asset Topology** | Interactive D3 force-directed graph · 8 node types · 11 edge types · ego-network click · search · type filters |

**Every table** has full-text search, **column visibility toggle** (hidden columns persisted per browser), and the **ⓘ About** button explains what each section means and what to look for.

## Orbis Dashboard

The web UI at `localhost:8787` is branded **Orbis — Full-Spectrum Attack Surface Intelligence**.

- **Project cards** — status badge, live progress bar (`Step X of 31`), elapsed/total duration
- **KPI row** — Total projects · Active scans · Completed · Queued
- **Filter tabs** — All / Running / Done / Queued
- **📋 View Logs** — live log streaming side panel, polls every 1.5 s during active scans
- **Project detail page** — full per-project run history with individual report + log access
- **Bulk operations** — select multiple projects for batch deletion
- **Modify / Rescan / Cancel** any project from the `···` context menu
- **Per-project Exclusion List** — edit out-of-scope assets from the New Scan / Modify modal
- **API Keys panel** — configure optional enrichment keys with live validation and individual Clear buttons
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

## Configuration

Access the **API Keys** panel from the sidebar (`🔑 API Keys`) to configure:

### API Keys (optional but unlock additional sources)

| Key | Unlocks |
|-----|---------|
| `github_token` | GitHub org surface discovery, secret detection |
| `shodan_api_key` | Shodan banner enrichment (non-HTTP ports) + favicon hash clustering (MMH3) |
| `censys_api_key` | Censys favicon hash clustering (MD5) — single key, new platform format |
| `otx_api_key` | AlienVault OTX enhanced passive DNS |
| `virustotal_api_key` | VirusTotal passive subdomain feed |
| `whoisxml_api_key` | WHOIS registrant pivot for seed expansion / org ASN mapping |
| `chaos_api_key` | ProjectDiscovery PDCP — runs `chaos` CLI per domain for live subdomain results |

All keys are **optional** — the pipeline runs fully without them, skipping only the enrichment steps that require a specific key. Each key has a **live validation test** and a **Clear** button in the API Keys panel.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web dashboard | Python · Flask 3.x |
| Scanner pipeline | Bash 5.x · 31-step workflow |
| Subdomain discovery | Subfinder · Assetfinder · crt.sh · GAU · Wayback CDX · RapidDNS · OTX · VirusTotal |
| DNS resolution | DNSX (A, AAAA, CNAME, MX, NS, SPF, DMARC, DKIM, DNSSEC, BIMI, MTA-STS, DANE) |
| Port scanning | Naabu (CDN/cloud-tier classification via Team Cymru ASN) |
| Web fingerprinting | HTTPX (follow-redirects, CORS, redirect dedup) |
| Web crawling | Katana (unique-page dedup, numeric segment normalisation) |
| TLS analysis | tlsx (cipher, key algo, key size, wildcard, self-signed, CA type, Cert Score A–F) |
| Banner enrichment | Shodan API · Censys API (both API-optional) |
| Email / DNS intel | dig · BIMI · MTA-STS · DANE/TLSA · structured WHOIS fields |
| Report visualisation | Chart.js (9 charts) · D3 v7 (Asset Topology force graph) |
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

