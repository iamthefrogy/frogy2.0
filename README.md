# Frogy 2.0
<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-and-usage">Installation</a> •
  <a href="#risk-scoring">Risk Scoring</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#blackhat-video">Blackhat Video</a>

**Frogy 2.0** is an automated external reconnaissance and Attack Surface Management (ASM) toolkit designed to map out an organization's entire internet presence. It identifies assets, IP addresses, web applications, and other metadata across the public internet and then smartly prioritizes them with highest (most attractive) to lowest (least attractive) from an attacker's playground perspective.

<img src="https://chintangurjar.com/images/frogy.png"/>

# Approx. Time Duration

Key pipeline stages: 17-step bash workflow.

Assumptions for timing: official Docker container on a mid-range cloud VM (≈2 vCPU, 4–8 GB RAM), fast but not unlimited network egress (Nat/ISP throttled around 50–100 Mbps), no upstream rate bans, and default script throttles (httpx -t 5 -rl 15, Katana -c 5, curl timeouts 25 s). Times grow nearly linearly with live subdomains because Naabu, curl login probes, tlsx, and dig/whois loops iterate per host/endpoint.

  | Total Discovered Subdomains | Typical Runtime (wallclock) | Primary Bottleneck / Rationale |
  | --- | --- | --- |
  | 2-digit (≤ 99) | ~20 – 40 minutes | Naabu still scans ~180 ports per host; each live endpoint then hits httpx twice (JSON + screenshots), Katana depth-3 crawl, curl login detection, and tlsx handshakes. DNS/email hygiene (dig) plus whois lookups run sequentially across every subdomain. |
  | 3-digit (100 – 999) | ~45 – 120 minutes | Port scanning now covers tens of thousands of probes; Katana/curl loops grow proportionally and are mostly sequential; tlsx and screenshotting contend for CPU. DNSSEC/SPF/DKIM checks and ipinfo enrichments fan out to hundreds of hosts, each with multiple dig/whois calls. |
  | 4-digit (1 000 – 9 999) | ~3 – 6 hours | Millions of port probes through Naabu plus repeated httpx/curl/TLS passes saturate rate limits, while Katana depth-3 crawls queue for hours. Large JSON merging (jq, sort) and disk writes (screenshots, responses) add I/O overhead. External services (crt.sh, whois, TLS endpoints) throttle aggressive parallelism. |
  | 5-digit (10 000 – 99 999) | ~8 – 18 hours | Naabu must touch tens of millions of host:port combos; httpx, tlsx, Katana, and curl runs become the dominant wallclock cost due to conservative rate limits and timeouts. Massive DNS/email hygiene loops hammer resolver APIs, and IP enrichment (whois.cymru, reverse DNS) further drags. Expect retries, remote throttling, and storage pressure from screenshots/responses. |

  Note: real runtimes can swing widely based on upstream rate-limits, packet loss, depth of Katana crawling, and whether endpoints time out (forcing every
  curl/httpx call to wait a full 15–25 s). Adjusting tool flags (e.g., trimming port catalog, lowering Katana depth, upping httpx -t) can significantly
  shorten runs at the cost of coverage.

# Features

- **Comprehensive recon:**  
  Aggregate subdomains and assets using multiple tools (CHAOS, Subfinder, Assetfinder, crt.sh) to map an organization's entire digital footprint.
  
- **Live asset verification:**  
  Validate assets with live DNS resolution and port scanning (using DNSX and Naabu) to confirm what is publicly reachable.
  
- **In-depth web recon:**  
  Collect detailed HTTP response data (via HTTPX) including metadata, technology stack, status codes, content lengths, and more.
  
- **Smart prioritization:**  
  Use a composite scoring system that considers homepage status, login identification, technology stack, and DNS data and much more to generate risk score for each assets helping bug bounty hunters and pentesters focus on the most promising targets to start attacks with.
  
- **Professional reporting:**  
  Generate a dynamic, colour-coded HTML report with a modern design and dark/light theme toggle.

# Risk Scoring

Attack Surface scoring flows through three capped buckets **(Exposure ≤45, Hygiene ≤35, Sensitivity ≤20)**. Each endpoint’s attributes—login transport, HTTP status, open/management/database ports, Katana link volume, cloud shielding, TLS version/expiry/protocols, security headers, email auth posture, DNSSEC, employee/API classification, tech stack breadth, cloud resource type—feeds the bucket-specific contributions. The final score is the capped sum of those buckets (max 100) and the top contributor explanations come from the same contribution list.

<img src="https://chintangurjar.com/images/riskscore.png"/>

---
# Screenshots

<img src="https://chintangurjar.com/images/frogyss3.png"/>
<img src="https://chintangurjar.com/images/frogyss2.png"/>
<img src="https://chintangurjar.com/images/frogyss1.png"/>

---

> **Why This Matters**  
> This approach helps you quickly **prioritize** which assets warrant deeper testing. Subdomains with high counts of open ports, advanced internal usage, missing headers, or login panels are more complex, more privileged, or more likely to be misconfigured—therefore, your security team can focus on those first.

# Installation and Usage

## Give permissions

```bash
chmod 777 *
```

## Quick Start (Docker)

```bash
docker build -t frogy:latest .
```

#### Linux hosts (native Docker)

`--network host` works reliably on Linux, so you can bind directly to the host network and keep the default port:

```bash
docker run --rm --network host --privileged --cap-add=NET_RAW frogy:latest
```

If you want runs to survive container restarts, add `-v "$(pwd)/output:/opt/frogy/output"` to that command so artefacts are stored on the host.

#### macOS & Windows (Docker Desktop)

Docker Desktop does **not** support `--network host`. Use bridged networking with an explicit port mapping instead:

```bash
docker run --rm --privileged --cap-add=NET_RAW -p 8787:8787 frogy:latest
```

Add `-v "$(pwd)/output:/opt/frogy/output"` if you want to persist run history to the host filesystem.

When the container starts you will see a banner similar to:

```
[frogy] Docker container is up. Control plane will be served at http://0.0.0.0:8787
[frogy] If you mapped the port (e.g. -p 8787:8787), open that URL from your browser.
```

The UI is available at `http://localhost:8787` (or the host/IP you published the port on).

> **Persisting runs**: Mounting `./output` into `/opt/frogy/output` keeps your scan history, metadata, and reports on the host. Without the mount the container still works, but all artefacts are wiped when it stops.

## Launching a Run

The control plane now opens with a single scan table:

1. Click **New Scan** to define a company name and paste newline-delimited **primary domains** (same format as `target.txt`). Client-side checks catch whitespace and invalid characters before submission.
2. Choose **Run Now**, **Add to Queue**, or **Schedule** (future date/time) directly from the modal. The scan is persisted regardless of the launch mode so you can rerun it later.
3. Scan rows list the last known status, completion time, and a report link. Selecting a row enables **Modify** (updates name/targets and optionally reruns) or **Delete** (removes the project folder and artefacts from disk).

Every launch writes a fresh target file to `output/projects/<project>/targets/targets-<timestamp>.txt` before invoking `frogy.sh`. Status badges stay in sync with the scheduler, so refreshes never lose track of queued or running jobs; reports always open in a new browser tab.

## Interface Highlights

- **Selectable rows & bulk actions**: Use the new checkbox column (or the select-all header) to modify or delete multiple scans at once.
- **Targets on demand**: The Targets column shows the total count plus a “View” pop-up with a scrollable list, keeping the table compact even for large target sets.
- **Instant reports**: The dedicated **View Results** column launches the latest HTML report in a new tab; buttons disable automatically while runs are still generating data.
- **Report exports**: Grab the underlying data straight from the dashboard—download JSON (all datasets) or a ZIP of CSV files ready for spreadsheets.
- **Progress visibility**: Each row carries a horizontal progress bar with live step labels (e.g. “Step 5/17 – httpx”), so you can see pipeline momentum at a glance.
- **Action icons**: The rightmost column offers quick controls for rescan/stop (🔄/⏹), modify (✏️), and delete (🗑️). Tooltips clarify each action; active runs expose a stop button you can use to cancel in-flight work.
- **Theme toggle**: Swap between dark and light palettes via the toggle in the header; your preference is remembered in the browser.
- **Footer credits**: A persistent “Developed by Frogy (Chintan Gurjar)” footer links out to contact details and the project homepage.

## Queueing & Scheduling

- Use **Add to Queue** when resources are busy—jobs execute automatically once earlier work completes.
- Use **Schedule** to select a future date/time; the run starts at that moment (subject to queue order). Scheduled entries remain highlighted until they fire.
- Parallel execution is supported by raising `FROGY_MAX_CONCURRENT` (see below); the scheduler respects that ceiling while interleaving queued and scheduled work.

## Browsing History

- The table consolidates every saved scan. Completed runs expose a **Report** link that opens a fresh tab to the archived HTML dashboard. Queued/running entries keep their link disabled until output is ready.
- If a run directory has been removed (for example `output/projects/<project>/run-2025XXXXXX` no longer exists) the UI surfaces a clear warning instead of rendering a blank report.
- Logs for every run are still archived under `output/projects/<project>/logs/`.


## CLI Compatibility

`frogy.sh` retains its original CLI usage and can still be executed manually:

```bash
bash frogy.sh target.txt
```
Manual runs continue to emit `output/run-*` folders in the repository root. The control plane only relocates runs that it initiated into `output/projects/<project>/`.

# BlackHat Video
https://www.youtube.com/watch?v=LHlU4CYNj1M

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
- Enforce data quality checks (valid domain syntax, duplicate detection, enrichment completion) before persisting records.
- Provide an option to hide the side panel.
- Export report in CSV + JSON format.
- Add the same search bar to all side panel reporting.
- User should be allowed to directly open UI and add targets there only.

