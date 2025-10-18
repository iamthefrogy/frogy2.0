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

  - Assumes default project-discovery stack on a mid-tier VPS (8 vCPU, 16 GB RAM, decent bandwidth). Slower links, tight rate limits, or weaker hardware
    stretch these numbers.
  - Core contributors to runtime: naabu’s TCP sweeps, httpx screenshots & headless fetches, katana crawl, and TLS/banner enrichment (tlsx, curl).

  | Approx. live hosts in scope | End-to-end duration | Why it takes that long |
  |-----------------------------|---------------------|------------------------|
  | 2-digit (≈50)               | ~15–25 minutes      | Tool start-up plus full DNS→port→HTTP cycle; even small sets run every stage (naabu, httpx, katana, login detection). |
  | 3-digit (≈300)              | ~45–75 minutes      | Naabu/httpx queues grow; each host fans out across multiple ports, screenshots, TLS probes, and katana fetches. |
  | 4-digit (≈2,000)            | ~3.5–5.5 hours      | Port scanning dominates; thousands of endpoints mean large response archives, more TLS handshakes, and heavier katana/link processing. |
  | 5-digit (≈12,000)           | ~12–18 hours        | Parallelism hits external rate limits; sheer volume of screenshots, raw bodies, and crawl data becomes the bottleneck alongside network bandwidth. |

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

- Step 1 - Clone the repository.
- Step 2 - Create the target file and add all primary domains to it. E.g., target.txt
- Step 3 - Give permissions to all files within the frogy2.0 folder.
  ```bash
  chmod 777 *
  ```
- Step 4 - Build docker container.
  ```bash
  docker build -t frogy:latest .
  ```
- Step 5 - Run docker container.
```bash
  docker run --rm -it --network host --privileged --cap-add=NET_RAW --cap-add=NET_ADMIN --security-opt seccomp=unconfined --ulimit nofile=1048576:1048576 -v "$(pwd):/opt/frogy" -w /opt/frogy --entrypoint /bin/bash frogy:latest
 ```
- Step 6 - Once, you are inside docker, run this command to start operations: 
```bash
  ./frogy.sh target.txt
 ```
<b>Once this is completed, you will find the output within the output/run-2025XXXXXXXX/report.html</b>

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
