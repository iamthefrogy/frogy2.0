# Frogy 2.0
<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-and-usage">Installation</a> •
  <a href="#risk-scoring">Risk Scoring</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#blackhat-video">Blackhat Video</a>

**Frogy 2.0** is an automated external reconnaissance and Attack Surface Management (ASM) toolkit designed to map out an organization's entire internet presence. It identifies assets, IP addresses, web applications, and other metadata across the public internet and then smartly prioritizes them with highest (most attractive) to lowest (least attractive) from an attacker's playground perspective.

<img src="https://chintangurjar.com/images/frogy.png" alt="graphviz"/>

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

In this tool, **risk scoring** is based on the notion of **asset attractiveness**—the idea that certain attributes or characteristics make an asset more interesting to attackers. If we see more of these attributes, the overall score goes **up**, indicating a broader “attack surface” that adversaries could leverage. Below is an overview of how each factor contributes to the final **risk score**.

<img src="https://github.com/user-attachments/assets/312e9d15-482e-4676-96fe-5dd5ae2a061d"/>

---
# Screenshots

<img src="https://chintangurjar.com/images/frogyasm_s1.png"/>
<img src="https://chintangurjar.com/images/frogyasm_s2.png"/>
<img src="https://chintangurjar.com/images/frogyasm_s3.png"/>
<img src="https://chintangurjar.com/images/frogyasm_s4.png"/>

---

#### 1. Purpose of the Asset
- **Employee-Intended Assets**  
  If a subdomain or system is meant for internal (employee/colleague) use, it’s often higher value for attackers. Internal portals or dashboards tend to hold sensitive data or offer privileged functionality. Therefore, **if the domain is flagged as employee‐only**, its score increases.

#### 2. URLs Found
- **Valid/Accessible URL**  
  If the tool identifies a workable URL (e.g., HTTP/HTTPS) for the asset, it means there’s a real endpoint to attack. An asset that isn’t listening on a web port or is offline is less interesting—so **any resolvable URL** raises the score slightly.

#### 3. Login Interfaces
- **Login Pages**  
  The presence of a login form indicates some form of access control or user authentication. Attackers often target logins to brute‐force credentials, attempt SQL injection, or exploit session handling. Thus, **any discovered login endpoint** bumps the score.

#### 4. HTTP Status 200
- **Accessible Status Code**  
  If an endpoint actually returns a `200 OK`, it often means the page is legitimately reachable and responding with content. A `200 OK` is more interesting to attackers than a `404` or a redirect—so **a 200 status** modestly increases the risk.

### 5. TLS Version
- **Modern vs. Outdated TLS**  
  If an asset is using older SSL/TLS protocols (or no TLS), that’s a bigger risk. However, to simplify:
  - **TLS 1.2 or 1.3** is considered standard (no penalty).
  - Anything older or absent is penalized by adding to the score.

#### 6. Certificate Expiry
- **Imminent Expiry**  
  Certificates expiring soon (within a few weeks) can indicate potential mismanagement or a higher chance of downtime or misconfiguration. Short‐term expiry windows (≤ 7 days, ≤ 14 days, ≤ 30 days) add a cumulative boost to the risk score.

#### 7. Missing Security Headers
- **Security Header Hygiene**  
  The tool checks for typical headers like:
  - `Strict-Transport-Security (HSTS)`
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `X-XSS-Protection`
  - `Referrer-Policy`
  - `Permissions-Policy`

  Missing or disabled headers mean an endpoint is more prone to common web exploits. Each absent header increments the score.

#### 8. Open Ports
- **Port Exposure**  
  The more open ports (and associated services) an asset exposes, the broader the potential attack surface. Each open port adds to the risk score.

#### 9. Technology Stack (Tech Count)
- **Number of Technologies Detected**  
  Attackers love multi‐tech stacks because more software → more possible CVEs or misconfigurations. Each identified technology (e.g., Apache, PHP, jQuery, etc.) adds to the overall attractiveness of the target.

---

#### Putting It All Together

Each factor above contributes **one or more** points to the final risk score. For example:

1. +1 if the purpose is employee‐intended  
2. +1 if the asset is a valid URL  
3. +1 if a login is found  
4. +1 if it returns HTTP 200  
5. +1 if TLS is older than 1.2 or absent  
6. +1–3 for certificates expiring soon (≤ 30 days)  
7. +1 for each missing security header  
8. +1 per open port  
9. +1 per detected technology  
10. +1 per each management ports open
11. +1 per each database ports open
12. +1 per each crawled link per application

Once all factors are tallied, we get a **numeric risk score**. **Higher** means **more interesting and potentially gives more room for pentesters to test around** to an attacker.

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
