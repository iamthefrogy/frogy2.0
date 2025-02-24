#!/usr/bin/env bash
set -euo pipefail

##############################################
# 0) Global counters for summary
##############################################
CHAOS_COUNT=0
SUBFINDER_COUNT=0
ASSETFINDER_COUNT=0
CRT_COUNT=0
DNSX_LIVE_COUNT=0
HTTPX_LIVE_COUNT=0
LOGIN_FOUND_COUNT=0  # Count how many times a login form was detected

##############################################
# 1) Helper: Print with colors (minimal logs)
##############################################
info()    { echo -e "\033[96m[+] $*\033[0m"; }
warning() { echo -e "\033[93m[!] $*\033[0m"; }
error()   { echo -e "\033[91m[-] $*\033[0m"; }

##############################################
# 2) Helper: Merge subdomain files (no count logs)
##############################################
merge_and_count() {
  local file="$1"
  local source_name="$2"
  local count=0
  if [[ -s "$file" ]]; then
    count=$(wc -l < "$file")
    cat "$file" >> "$ALL_TEMP"
  fi
  # Accumulate into global counters
  case "$source_name" in
    "Chaos")       CHAOS_COUNT=$((CHAOS_COUNT + count)) ;;
    "Subfinder")   SUBFINDER_COUNT=$((SUBFINDER_COUNT + count)) ;;
    "Assetfinder") ASSETFINDER_COUNT=$((ASSETFINDER_COUNT + count)) ;;
    "Certificate") CRT_COUNT=$((CRT_COUNT + count)) ;;
  esac
}

##############################################
# 3) Prompt user for input
##############################################
read -rp $'\033[94m[?] Enter the organization name (e.g., \'Carbon Black\'): \033[0m' org
[[ -z "$org" ]] && { error "Org name cannot be empty. Exiting."; exit 1; }

read -rp $'\033[94m[?] Enter the root domain name (e.g., \'example.com\'): \033[0m' domain_name
[[ -z "$domain_name" ]] && { error "Domain name cannot be empty. Exiting."; exit 1; }

# Make organization name lowercase + underscores
cdir=$(echo "$org" | tr '[:upper:]' '[:lower:]' | tr ' ' '_')

# Create output directories
mkdir -p "output/$cdir/raw_output/raw_http_responses"
mkdir -p "output/$cdir/logs"

# Central temp file & final subdomain file
ALL_TEMP="output/$cdir/all_temp_subdomains.txt"
MASTER_SUBS="output/$cdir/master_subdomains.txt"
> "$ALL_TEMP"
> "$MASTER_SUBS"

##############################################
# 4) Option toggles for tools (true/false)
##############################################
USE_CHAOS="true"
USE_SUBFINDER="true"
USE_ASSETFINDER="true"
USE_DNSX="true"
USE_NAABU="true"
USE_HTTPX="true"

##############################################
# 4a) CHAOS
##############################################
run_chaos() {
  if [[ "$USE_CHAOS" == "true" ]]; then
    info "Running Chaos..."
    local chaos_index="output/$cdir/logs/chaos_index.json"
    curl -s https://chaos-data.projectdiscovery.io/index.json -o "$chaos_index"

    local chaos_url
    chaos_url=$(grep -w "$cdir" "$chaos_index" | grep "URL" | sed 's/"URL": "//;s/",//' | xargs || true)

    if [[ -n "$chaos_url" ]]; then
      (
        cd "output/$cdir"
        curl -sSL "$chaos_url" -O
        unzip -qq "*.zip" || true
        cat ./*.txt > chaos.txt
        rm -f ./*.zip
      )
      merge_and_count "output/$cdir/chaos.txt" "Chaos"
    fi
    rm -f "$chaos_index"
  fi
}

##############################################
# 4b) Subfinder
##############################################
run_subfinder() {
  if [[ "$USE_SUBFINDER" == "true" ]]; then
    info "Running Subfinder..."
    subfinder -d "$domain_name" -all -silent \
      -o "output/$cdir/subfinder.txt" \
      >/dev/null 2>&1 || true

    merge_and_count "output/$cdir/subfinder.txt" "Subfinder"
  fi
}

##############################################
# 4c) Assetfinder
##############################################
run_assetfinder() {
  if [[ "$USE_ASSETFINDER" == "true" ]]; then
    info "Running Assetfinder..."
    assetfinder --subs-only "$domain_name" \
      > "output/$cdir/assetfinder.txt" \
      2>/dev/null || true

    merge_and_count "output/$cdir/assetfinder.txt" "Assetfinder"
  fi
}

##############################################
# 4d) Certificates (crt.sh)
##############################################
run_crtsh() {
  info "Running crt.sh..."
  local whois_file="output/$cdir/whois.txtls"
  > "$whois_file"
  {
    set +e
    local registrant
    registrant=$(whois "$domain_name" 2>/dev/null \
      | grep -i "Registrant Organization" \
      | cut -d ":" -f2 \
      | xargs \
      | sed 's/,/%2C/g; s/ /+/g' \
      | egrep -v '(Whois|domains|proxy|PRIVACY|REDACTED|DNStination|Protected|Registration Private)' \
      || true)

    if [[ -n "$registrant" ]]; then
      curl -s "https://crt.sh/?q=$registrant" \
        | grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' \
        | sed -e 's/^<TD>//;s/<\/TD>$//' \
        >> "$whois_file"
    fi

    curl -s "https://crt.sh/?q=$domain_name&output=json" \
      | jq -r ".[].name_value" 2>/dev/null \
      | sed 's/\*\.//g' \
      >> "$whois_file"
    set -e
  } || true

  merge_and_count "$whois_file" "Certificate"
}

##############################################
# 4e) (REMOVED logic - as in the original)
##############################################

##############################################
# 4f) DNSX â€“ Live Domain Check
##############################################
run_dnsx() {
  if [[ "$USE_DNSX" == "true" ]]; then
    info "Running dnsx..."
    dnsx -silent \
         -l "output/$cdir/master_subdomains.txt" \
         -o "output/$cdir/dnsx.json" \
         -j \
         >/dev/null 2>&1 || true

    # Count how many are live
    DNSX_LIVE_COUNT=$(cat "output/$cdir/dnsx.json" \
      | jq -r 'select(.status_code=="NOERROR") | .host' \
      | sort -u \
      | wc -l)
  fi
}

##############################################
# 4g) Naabu â€“ Port Scanning
##############################################
run_naabu() {
  if [[ "$USE_NAABU" == "true" ]]; then
    info "Running naabu..."
    # limiting to top ports or specific ports is optional
    # Adjust to suit your environment
    naabu -silent \
          -l "output/$cdir/master_subdomains.txt" \
          -p 80,443 \
          -o "output/$cdir/naabu.json" \
          -j \
          >/dev/null 2>&1 || true

    local final_urls_ports="output/$cdir/final_urls_and_ports.txt"
    cat "output/$cdir/naabu.json" \
      | jq -r '"\(.host):\(.port)"' \
      | sort -u \
      > "$final_urls_ports"
  fi
}

##############################################
# 4h) HTTPX â€“ Web Recon
##############################################
run_httpx() {
  if [[ "$USE_HTTPX" == "true" ]]; then
    info "Running httpx..."
    httpx -silent \
          -l "output/$cdir/final_urls_and_ports.txt" \
          -j \
          -o "output/$cdir/httpx.json" \
          >/dev/null 2>&1 || true

    # Count how many lines => how many "live websites"
    HTTPX_LIVE_COUNT=$(wc -l < "output/$cdir/httpx.json")
  fi
}

##############################################
# 4i) Login detection
##############################################
run_login_detection() {
  # Only print "Detecting Login panels..." once
  info "Detecting Login panels...."

  local input_file="output/$cdir/httpx.json"
  local output_file="output/$cdir/login.json"

  # If no httpx.json, skip
  if [ ! -f "$input_file" ]; then
    return
  fi

  # Ensure jq is installed
  if ! command -v jq >/dev/null 2>&1; then
    return
  fi

  local timeout_duration="10"  # 10-second timeout
  local urls
  local -a results=()

  # Extract the URLs from httpx.json
  urls=$(jq -r '.url' "$input_file")

  for url in $urls; do
    # We don't print anything while processing each URL
    response=$(curl -Ls --max-time "$timeout_duration" -w "%{url_effective}\n" "$url" -o response.html 2>/dev/null || true)
    if [ $? -ne 0 ] || [ -z "$response" ]; then
      # If curl fails or times out
      results+=("{\"url\": \"$url\", \"final_url\": \"\", \"login_found\": \"N/A\"}")
      continue
    fi

    final_url=$(echo "$response" | tail -n1)
    local initial_domain=$(echo "$url" | awk -F/ '{print $3}')
    local final_domain=$(echo "$final_url" | awk -F/ '{print $3}')

    # If domain changes, skip
    if [[ "$initial_domain" != "$final_domain" ]]; then
      results+=("{\"url\": \"$url\", \"final_url\": \"$final_url\", \"login_found\": \"No\"}")
      continue
    fi

    # Basic login detection: search for typical form-based patterns
    # Avoid script exit with '|| true' after each grep
    login_detected=$(
      grep -Eo '<form[^>]*>' response.html 2>/dev/null || true \
      | grep -Ei 'login|log-in|sign-in|authentication|username|password|auth|session|token|credential|forgot-password|reset-password|oauth|register|signup|sign-up|user[ _-]?name|pass[ _-]?word|passwd|account|secure|access|member|log[ _-]?on|signoff|sign-off|logoff|log-off|security|authentic|authorize|access[ _-]?control|verify|validat|sso|two-factor|2fa|mfa|lockscreen|biometric|fingerprint|face[ _-]?id|otp|one[ _-]?time[ _-]?pass|recover|recovery' 2>/dev/null || true
    )

    if [[ -n "$login_detected" ]]; then
      LOGIN_FOUND_COUNT=$((LOGIN_FOUND_COUNT + 1))
      results+=("{\"url\": \"$url\", \"final_url\": \"$final_url\", \"login_found\": \"Yes\"}")
    else
      results+=("{\"url\": \"$url\", \"final_url\": \"$final_url\", \"login_found\": \"No\"}")
    fi
  done

  # Combine all result objects into a JSON array
  local json_output
  json_output=$(printf "%s\n" "${results[@]}" | jq -s '.')

  echo "$json_output" > "$output_file"
  mv response.html output/$cdir/
}

##############################################
# 4j) Security Compliance Detection
##############################################

##############################################
# 4j) Security Compliance Detection (Sequential)
##############################################
securitycompliance() {
  info "Analyzing security hygiene (it will take some time)..."

  local input_file="output/$cdir/master_subdomains.txt"
  local output_file="output/$cdir/securitycompliance.json"
  local REQUEST_TIMEOUT=4

  # Ensure the input file exists and is not empty
  if [ ! -s "$input_file" ]; then
    echo "Error: Input file '$input_file' not found or is empty." >&2
    return 1
  fi

  # Function to analyze a single domain
  analyze_domain() {
    local domain="$1"
    # Remove carriage returns and trim whitespace
    domain=$(echo "$domain" | tr -d '\r' | xargs)
    [ -z "$domain" ] && return

    # SPF Record Check
    local spf
    spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" || true)
    [ -z "$spf" ] && spf="No SPF Record"

    # DKIM Record Check
    local dkim
    dkim=$(dig +short TXT "default._domainkey.$domain" 2>/dev/null | grep -i "v=DKIM1" || true)
    [ -z "$dkim" ] && dkim="No DKIM Record"

    # DMARC Record Check
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC1" || true)
    [ -z "$dmarc" ] && dmarc="No DMARC Record"

    # DNSSEC Check
    local dnskey dnssec
    dnskey=$(dig +short DNSKEY "$domain" 2>/dev/null || true)
    if [ -z "$dnskey" ]; then
      dnssec="DNSSEC Not Enabled"
    else
      dnssec="DNSSEC Enabled"
    fi

    # SSL/TLS Certificate Details
    local ssl_output CERT SSL_VERSION SSL_ISSUER CERT_EXPIRY
    ssl_output=$(echo | openssl s_client -connect "${domain}":443 -servername "$domain" 2>/dev/null || true)
    CERT=$(echo "$ssl_output" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)
    if [ -n "$CERT" ]; then
      SSL_VERSION=$(echo "$ssl_output" | grep -i "Protocol:" | head -1 | awk -F": " '{print $2}' || true)
      [ -z "$SSL_VERSION" ] && SSL_VERSION="Unknown"
      SSL_ISSUER=$(echo "$CERT" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //' || true)
      [ -z "$SSL_ISSUER" ] && SSL_ISSUER="N/A"
      CERT_EXPIRY=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
      [ -z "$CERT_EXPIRY" ] && CERT_EXPIRY="N/A"
    else
      SSL_VERSION="No SSL/TLS"
      SSL_ISSUER="N/A"
      CERT_EXPIRY="N/A"
    fi

    # Security Headers Check (try HTTPS first, fallback to HTTP)
    local HEADERS sts xfo csp xss rp pp acao
    HEADERS=$(curl -s -D - "https://$domain" -o /dev/null --max-time "$REQUEST_TIMEOUT" || true)
    if [ -z "$HEADERS" ]; then
      HEADERS=$(curl -s -D - "http://$domain" -o /dev/null --max-time "$REQUEST_TIMEOUT" || true)
    fi
    sts=$(echo "$HEADERS" | grep -i "Strict-Transport-Security:" | cut -d':' -f2- | xargs || true)
    xfo=$(echo "$HEADERS" | grep -i "X-Frame-Options:" | cut -d':' -f2- | xargs || true)
    csp=$(echo "$HEADERS" | grep -i "Content-Security-Policy:" | cut -d':' -f2- | xargs || true)
    xss=$(echo "$HEADERS" | grep -i "X-XSS-Protection:" | cut -d':' -f2- | xargs || true)
    rp=$(echo "$HEADERS" | grep -i "Referrer-Policy:" | cut -d':' -f2- | xargs || true)
    pp=$(echo "$HEADERS" | grep -i "Permissions-Policy:" | cut -d':' -f2- | xargs || true)
    acao=$(echo "$HEADERS" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs || true)

    # Construct a JSON object using jq
    jq -n \
      --arg domain "$domain" \
      --arg spf "$spf" \
      --arg dkim "$dkim" \
      --arg dmarc "$dmarc" \
      --arg dnssec "$dnssec" \
      --arg ssl_version "$SSL_VERSION" \
      --arg ssl_issuer "$SSL_ISSUER" \
      --arg cert_expiry "$CERT_EXPIRY" \
      --arg sts "$sts" \
      --arg xfo "$xfo" \
      --arg csp "$csp" \
      --arg xss "$xss" \
      --arg rp "$rp" \
      --arg pp "$pp" \
      --arg acao "$acao" \
      '{
         Domain: $domain,
         "SPF Record": $spf,
         "DKIM Record": $dkim,
         "DMARC Record": $dmarc,
         "DNSSEC Status": $dnssec,
         "SSL/TLS Version": $ssl_version,
         "SSL/TLS Issuer": $ssl_issuer,
         "Cert Expiry Date": $cert_expiry,
         "Strict-Transport-Security": $sts,
         "X-Frame-Options": $xfo,
         "Content-Security-Policy": $csp,
         "X-XSS-Protection": $xss,
         "Referrer-Policy": $rp,
         "Permissions-Policy": $pp,
         "Access-Control-Allow-Origin": $acao
       }'
  }

  # Create a temporary directory for intermediate JSON outputs
  local temp_dir
  temp_dir=$(mktemp -d)

  # Process each domain sequentially
  while IFS= read -r domain || [ -n "$domain" ]; do
    # Remove carriage returns
    domain=$(echo "$domain" | tr -d '\r')
    [ -z "$domain" ] && continue
    local sanitized
    sanitized=$(echo "$domain" | tr '/.' '_')
    analyze_domain "$domain" > "$temp_dir/${sanitized}.json"
  done < "$input_file"

  # Combine all JSON objects into a single JSON array using jq's slurp mode
  shopt -s nullglob
  local files=("$temp_dir"/*.json)
  if [ ${#files[@]} -eq 0 ]; then
    echo "[]" > "$output_file"
  else
    jq -s '.' "${files[@]}" > "$output_file"
  fi

  rm -r "$temp_dir"
  info "Security compliance results saved to $output_file"
}


##############################################
# 5) Merge line-based JSON -> single-array JSON
##############################################
combine_json() {
  local infile="$1"
  local outfile="$2"
  if [[ -f "$infile" ]]; then
    jq -cs . "$infile" > "$outfile" 2>/dev/null || echo "[]" > "$outfile"
  else
    echo "[]" > "$outfile"
  fi
}

##############################################
# 6) Build HTML Report
##############################################
build_html_report() {
  info "Building HTML report with analytics..."

  # Merge line-based JSON into arrays
  combine_json "output/$cdir/dnsx.json"   "output/$cdir/dnsx_merged.json"
  combine_json "output/$cdir/naabu.json"  "output/$cdir/naabu_merged.json"
  combine_json "output/$cdir/httpx.json"  "output/$cdir/httpx_merged.json"

  mv "output/$cdir/dnsx_merged.json"  "output/$cdir/dnsx.json"
  mv "output/$cdir/naabu_merged.json" "output/$cdir/naabu.json"
  mv "output/$cdir/httpx_merged.json" "output/$cdir/httpx.json"

  local report_html="output/$cdir/report.html"

  # Original HTML contents (unchanged)
  cat << 'EOF' > "$report_html"
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>External Attack Surface Analysis - $cdir</title>
      <!-- Chart.js for charts -->
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        :root {
          --bg-color: #f7f7f7;
          --text-color: #333;
          --header-bg: #fff;
          --header-text: #333;
          --table-bg: #fff;
          --table-header-bg: #eaeaea;
          --table-border: #ddd;
          --toggle-bg: #ccc;
          --toggle-btn: #fff;
        }
        body.dark {
          --bg-color: #222;
          --text-color: #ddd;
          --header-bg: #333;
          --header-text: #ddd;
          --table-bg: #333;
          --table-header-bg: #444;
          --table-border: #555;
          --toggle-bg: #555;
          --toggle-btn: #222;
        }
        body {
          background-color: var(--bg-color);
          color: var(--text-color);
          margin: 0;
          font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          background-color: var(--header-bg);
          color: var(--header-text);
          padding: 10px 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 {
          margin: 0;
          font-size: 24px;
        }
        .toggle-btn {
          background-color: var(--toggle-bg);
          border: none;
          color: var(--toggle-btn);
          padding: 5px 10px;
          cursor: pointer;
          border-radius: 4px;
          font-size: 14px;
        }
        .container {
          padding: 20px;
          max-width: 1200px;
          margin: 0 auto;
        }

        /* Scoreboard row */
        .scoreboard {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-bottom: 20px;
        }
        .score-card {
          background-color: var(--table-bg);
          border: 1px solid var(--table-border);
          border-radius: 5px;
          flex: 1 1 200px;
          padding: 10px;
          text-align: center;
        }
        .score-card h2 {
          margin: 0;
          font-size: 2em;
        }
        .score-card p {
          margin: 0;
          font-size: 0.9em;
          color: var(--text-color);
        }

        /* Fluid grid for charts */
        .charts-grid {
          display: grid;
          gap: 10px;
          /* auto-fill + minmax => as many columns as fit, each at least 300px wide */
          grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
          margin-bottom: 20px;
        }

        .chart-container {
          position: relative;
          /* no fixed height => Chart.js will be responsive */
          background-color: var(--table-bg);
          border: 1px solid var(--table-border);
          border-radius: 5px;
          padding: 10px;
          box-sizing: border-box;
        }
        .chart-container canvas {
          display: block;
          width: 100% !important;
          height: auto !important;
        }

        /* Table search box */
        #searchBox {
          margin-top: 20px;
          margin-bottom: 10px;
          padding: 8px;
          width: 300px;
          font-size: 14px;
        }
        /* Main table */
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 20px;
          background-color: var(--table-bg);
          font-size: 12px;
        }
        th, td {
          border: 1px solid var(--table-border);
          padding: 8px;
          text-align: left;
          vertical-align: top;
        }
        th {
          background-color: var(--table-header-bg);
        }
        /* Filter row <select> styles */
        #filter-row select {
          width: 100%;
          font-size: 12px;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>External Attack Surface Analysis Report</h1>
        <button id="themeToggle" class="toggle-btn">Change View</button>
      </div>
      <div class="container">
        <!-- SCOREBOARD -->
        <div class="scoreboard" id="scoreboard"></div>

        <!-- All charts in one fluid grid -->
        <div class="charts-grid">
          <!-- Priority Chart -->
          <div class="chart-container">
            <canvas id="priorityChart"></canvas>
          </div>
          <!-- Status Code Chart -->
          <div class="chart-container">
            <canvas id="statusCodeChart"></canvas>
          </div>
          <!-- Login Chart -->
          <div class="chart-container">
            <canvas id="loginPieChart"></canvas>
          </div>
          <!-- Port Chart -->
          <div class="chart-container">
            <canvas id="portChart"></canvas>
          </div>
          <!-- Tech Chart -->
          <div class="chart-container">
            <canvas id="techChart"></canvas>
          </div>
          <!-- Certificate Expiry Chart -->
          <div class="chart-container">
            <canvas id="certExpiryChart"></canvas>
          </div>
          <!-- TLS Usage Chart -->
          <div class="chart-container">
            <canvas id="tlsUsageChart"></canvas>
          </div>
          <!-- Security Headers Chart -->
          <div class="chart-container">
            <canvas id="headersChart"></canvas>
          </div>
          <!-- Email Security Chart -->
          <div class="chart-container">
            <canvas id="emailSecChart"></canvas>
          </div>
          <!-- CDN Usage Chart -->
          <div class="chart-container">
            <canvas id="cdnChart"></canvas>
          </div>
        </div>

        <!-- SEARCH BOX -->
        <input type="text" id="searchBox" placeholder="Filter table (e.g. domain, status code, tech)..." />

        <!-- MAIN TABLE with Filter Row -->
        <table id="report-table">
          <thead>
            <!-- Column Names -->
            <tr>
              <th>Priority</th>
              <th>Domain</th>
              <th>Resolvers</th>
              <th>A records</th>
              <th>DNS Status</th>
              <th>CDN Name</th>
              <th>CDN Type</th>
              <th>Port</th>
              <th>URL</th>
              <th>Redirect Location</th>
              <th>Homepage Title</th>
              <th>Web Server</th>
              <th>Login Found</th>
              <th>Technology Stack</th>
              <th>Status Code</th>
              <th>Content Length</th>
              <th>CDN</th>
              <!-- Security Compliance Columns -->
              <th>SPF Record</th>
              <th>DKIM Record</th>
              <th>DMARC Record</th>
              <th>DNSSEC Record</th>
              <th>SSL/TLS Version</th>
              <th>Cert Expiry Date</th>
              <th>SSL/TLS Issuer</th>
              <th>Strict-Transport-Security</th>
              <th>X-Frame-Options</th>
              <th>Content-Security-Policy</th>
              <th>X-XSS-Protection</th>
              <th>Referrer Policy</th>
              <th>Permissions Policy</th>
            </tr>
            <!-- Filter Dropdown Row -->
            <tr id="filter-row">
              <th><select id="priority-filter"><option value="">All</option></select></th>
              <th><select id="domain-filter"><option value="">All</option></select></th>
              <th><select id="resolvers-filter"><option value="">All</option></select></th>
              <th><select id="arecords-filter"><option value="">All</option></select></th>
              <th><select id="dnsstatus-filter"><option value="">All</option></select></th>
              <th><select id="cdnname-filter"><option value="">All</option></select></th>
              <th><select id="cdntype-filter"><option value="">All</option></select></th>
              <th><select id="port-filter"><option value="">All</option></select></th>
              <th><select id="url-filter"><option value="">All</option></select></th>
              <th><select id="redirect-filter"><option value="">All</option></select></th>
              <th><select id="title-filter"><option value="">All</option></select></th>
              <th><select id="webserver-filter"><option value="">All</option></select></th>
              <th><select id="login-filter"><option value="">All</option></select></th>
              <th><select id="tech-filter"><option value="">All</option></select></th>
              <th><select id="statuscode-filter"><option value="">All</option></select></th>
              <th><select id="contentlength-filter"><option value="">All</option></select></th>
              <th><select id="cdn-filter"><option value="">All</option></select></th>
              <th><select id="spf-filter"><option value="">All</option></select></th>
              <th><select id="dkim-filter"><option value="">All</option></select></th>
              <th><select id="dmarc-filter"><option value="">All</option></select></th>
              <th><select id="dnssec-filter"><option value="">All</option></select></th>
              <th><select id="sslversion-filter"><option value="">All</option></select></th>
              <th><select id="certexpiry-filter"><option value="">All</option></select></th>
              <th><select id="sslissuer-filter"><option value="">All</option></select></th>
              <th><select id="sts-filter"><option value="">All</option></select></th>
              <th><select id="xfo-filter"><option value="">All</option></select></th>
              <th><select id="csp-filter"><option value="">All</option></select></th>
              <th><select id="xss-filter"><option value="">All</option></select></th>
              <th><select id="rp-filter"><option value="">All</option></select></th>
              <th><select id="pp-filter"><option value="">All</option></select></th>
            </tr>
          </thead>
          <tbody id="report-table-body"></tbody>
        </table>
      </div>

      <!-- Register a custom plugin to draw labels on top of each bar -->
      <script>
        const barLabelPlugin = {
          id: 'barLabelPlugin',
          afterDatasetsDraw(chart, args, options) {
            const { ctx } = chart;
            // Filter for bar datasets only
            const metaSets = chart.getSortedVisibleDatasetMetas().filter(m => m.type === 'bar');

            metaSets.forEach((meta) => {
              meta.data.forEach((element, index) => {
                // The raw data value for this bar
                const value = meta._parsed[index][meta.vScale.axis];

                // Skip if value is 0 (remove this line if you want to display "0")
                if (value === 0) return;

                // Determine bar center for label placement
                const { x, y } = element.tooltipPosition();
                ctx.save();
                // Label styling
                ctx.fillStyle = options.color || '#000';
                ctx.font = options.font || '9px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                // Draw the label just above the bar
                ctx.fillText(value, x, y - 2);
                ctx.restore();
              });
            });
          }
        };
        // Make plugin available to all charts globally
        Chart.register(barLabelPlugin);
      </script>

      <script>
        // Theme toggle
        const toggleButton = document.getElementById("themeToggle");
        toggleButton.addEventListener("click", () => {
          document.body.classList.toggle("dark");
        });

        // Utility for formatting cell values
        const formatCell = (arr) => (arr && arr.length) ? arr.join("<br>") : "N/A";

        // Compute Priority from HTTP and DNS records
        function computePriority(httpRecord, dnsRecord) {
          let score = 0;
          if (httpRecord.status_code === 200) score += 5;
          else if ([301, 302].includes(httpRecord.status_code)) score += 3;
          else if (httpRecord.status_code >= 400) score += 1;
          else score += 1;
          if (httpRecord.content_length !== undefined) {
            if (httpRecord.content_length > 100000) score += 3;
            else if (httpRecord.content_length > 50000) score += 2;
            else if (httpRecord.content_length > 10000) score += 1;
          }
          if (httpRecord.tech && httpRecord.tech.length > 0) score += 2;
          if (dnsRecord && dnsRecord.status_code === "NOERROR") score += 1;
          if (score >= 10) return "P0";
          if (score >= 8)  return "P1";
          if (score >= 6)  return "P2";
          if (score >= 4)  return "P3";
          return "P4";
        }

        function getPriorityColor(priority) {
          switch (priority) {
            case "P0": return "#e74c3c";
            case "P1": return "#e67e22";
            case "P2": return "#2ecc71";
            case "P3": return "#3498db";
            case "P4": return "#85c1e9";
            default:   return "inherit";
          }
        }

        // Build scoreboard summary
        function buildScoreboard({ totalSubdomains, liveSubs, totalHttpx, loginFoundCount }) {
          const sb = document.getElementById("scoreboard");
          sb.innerHTML = `
            <div class="score-card">
              <h2>${totalSubdomains}</h2>
              <p>Total Unique Assets</p>
            </div>
            <div class="score-card">
              <h2>${liveSubs}</h2>
              <p>Total Live Assets</p>
            </div>
            <div class="score-card">
              <h2>${totalHttpx}</h2>
              <p>Application Endpoints (Various Ports)</p>
            </div>
            <div class="score-card">
              <h2>${loginFoundCount}</h2>
              <p>Login Interface Found</p>
            </div>
          `;
        }

        // Build original charts: priority, status code, login, port, tech
        function buildCharts({ statusCount, priorityCount, portCount, techCount }) {
          const scCanvas   = document.getElementById("statusCodeChart");
          const prCanvas   = document.getElementById("priorityChart");
          const portCanvas = document.getElementById("portChart");
          const techCanvas = document.getElementById("techChart");

          // Priority distribution chart
          if (prCanvas) {
            const labels = ["P0", "P1", "P2", "P3", "P4"];
            const data = labels.map(l => priorityCount[l] || 0);
            new Chart(prCanvas, {
              type: "bar",
              data: {
                labels,
                datasets: [{
                  label: "Priority Buckets",
                  data,
                  backgroundColor: ["#e74c3c", "#e67e22", "#2ecc71", "#3498db", "#85c1e9"]
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  legend: { display: false },
                  title: { display: true, text: "Asset Attractiveness by Hackers" }
                },
                scales: { y: { beginAtZero: true } }
              }
            });
          }

          // HTTP Status Codes chart
          if (scCanvas) {
            const labels = Object.keys(statusCount).sort((a, b) => +a - +b);
            const data   = labels.map(l => statusCount[l]);
            new Chart(scCanvas, {
              type: "bar",
              data: {
                labels,
                datasets: [{
                  label: "HTTP Status Codes",
                  data,
                  backgroundColor: [
                    "#3498db",
                    "#1abc9c",
                    "#9b59b6",
                    "#f1c40f",
                    "#e74c3c",
                    "#34495e",
                    "#95a5a6"
                  ]
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  legend: { display: false },
                  title: { display: true, text: "HTTP Status Codes" }
                },
                scales: { y: { beginAtZero: true } }
              }
            });
          }

          // Port usage chart
          if (portCanvas) {
            const sortedPorts = Object.keys(portCount).sort((a, b) => +a - +b);
            const portVals = sortedPorts.map(p => portCount[p]);
            new Chart(portCanvas, {
              type: "bar",
              data: {
                labels: sortedPorts,
                datasets: [{
                  label: "Open Ports",
                  data: portVals,
                  backgroundColor: "#f39c12"
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  legend: { display: false },
                  title: { display: true, text: "Port Usage" }
                },
                scales: { y: { beginAtZero: true } }
              }
            });
          }

          // Tech usage chart (horizontal)
          if (techCanvas) {
            const sortedTech = Object.keys(techCount).sort((a, b) => techCount[b] - techCount[a]);
            const top10 = sortedTech.slice(0, 10);
            const topVals = top10.map(t => techCount[t]);
            new Chart(techCanvas, {
              type: "bar",
              data: {
                labels: top10,
                datasets: [{
                  label: "Tech Usage (Top 10)",
                  data: topVals,
                  backgroundColor: "#9b59b6"
                }]
              },
              options: {
                responsive: true,
                indexAxis: "x",
                plugins: {
                  legend: { display: false },
                  title: { display: true, text: "Top 10 Technologies" }
                },
                scales: { x: { beginAtZero: true } }
              }
            });
          }
        }

        // Build Login Pie Chart
        function buildLoginPieChart(endpointsCount, loginFoundCount) {
          const canvas = document.getElementById("loginPieChart");
          if (canvas) {
            new Chart(canvas, {
              type: "bar",
              data: {
                labels: ["Found", "Not Found"],
                datasets: [{
                  data: [loginFoundCount, endpointsCount - loginFoundCount],
                  backgroundColor: ["#e74c3c", "#2ecc71"]
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  title: { display: true, text: "Login Interfaces Identified" },
                  legend: { display: false }
                }
              }
            });
          }
        }

        // ===== New Analytics Widgets =====

        // 1. Certificate Expiry Chart
        function buildCertExpiryChart(secData) {
          let now = new Date();
          let exp7 = 0, exp14 = 0, exp30 = 0;

          secData.forEach(item => {
            const expiryStr = item["Cert Expiry Date"];
            if (expiryStr && expiryStr !== "N/A") {
              let expiryDate = new Date(expiryStr);
              if (!isNaN(expiryDate)) {
                let diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
                if (diffDays >= 0) {
                  if (diffDays <= 7) {
                    exp7++;
                  } else if (diffDays <= 14) {
                    exp14++;
                  } else if (diffDays <= 30) {
                    exp30++;
                  }
                  // if >30 do nothing
                }
              }
            }
          });

          const ctx = document.getElementById("certExpiryChart").getContext("2d");
          new Chart(ctx, {
            type: "bar",
            data: {
              labels: ["Next 7 Days", "Next 14 Days", "Next 30 Days"],
              datasets: [{
                label: "Certs Expiring",
                data: [exp7, exp14, exp30],
                backgroundColor: [
                  "#e74c3c", // Dark Red
                  "#e67e22", // Orange
                  "#3498db"  // Blue
                ]
              }]
            },
            options: {
              responsive: true,
              plugins: {
                title: { display: true, text: "Certificate Expiry" },
                legend: { display: false }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // 2. TLS Usage Chart
        function buildTLSUsageChart(secData) {
          const tlsCounts = {};
          secData.forEach(item => {
            let ver = item["SSL/TLS Version"];
            ver = ver ? ver.trim() : "Unknown";
            tlsCounts[ver] = (tlsCounts[ver] || 0) + 1;
          });
          const labels = Object.keys(tlsCounts);
          const data = labels.map(l => tlsCounts[l]);
          const ctx = document.getElementById("tlsUsageChart").getContext("2d");
          new Chart(ctx, {
            type: "bar",
            data: {
              labels,
              datasets: [{
                label: "TLS Version Usage",
                data,
                backgroundColor: "#2ecc71"
              }]
            },
            options: {
              responsive: true,
              plugins: {
                title: { display: true, text: "SSL/TLS Usage" },
                legend: { display: false }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // 4. Security Headers Chart
        function buildHeadersChart(httpxData, secMap) {
          let hstsSet = 0, hstsMissing = 0;
          let xfoSet = 0, xfoMissing = 0;
          let cspSet = 0, cspMissing = 0;
          httpxData.forEach(record => {
            if (record.status_code === 200) {
              const domain = (record.input || "").split(":")[0];
              const sec = secMap[domain] || {};
              const hsts = (sec["Strict-Transport-Security"] || "").trim();
              const xfo = (sec["X-Frame-Options"] || "").trim();
              const csp = (sec["Content-Security-Policy"] || "").trim();
              if (hsts) hstsSet++; else hstsMissing++;
              if (xfo) xfoSet++; else xfoMissing++;
              if (csp) cspSet++; else cspMissing++;
            }
          });
          const ctx = document.getElementById("headersChart").getContext("2d");
          new Chart(ctx, {
            type: "bar",
            data: {
              labels: ["HSTS", "X-Frame Options", "CSP"],
              datasets: [
                {
                  label: "Present",
                  data: [hstsSet, xfoSet, cspSet],
                  backgroundColor: "#2ecc71"
                },
                {
                  label: "Missing",
                  data: [hstsMissing, xfoMissing, cspMissing],
                  backgroundColor: "#e74c3c"
                }
              ]
            },
            options: {
              responsive: true,
              plugins: {
                title: { display: true, text: "Security Headers (Status 200)" },
                tooltip: { mode: "index", intersect: false }
              },
              scales: {
                x: { stacked: true },
                y: { stacked: true, beginAtZero: true }
              }
            }
          });
        }

        // 5. Email Security Chart
        function buildEmailSecChart(secData) {
          let spfSet = 0, spfMissing = 0;
          let dkimSet = 0, dkimMissing = 0;
          let dmarcSet = 0, dmarcMissing = 0;
          secData.forEach(item => {
            const spf = item["SPF Record"] || "";
            const dkim = item["DKIM Record"] || "";
            const dmarc = item["DMARC Record"] || "";
            if (spf.toLowerCase().includes("spf1")) spfSet++; else spfMissing++;
            if (dkim.toLowerCase().includes("dkim1")) dkimSet++; else dkimMissing++;
            if (dmarc.toLowerCase().includes("dmarc1")) dmarcSet++; else dmarcMissing++;
          });
          const ctx = document.getElementById("emailSecChart").getContext("2d");
          new Chart(ctx, {
            type: "bar",
            data: {
              labels: ["SPF", "DKIM", "DMARC"],
              datasets: [
                {
                  label: "Present",
                  data: [spfSet, dkimSet, dmarcSet],
                  backgroundColor: "#2ecc71"
                },
                {
                  label: "Missing",
                  data: [spfMissing, dkimMissing, dmarcMissing],
                  backgroundColor: "#e74c3c"
                }
              ]
            },
            options: {
              responsive: true,
              plugins: {
                title: { display: true, text: "Email Security Records" },
                tooltip: { mode: "index", intersect: false }
              },
              scales: {
                x: { stacked: true },
                y: { stacked: true, beginAtZero: true }
              }
            }
          });
        }

        // 6. CDN Usage Chart
        function buildCDNChart(httpxData) {
          const cdnCounts = {};
          httpxData.forEach(record => {
            let cdn = record.cdn_name;
            if (cdn && cdn !== "N/A") {
              cdn = cdn.trim();
              cdnCounts[cdn] = (cdnCounts[cdn] || 0) + 1;
            }
          });
          const labels = Object.keys(cdnCounts);
          const data = labels.map(l => cdnCounts[l]);
          const ctx = document.getElementById("cdnChart").getContext("2d");
          new Chart(ctx, {
            type: "bar",
            data: {
              labels,
              datasets: [{
                label: "CDN Usage Distribution",
                data,
                backgroundColor: "#3498db"
              }]
            },
            options: {
              responsive: true,
              plugins: {
                title: { display: true, text: "CDN Usage" },
                legend: { display: false }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // Populate filter dropdowns for table columns
        function populateColumnFilters() {
          const tBody = document.getElementById("report-table-body");
          const rows = tBody.getElementsByTagName("tr");
          const uniqueCols = Array.from({ length: 30 }, () => new Set());
          for (let i = 0; i < rows.length; i++) {
            const cells = rows[i].getElementsByTagName("td");
            for (let col = 0; col < 30; col++) {
              uniqueCols[col].add(cells[col].innerText.trim());
            }
          }
          function fillSelectOptions(selectId, values) {
            const select = document.getElementById(selectId);
            const existing = select.querySelectorAll("option:not([value=''])");
            existing.forEach(opt => opt.remove());
            values.forEach(val => {
              const option = document.createElement("option");
              option.value = val;
              option.textContent = val;
              select.appendChild(option);
            });
          }
          fillSelectOptions("priority-filter",   [...uniqueCols[0]].sort());
          fillSelectOptions("domain-filter",     [...uniqueCols[1]].sort());
          fillSelectOptions("resolvers-filter",  [...uniqueCols[2]].sort());
          fillSelectOptions("arecords-filter",   [...uniqueCols[3]].sort());
          fillSelectOptions("dnsstatus-filter",  [...uniqueCols[4]].sort());
          fillSelectOptions("cdnname-filter",    [...uniqueCols[5]].sort());
          fillSelectOptions("cdntype-filter",    [...uniqueCols[6]].sort());
          fillSelectOptions("port-filter",       [...uniqueCols[7]].sort());
          fillSelectOptions("url-filter",        [...uniqueCols[8]].sort());
          fillSelectOptions("redirect-filter",   [...uniqueCols[9]].sort());
          fillSelectOptions("title-filter",      [...uniqueCols[10]].sort());
          fillSelectOptions("webserver-filter",  [...uniqueCols[11]].sort());
          fillSelectOptions("login-filter",      [...uniqueCols[12]].sort());
          fillSelectOptions("tech-filter",       [...uniqueCols[13]].sort());
          fillSelectOptions("statuscode-filter", [...uniqueCols[14]].sort());
          fillSelectOptions("contentlength-filter", [...uniqueCols[15]].sort());
          fillSelectOptions("cdn-filter",        [...uniqueCols[16]].sort());
          fillSelectOptions("spf-filter",        [...uniqueCols[17]].sort());
          fillSelectOptions("dkim-filter",       [...uniqueCols[18]].sort());
          fillSelectOptions("dmarc-filter",      [...uniqueCols[19]].sort());
          fillSelectOptions("dnssec-filter",     [...uniqueCols[20]].sort());
          fillSelectOptions("sslversion-filter", [...uniqueCols[21]].sort());
          fillSelectOptions("certexpiry-filter", [...uniqueCols[22]].sort());
          fillSelectOptions("sslissuer-filter",  [...uniqueCols[23]].sort());
          fillSelectOptions("sts-filter",        [...uniqueCols[24]].sort());
          fillSelectOptions("xfo-filter",        [...uniqueCols[25]].sort());
          fillSelectOptions("csp-filter",        [...uniqueCols[26]].sort());
          fillSelectOptions("xss-filter",        [...uniqueCols[27]].sort());
          fillSelectOptions("rp-filter",         [...uniqueCols[28]].sort());
          fillSelectOptions("pp-filter",         [...uniqueCols[29]].sort());
        }

        // Attach filter events to dropdowns
        function attachFilterEvents() {
          [
            "priority-filter",
            "domain-filter",
            "resolvers-filter",
            "arecords-filter",
            "dnsstatus-filter",
            "cdnname-filter",
            "cdntype-filter",
            "port-filter",
            "url-filter",
            "redirect-filter",
            "title-filter",
            "webserver-filter",
            "login-filter",
            "tech-filter",
            "statuscode-filter",
            "contentlength-filter",
            "cdn-filter",
            "spf-filter",
            "dkim-filter",
            "dmarc-filter",
            "dnssec-filter",
            "sslversion-filter",
            "certexpiry-filter",
            "sslissuer-filter",
            "sts-filter",
            "xfo-filter",
            "csp-filter",
            "xss-filter",
            "rp-filter",
            "pp-filter"
          ].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
              el.addEventListener("change", filterTable);
            }
          });
        }

        // Filter table based on global search and column filters
        function filterTable() {
          const tBody = document.getElementById("report-table-body");
          const rows = tBody.getElementsByTagName("tr");
          const query = document.getElementById("searchBox").value.toLowerCase();
          const selPriority   = document.getElementById("priority-filter").value.toLowerCase();
          const selDomain     = document.getElementById("domain-filter").value.toLowerCase();
          const selResolvers  = document.getElementById("resolvers-filter").value.toLowerCase();
          const selARecords   = document.getElementById("arecords-filter").value.toLowerCase();
          const selDNSStatus  = document.getElementById("dnsstatus-filter").value.toLowerCase();
          const selCDNName    = document.getElementById("cdnname-filter").value.toLowerCase();
          const selCDNType    = document.getElementById("cdntype-filter").value.toLowerCase();
          const selPort       = document.getElementById("port-filter").value.toLowerCase();
          const selURL        = document.getElementById("url-filter").value.toLowerCase();
          const selRedirect   = document.getElementById("redirect-filter").value.toLowerCase();
          const selTitle      = document.getElementById("title-filter").value.toLowerCase();
          const selWebserver  = document.getElementById("webserver-filter").value.toLowerCase();
          const selLogin      = document.getElementById("login-filter").value.toLowerCase();
          const selTech       = document.getElementById("tech-filter").value.toLowerCase();
          const selStatusCode = document.getElementById("statuscode-filter").value.toLowerCase();
          const selCLength    = document.getElementById("contentlength-filter").value.toLowerCase();
          const selCDN        = document.getElementById("cdn-filter").value.toLowerCase();
          const selSPF        = document.getElementById("spf-filter").value.toLowerCase();
          const selDKIM       = document.getElementById("dkim-filter").value.toLowerCase();
          const selDMARC      = document.getElementById("dmarc-filter").value.toLowerCase();
          const selDNSSEC     = document.getElementById("dnssec-filter").value.toLowerCase();
          const selSSLVersion = document.getElementById("sslversion-filter").value.toLowerCase();
          const selCertExpiry = document.getElementById("certexpiry-filter").value.toLowerCase();
          const selSSLIssuer  = document.getElementById("sslissuer-filter").value.toLowerCase();
          const selSTS        = document.getElementById("sts-filter").value.toLowerCase();
          const selXFO        = document.getElementById("xfo-filter").value.toLowerCase();
          const selCSP        = document.getElementById("csp-filter").value.toLowerCase();
          const selXSS        = document.getElementById("xss-filter").value.toLowerCase();
          const selRP         = document.getElementById("rp-filter").value.toLowerCase();
          const selPP         = document.getElementById("pp-filter").value.toLowerCase();

          for (let i = 0; i < rows.length; i++) {
            const cells = rows[i].getElementsByTagName("td");
            const colPriority   = cells[0].innerText.toLowerCase();
            const colDomain     = cells[1].innerText.toLowerCase();
            const colResolvers  = cells[2].innerText.toLowerCase();
            const colARecords   = cells[3].innerText.toLowerCase();
            const colDNSStatus  = cells[4].innerText.toLowerCase();
            const colCDNName    = cells[5].innerText.toLowerCase();
            const colCDNType    = cells[6].innerText.toLowerCase();
            const colPort       = cells[7].innerText.toLowerCase();
            const colURL        = cells[8].innerText.toLowerCase();
            const colRedirect   = cells[9].innerText.toLowerCase();
            const colTitle      = cells[10].innerText.toLowerCase();
            const colWebserver  = cells[11].innerText.toLowerCase();
            const colLogin      = cells[12].innerText.toLowerCase();
            const colTech       = cells[13].innerText.toLowerCase();
            const colStatusCode = cells[14].innerText.toLowerCase();
            const colCLength    = cells[15].innerText.toLowerCase();
            const colCDN        = cells[16].innerText.toLowerCase();
            const colSPF        = cells[17].innerText.toLowerCase();
            const colDKIM       = cells[18].innerText.toLowerCase();
            const colDMARC      = cells[19].innerText.toLowerCase();
            const colDNSSEC     = cells[20].innerText.toLowerCase();
            const colSSLVersion = cells[21].innerText.toLowerCase();
            const colCertExpiry = cells[22].innerText.toLowerCase();
            const colSSLIssuer  = cells[23].innerText.toLowerCase();
            const colSTS        = cells[24].innerText.toLowerCase();
            const colXFO        = cells[25].innerText.toLowerCase();
            const colCSP        = cells[26].innerText.toLowerCase();
            const colXSS        = cells[27].innerText.toLowerCase();
            const colRP         = cells[28].innerText.toLowerCase();
            const colPP         = cells[29].innerText.toLowerCase();
            let match = true;
            if (selPriority   && colPriority   !== selPriority)   match = false;
            if (selDomain     && colDomain     !== selDomain)     match = false;
            if (selResolvers  && colResolvers  !== selResolvers)  match = false;
            if (selARecords   && colARecords   !== selARecords)   match = false;
            if (selDNSStatus  && colDNSStatus  !== selDNSStatus)  match = false;
            if (selCDNName    && colCDNName    !== selCDNName)    match = false;
            if (selCDNType    && colCDNType    !== selCDNType)    match = false;
            if (selPort       && colPort       !== selPort)       match = false;
            if (selURL        && colURL        !== selURL)        match = false;
            if (selRedirect   && colRedirect   !== selRedirect)   match = false;
            if (selTitle      && colTitle      !== selTitle)      match = false;
            if (selWebserver  && colWebserver  !== selWebserver)  match = false;
            if (selLogin      && colLogin      !== selLogin)      match = false;
            if (selTech       && colTech       !== selTech)       match = false;
            if (selStatusCode && colStatusCode !== selStatusCode) match = false;
            if (selCLength    && colCLength    !== selCLength)    match = false;
            if (selCDN        && colCDN        !== selCDN)        match = false;
            if (selSPF        && colSPF        !== selSPF)        match = false;
            if (selDKIM       && colDKIM       !== selDKIM)       match = false;
            if (selDMARC      && colDMARC      !== selDMARC)      match = false;
            if (selDNSSEC     && colDNSSEC     !== selDNSSEC)     match = false;
            if (selSSLVersion && colSSLVersion !== selSSLVersion) match = false;
            if (selCertExpiry && colCertExpiry !== selCertExpiry) match = false;
            if (selSSLIssuer  && colSSLIssuer  !== selSSLIssuer)  match = false;
            if (selSTS        && colSTS        !== selSTS)        match = false;
            if (selXFO        && colXFO        !== selXFO)        match = false;
            if (selCSP        && colCSP        !== selCSP)        match = false;
            if (selXSS        && colXSS        !== selXSS)        match = false;
            if (selRP         && colRP         !== selRP)         match = false;
            if (selPP         && colPP         !== selPP)         match = false;
            const rowText = rows[i].innerText.toLowerCase();
            if (!rowText.includes(document.getElementById("searchBox").value.toLowerCase())) {
              match = false;
            }
            rows[i].style.display = match ? "" : "none";
          }
        }

        // ===== Load Data and Build Report =====
        async function loadData() {
          try {
            const [dnsxRes, naabuRes, httpxRes, loginRes, secRes] = await Promise.all([
              fetch("dnsx.json"),
              fetch("naabu.json"),
              fetch("httpx.json"),
              fetch("login.json"),
              fetch("securitycompliance.json")
            ]);
            const dnsxData  = await dnsxRes.json().catch(() => []);
            const naabuData = await naabuRes.json().catch(() => []);
            const httpxData = await httpxRes.json().catch(() => []);
            const loginData = await loginRes.json().catch(() => []);
            const secData   = await secRes.json().catch(() => []);

            // Build lookup maps for login and security compliance
            const loginMap = {};
            loginData.forEach(item => { loginMap[item.url] = item.login_found; });
            const secMap = {};
            secData.forEach(item => { secMap[item.Domain] = item; });

            // Compute scoreboard stats
            const endpointsCount = httpxData.length;
            const loginFoundCount = loginData.filter(item => item.login_found === "Yes").length;
            const liveSubs = dnsxData.filter(d => d.status_code === "NOERROR").length;
            const domainSet = new Set();
            dnsxData.forEach(d => { if (d.host) domainSet.add(d.host); });
            const totalSubdomains = domainSet.size;

            buildLoginPieChart(endpointsCount, loginFoundCount);
            buildScoreboard({
              totalSubdomains,
              liveSubs,
              totalHttpx: endpointsCount,
              loginFoundCount
            });

            // Build distributions for original charts
            const statusCount = {};
            httpxData.forEach(h => {
              const code = h.status_code || 0;
              statusCount[code] = (statusCount[code] || 0) + 1;
            });
            const priorityCount = { P0: 0, P1: 0, P2: 0, P3: 0, P4: 0 };
            const dnsMap = {};
            dnsxData.forEach(d => { dnsMap[d.host] = d; });
            httpxData.forEach(h => {
              const domain = (h.input || "").split(":")[0];
              const dnsRec = dnsMap[domain] || null;
              const prio = computePriority(h, dnsRec);
              priorityCount[prio] = (priorityCount[prio] || 0) + 1;
            });
            const portCount = {};
            naabuData.forEach(n => {
              const p = n.port || "unknown";
              portCount[p] = (portCount[p] || 0) + 1;
            });
            const techCount = {};
            httpxData.forEach(h => {
              if (h.tech && Array.isArray(h.tech)) {
                h.tech.forEach(t => { techCount[t] = (techCount[t] || 0) + 1; });
              }
            });
            buildCharts({ statusCount, priorityCount, portCount, techCount });

            // Merge DNS + HTTP data for table
            const combinedData = {};
            dnsxData.forEach(d => {
              const domain = d.host;
              combinedData[domain] = { dns: d, http: [] };
            });
            httpxData.forEach(h => {
              const domain = (h.input || "").split(":")[0];
              if (!combinedData[domain]) combinedData[domain] = { dns: null, http: [h] };
              else combinedData[domain].http.push(h);
            });

            const tBody = document.getElementById("report-table-body");
            Object.keys(combinedData).forEach(domain => {
              const { dns, http } = combinedData[domain];
              const dnsResolvers = dns && dns.resolver ? dns.resolver : [];
              const dnsA = dns && dns.a ? dns.a : [];
              const dnsStatus = dns ? dns.status_code : "N/A";
              const sec = secMap[domain] || {};
              const spf        = sec["SPF Record"] || "N/A";
              const dkim       = sec["DKIM Record"] || "N/A";
              const dmarc      = sec["DMARC Record"] || "N/A";
              const dnssec     = sec["DNSSEC Status"] || "N/A";
              const sslVersion = sec["SSL/TLS Version"] || "N/A";
              const certExpiry = sec["Cert Expiry Date"] || "N/A";
              const sslIssuer  = sec["SSL/TLS Issuer"] || "N/A";
              const stsFlag = (sec["Strict-Transport-Security"] || "").trim() !== "" ? "True" : "False";
              const xfoFlag = (sec["X-Frame-Options"] || "").trim() !== "" ? "True" : "False";
              const cspFlag = (sec["Content-Security-Policy"] || "").trim() !== "" ? "True" : "False";
              const xssFlag = (sec["X-XSS-Protection"] || "").trim() !== "" ? "True" : "False";
              const rpFlag  = (sec["Referrer-Policy"] || "").trim() !== "" ? "True" : "False";
              const ppFlag  = (sec["Permissions-Policy"] || "").trim() !== "" ? "True" : "False";

              if (http && http.length) {
                http.forEach(h => {
                  const prio = computePriority(h, dns);
                  const row = document.createElement("tr");
                  row.innerHTML = `
                    <td style="background-color:${getPriorityColor(prio)}; color:#fff;">${prio}</td>
                    <td>${domain}</td>
                    <td>${formatCell(dnsResolvers)}</td>
                    <td>${formatCell(dnsA)}</td>
                    <td>${dnsStatus}</td>
                    <td>${h.cdn_name || "N/A"}</td>
                    <td>${h.cdn_type || "N/A"}</td>
                    <td>${h.port || "N/A"}</td>
                    <td>${h.url || "N/A"}</td>
                    <td>${h.location || "N/A"}</td>
                    <td>${h.title || "N/A"}</td>
                    <td>${h.webserver || "N/A"}</td>
                    <td>${loginMap[h.url] || "N/A"}</td>
                    <td>${(h.tech && h.tech.length) ? h.tech.join("<br>") : "N/A"}</td>
                    <td>${(h.status_code !== undefined) ? h.status_code : "N/A"}</td>
                    <td>${(h.content_length !== undefined) ? h.content_length : "N/A"}</td>
                    <td>${(h.cdn !== undefined) ? h.cdn : "N/A"}</td>
                    <td>${spf}</td>
                    <td>${dkim}</td>
                    <td>${dmarc}</td>
                    <td>${dnssec}</td>
                    <td>${sslVersion}</td>
                    <td>${certExpiry}</td>
                    <td>${sslIssuer}</td>
                    <td>${stsFlag}</td>
                    <td>${xfoFlag}</td>
                    <td>${cspFlag}</td>
                    <td>${xssFlag}</td>
                    <td>${rpFlag}</td>
                    <td>${ppFlag}</td>
                  `;
                  tBody.appendChild(row);
                });
              } else {
                const row = document.createElement("tr");
                row.innerHTML = `
                  <td>N/A</td>
                  <td>${domain}</td>
                  <td>${formatCell(dnsResolvers)}</td>
                  <td>${formatCell(dnsA)}</td>
                  <td>${dnsStatus}</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>N/A</td>
                  <td>${spf}</td>
                  <td>${dkim}</td>
                  <td>${dmarc}</td>
                  <td>${dnssec}</td>
                  <td>${sslVersion}</td>
                  <td>${certExpiry}</td>
                  <td>${sslIssuer}</td>
                  <td>${stsFlag}</td>
                  <td>${xfoFlag}</td>
                  <td>${cspFlag}</td>
                  <td>${xssFlag}</td>
                  <td>${rpFlag}</td>
                  <td>${ppFlag}</td>
                `;
                tBody.appendChild(row);
              }
            });

            populateColumnFilters();
            attachFilterEvents();
            document.getElementById("searchBox").addEventListener("input", filterTable);

            // ===== Build New Analytics Charts =====
            // Filter secData to only include records where the domain has a valid URL (not "N/A")
            const validDomains = new Set();
            httpxData.forEach(h => {
              if (h.url && h.url !== "N/A") {
                validDomains.add((h.input || "").split(":")[0]);
              }
            });
            const secDataValid = secData.filter(item => validDomains.has(item.Domain));

            // Only build TLS and Cert Expiry charts if there is at least one valid domain
            if (secDataValid.length > 0) {
              buildCertExpiryChart(secDataValid);
              buildTLSUsageChart(secDataValid);
            } else {
              document.getElementById("certExpiryChart").parentElement.innerHTML = "<p>No valid website data available for certificate analysis.</p>";
              document.getElementById("tlsUsageChart").parentElement.innerHTML = "<p>No valid website data available for TLS usage analysis.</p>";
            }

            buildHeadersChart(httpxData, secMap);
            buildEmailSecChart(secData);
            buildCDNChart(httpxData);
          } catch (err) {
            console.error("Error loading data or building report:", err);
          }
        }

        loadData();
      </script>
    </body>
  </html>
EOF

  info "HTML report generated at: $report_html"
}

##############################################
# 7) Show final summary table
##############################################
show_summary() {
  local combined_pre_dedup=$((CHAOS_COUNT + SUBFINDER_COUNT + ASSETFINDER_COUNT + CRT_COUNT))
  local final_subdomains_count
  final_subdomains_count=$(wc -l < "$MASTER_SUBS")

  echo ""
  echo "=============== RECON SUMMARY ==============="
  printf "%-28s %s\n" "Chaos found:"          "$CHAOS_COUNT"
  printf "%-28s %s\n" "Subfinder found:"      "$SUBFINDER_COUNT"
  printf "%-28s %s\n" "Assetfinder found:"    "$ASSETFINDER_COUNT"
  printf "%-28s %s\n" "crt.sh found:"         "$CRT_COUNT"
  echo "---------------------------------------------"
  printf "%-28s %s\n" "Total assets pre-deduplication:" "$combined_pre_dedup"
  printf "%-28s %s\n" "Final assets post-deduplication:" "$final_subdomains_count"
  printf "%-28s %s\n" "Total Live assets (dnsx):" "$DNSX_LIVE_COUNT"
  printf "%-28s %s\n" "Total Live websites (httpx):" "$HTTPX_LIVE_COUNT"
  printf "%-28s %s\n" "Detected Login Forms:" "$LOGIN_FOUND_COUNT"
  echo "============================================="
}

##############################################
# 8) Main Execution
##############################################
main() {
  # 1) Run enumerations
  run_chaos
  run_subfinder
  run_assetfinder
  run_crtsh

  # 2) Merge subdomains
  info "Merging subdomains..."
  echo "$domain_name" >> "$ALL_TEMP"
  echo "www.$domain_name" >> "$ALL_TEMP"
  sort -u "$ALL_TEMP" > "$MASTER_SUBS"
  rm -f "$ALL_TEMP"

  # 3) Run Recon
  run_dnsx
  run_naabu
  run_httpx
  run_login_detection
  securitycompliance

  # 5) Build HTML report
  build_html_report

  # 6) Final summary
  show_summary
}

main
