#!/usr/bin/env bash
set -euo pipefail

##############################################
# Global counters for summary
##############################################
CHAOS_COUNT=0
SUBFINDER_COUNT=0
ASSETFINDER_COUNT=0
CRT_COUNT=0
DNSX_LIVE_COUNT=0
HTTPX_LIVE_COUNT=0
LOGIN_FOUND_COUNT=0

##############################################
# Check input argument: primary domains file
##############################################
if [ "$#" -lt 1 ]; then
  echo -e "\033[91m[-] Usage: $0 <primary_domains_file>\033[0m"
  exit 1
fi

PRIMARY_DOMAINS_FILE="$1"
if [ ! -f "$PRIMARY_DOMAINS_FILE" ]; then
  echo -e "\033[91m[-] File '$PRIMARY_DOMAINS_FILE' not found!\033[0m"
  exit 1
fi

##############################################
# Create a unique output directory for this run
##############################################
RUN_DIR="output/run-$(date +%Y%m%d%H%M%S)"
mkdir -p "$RUN_DIR/raw_output/raw_http_responses"
mkdir -p "$RUN_DIR/logs"

##############################################
# Global file paths
##############################################
ALL_TEMP="$RUN_DIR/all_temp_subdomains.txt"
MASTER_SUBS="$RUN_DIR/master_subdomains.txt"
> "$ALL_TEMP"
> "$MASTER_SUBS"

##############################################
# Option toggles for tools (true/false)
##############################################
USE_CHAOS="false"
USE_SUBFINDER="true"
USE_ASSETFINDER="true"
USE_DNSX="true"
USE_NAABU="true"
USE_HTTPX="true"

##############################################
# Logging Functions (with timestamps)
##############################################
info()    { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [+] $*"; }
warning() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [!] $*"; }
error()   { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [-] $*"; }

##############################################
# Helper: Merge subdomain files
##############################################
merge_and_count() {
  local file="$1"
  local source_name="$2"
  local count=0
  if [[ -s "$file" ]]; then
    count=$(wc -l < "$file")
    cat "$file" >> "$ALL_TEMP"
  fi
  case "$source_name" in
    "Chaos")       CHAOS_COUNT=$((CHAOS_COUNT + count)) ;;
    "Subfinder")   SUBFINDER_COUNT=$((SUBFINDER_COUNT + count)) ;;
    "Assetfinder") ASSETFINDER_COUNT=$((ASSETFINDER_COUNT + count)) ;;
    "Certificate") CRT_COUNT=$((CRT_COUNT + count)) ;;
  esac
}

##############################################
# CHAOS DB
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
# Subfinder
##############################################
run_subfinder() {
  if [[ "$USE_SUBFINDER" == "true" ]]; then
    info "Running Subfinder..."
    subfinder -dL "$PRIMARY_DOMAINS_FILE" -all -silent \
      -o "$RUN_DIR/subfinder.txt" \
      >/dev/null 2>&1 || true
    merge_and_count "$RUN_DIR/subfinder.txt" "Subfinder"
  fi
}

##############################################
# Assetfinder
##############################################
run_assetfinder() {
  if [[ "$USE_ASSETFINDER" == "true" ]]; then
    info "Running Assetfinder..."
    while read -r domain; do
      assetfinder --subs-only "$domain" >> "$RUN_DIR/assetfinder.txt" 2>/dev/null || true
    done < "$PRIMARY_DOMAINS_FILE"
    merge_and_count "$RUN_DIR/assetfinder.txt" "Assetfinder"
  fi
}

##############################################
# Certificates (crt.sh)
##############################################
run_crtsh() {
  info "Running crt.sh..."
  local crt_file="$RUN_DIR/whois.txt"
  > "$crt_file"
  while read -r domain; do
    {
      set +e
      local registrant
      registrant=$(whois "$domain" 2>/dev/null \
        | grep -i "Registrant Organization" \
        | cut -d ":" -f2 \
        | xargs \
        | sed 's/,/%2C/g; s/ /+/g' \
        | egrep -v '(Whois|whois|WHOIS|domains|DOMAINS|Domains|domain|DOMAIN|Domain|proxy|Proxy|PROXY|PRIVACY|privacy|Privacy|REDACTED|redacted|Redacted|DNStination|WhoisGuard|Protected|protected|PROTECTED|Registration Private|REGISTRATION PRIVATE|registration private)' \
        || true)
      if [[ -n "$registrant" ]]; then
        curl -s "https://crt.sh/?q=$registrant" \
          | grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' \
          | sed -e 's/^<TD>//;s/<\/TD>$//' \
          >> "$crt_file"
      fi
      curl -s "https://crt.sh/?q=$domain&output=json" \
        | jq -r ".[].name_value" 2>/dev/null \
        | sed 's/\*\.//g' \
        >> "$crt_file"
      set -e
    } || true
  done < "$PRIMARY_DOMAINS_FILE"
  merge_and_count "$crt_file" "Certificate"
}

##############################################
# DNSX Live Domain Check
##############################################
run_dnsx() {
  if [[ "$USE_DNSX" == "true" ]]; then
    info "Running dnsx..."
    dnsx -silent \
         -l "$MASTER_SUBS" \
         -o "$RUN_DIR/dnsx.json" \
         -j \
         >/dev/null 2>&1 || true
    DNSX_LIVE_COUNT=$(jq -r 'select(.status_code=="NOERROR") | .host' "$RUN_DIR/dnsx.json" | sort -u | wc -l)
  fi
}

##############################################
# Naabu  Port Scanning
##############################################
run_naabu() {
  if [[ "$USE_NAABU" == "true" ]]; then
    info "Running naabu..."
    naabu -silent \
          -l "$MASTER_SUBS" \
          -p "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157" \
          -o "$RUN_DIR/naabu.json" \
          -j \
          >/dev/null 2>&1 || true
    local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
    jq -r '"\(.host):\(.port)"' "$RUN_DIR/naabu.json" | sort -u > "$final_urls_ports"
  fi
}

##############################################
# HTTPX Web Recon
##############################################
run_httpx() {
  if [[ "$USE_HTTPX" == "true" ]]; then
    info "Running httpx..."
    local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
    httpx -silent \
          -l "$final_urls_ports" \
          -j \
          -o "$RUN_DIR/httpx.json" \
          >/dev/null 2>&1 || true
    HTTPX_LIVE_COUNT=$(wc -l < "$RUN_DIR/httpx.json")
  fi
}

##############################################
# Login detection (Comprehensive Logic)
##############################################
run_login_detection() {
  info "Detecting Login panels..."
  local input_file="$RUN_DIR/httpx.json"
  local output_file="$RUN_DIR/login.json"

  # If the httpx.json file doesn't exist or jq is not installed, just exit early
  if [ ! -f "$input_file" ]; then
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    return
  fi

  local timeout_duration="10"
  local urls
  urls=$(jq -r '.url' "$input_file")

  # Begin JSON array
  echo "[" > "$output_file"
  local first_entry=true

  # Helper function to do the login "detection"
  detect_login() {
      local headers_file="$1"
      local body_file="$2"
      local final_url="$3"
      local -a reasons=()

      # Examples below: each grep checks something. If it matches, push a reason:
      if grep -qi -E '<input[^>]*type=["'"'"']password["'"'"']' "$body_file"; then
          reasons+=("Found password field")
      fi
      if grep -qi -E '<input[^>]*(name|id)=["'"'"']?(username|user|email|userid|loginid)' "$body_file"; then
          reasons+=("Found username/email field")
      fi
      if grep -qi -E '<form[^>]*(action|id|name)[[:space:]]*=[[:space:]]*["'"'"'][^"'"'"'>]*(login|log[-]?in|signin|auth|session|user|passwd|pwd|credential|verify|oauth|token|sso)' "$body_file"; then
          reasons+=("Found form with login-related attributes")
      fi
      if grep -qi -E '(<input[^>]*type=["'"'"']submit["'"'"'][^>]*value=["'"'"']?(login|sign[[:space:]]*in|authenticate)|<button[^>]*>([[:space:]]*)?(login|sign[[:space:]]*in|authenticate))' "$body_file"; then
          reasons+=("Found submit button with login text")
      fi
      if grep -qi -E 'Forgot[[:space:]]*Password|Reset[[:space:]]*Password|Sign[[:space:]]*in|Log[[:space:]]*in' "$body_file"; then
          reasons+=("Found textual indicators for login")
      fi
      if grep -qi -E '<input[^>]*type=["'"'"']hidden["'"'"'][^>]*(csrf|token|authenticity|nonce|xsrf)' "$body_file"; then
          reasons+=("Found hidden token field")
      fi
      if grep -qi -E '<meta[^>]+content=["'"'"'][^"'"'"']*(login|sign[[:space:]]*in)[^"'"'"']*["'"'"']' "$body_file"; then
          reasons+=("Found meta tag mentioning login")
      fi
      if grep -qi -E '(recaptcha|g-recaptcha|hcaptcha)' "$body_file"; then
          reasons+=("Found CAPTCHA widget")
      fi
      if grep -qi -E '(loginModal|modal[-_]?login|popup[-_]?login)' "$body_file"; then
          reasons+=("Found modal/popup login hint")
      fi
      if grep -qi -E '(iniciar[[:space:]]+sesiÃ³n|connexion|anmelden|accedi|entrar|inloggen)' "$body_file"; then
          reasons+=("Found multi-language login keyword")
      fi
      if grep -qi -E '(firebase\.auth|Auth0|passport)' "$body_file"; then
          reasons+=("Found JavaScript auth library reference")
      fi
      if grep -qi -E '^HTTP/.*[[:space:]]+(401|403|407)' "$headers_file"; then
          reasons+=("HTTP header indicates authentication requirement")
      fi
      if grep -qi 'WWW-Authenticate' "$headers_file"; then
          reasons+=("Found WWW-Authenticate header")
      fi
      if grep -qi -E 'Set-Cookie:[[:space:]]*(sessionid|PHPSESSID|JSESSIONID|auth_token|jwt)' "$headers_file"; then
          reasons+=("Found session cookie in headers")
      fi
      if grep -qi -E 'Location:.*(login|signin|auth)' "$headers_file"; then
          reasons+=("Found redirection to login in headers")
      fi
      if echo "$final_url" | grep -qiE '/(login|signin|auth|account|admin|wp-login\.php|wp-admin|users/sign_in|member/login|login\.aspx|signin\.aspx)'; then
          reasons+=("Final URL path suggests login endpoint")
      fi
      if echo "$final_url" | grep -qiE '[?&](redirect|action|auth|callback)='; then
          reasons+=("Final URL query parameters indicate login action")
      fi

      local login_found="No"
      if [ "${#reasons[@]}" -gt 0 ]; then
          login_found="Yes"
      fi

      local json_details
      # Dump each "reason" line as a JSON string, wrap in an array
      json_details=$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s .)

      # Return final detection object as JSON
      jq -n --arg login_found "$login_found" --argjson details "$json_details" \
            '{login_found: $login_found, login_details: $details}'
  }

  for url in $urls; do
      local headers_file="final_headers.tmp"
      local body_file="final_body.tmp"
      rm -f "$headers_file" "$body_file"

      local curl_err="curl_err.tmp"
      rm -f "$curl_err"

      # 1) First cURL: fetch the URLâ€™s headers/body
      set +e
      curl -s -S -L --max-time "$timeout_duration" \
           -D "$headers_file" \
           -o "$body_file" \
           "$url" \
           2> "$curl_err"
      local curl_exit=$?
      set -e

      # If cURL returned error code 35 (SSL connect error), skip
      if [ $curl_exit -eq 35 ]; then
          info "Skipping $url due to SSL error."
          rm -f "$headers_file" "$body_file" "$curl_err"
          continue
      fi

      # If any other error occurred, log in JSON but mark no login found
      if [ $curl_exit -ne 0 ]; then
          if [ "$first_entry" = true ]; then
              first_entry=false
          else
              echo "," >> "$output_file"
          fi

          echo "  { \"url\": \"${url}\", \"final_url\": \"\", \"login_detection\": { \"login_found\": \"No\", \"login_details\": [] } }" >> "$output_file"

          rm -f "$headers_file" "$body_file" "$curl_err"
          continue
      fi

      rm -f "$curl_err"

      # 2) Second cURL: get the final URL cURL ended up on
      set +e
      local final_url
      final_url=$(curl -s -o /dev/null -w "%{url_effective}" -L --max-time "$timeout_duration" "$url")
      local final_curl_exit=$?
      set -e

      # If it failed, or is empty, fallback to the original
      if [ $final_curl_exit -ne 0 ] || [ -z "$final_url" ]; then
          final_url="$url"
      fi

      # Actually do the detection
      local detection_json
      detection_json=$(detect_login "$headers_file" "$body_file" "$final_url")

      # If detection says "Yes", increment count
      if echo "$detection_json" | grep -q '"login_found": "Yes"'; then
          LOGIN_FOUND_COUNT=$((LOGIN_FOUND_COUNT + 1))
      fi

      # Write out the JSON for this URL
      if [ "$first_entry" = true ]; then
          first_entry=false
      else
          echo "," >> "$output_file"
      fi

      echo "  { \"url\": \"${url}\", \"final_url\": \"${final_url}\", \"login_detection\": $detection_json }" >> "$output_file"

      rm -f "$headers_file" "$body_file"
  done

  echo "]" >> "$output_file"

  # Clean up any lingering .tmp
  rm -f *.tmp
}

##############################################
# Security Compliance Detection
##############################################
run_security_compliance() {
  info "Analyzing security hygiene using..."
  local output_file="$RUN_DIR/securitycompliance.json"
  local REQUEST_TIMEOUT=4

  # Ensure that MASTER_SUBS exists (for full domain coverage)
  if [ ! -f "$MASTER_SUBS" ]; then
    echo "Error: MASTER_SUBS file not found!" >&2
    return 1
  fi

  # Ensure that httpx.json exists (for live URL details)
  if [ ! -f "$RUN_DIR/httpx.json" ]; then
    echo "Error: httpx.json not found!" >&2
    return 1
  fi

  local temp_dir
  temp_dir=$(mktemp -d)

  # Process each domain from MASTER_SUBS.
  while IFS= read -r domain || [ -n "$domain" ]; do
    domain=$(echo "$domain" | tr -d '\r' | xargs)
    [ -z "$domain" ] && continue

    # --- Functionality 1: Domain-level DNS checks ---
    local spf dkim dmarc dnskey dnssec
    spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" | head -n 1 || true)
    [ -z "$spf" ] && spf="No SPF Record"
    dkim=$(dig +short TXT "default._domainkey.$domain" 2>/dev/null | grep -i "v=DKIM1" | head -n 1 || true)
    [ -z "$dkim" ] && dkim="No DKIM Record"
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC1" | head -n 1 || true)
    [ -z "$dmarc" ] && dmarc="No DMARC Record"
    dnskey=$(dig +short DNSKEY "$domain" 2>/dev/null || true)
    if [ -z "$dnskey" ]; then
      dnssec="DNSSEC Not Enabled"
    else
      dnssec="DNSSEC Enabled"
    fi

    # --- Functionality 2 & 3: Process live URL records from httpx.json ---
    # Filter httpx.json for records where the "input" field starts with the domain.
    local matches
    matches=$(jq -c --arg domain "$domain" 'select(.input | startswith($domain))' "$RUN_DIR/httpx.json")

    if [ -n "$matches" ]; then
      # For each matching live URL record...
      echo "$matches" | while IFS= read -r record; do
        local url ssl_version ssl_issuer cert_expiry sts xfo csp xss rp pp acao
        url=$(echo "$record" | jq -r '.url')
        # Since URLs are always in the format https://host:port,
        # extract host and port with a simplified regex.
        if [[ "$url" =~ ^https://([^:]+):([0-9]+) ]]; then
          local host port
          host="${BASH_REMATCH[1]}"
          port="${BASH_REMATCH[2]}"
        else
          host=""
          port=""
        fi

        # SSL Certificate Checks (only if HTTPS)
        if [ -n "$host" ]; then
          local ssl_output CERT
          ssl_output=$(echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null || true)
          CERT=$(echo "$ssl_output" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)
          if [ -n "$CERT" ]; then
            ssl_version=$(echo "$ssl_output" | grep -i "Protocol:" | head -1 | awk -F": " '{print $2}' || true)
            [ -z "$ssl_version" ] && ssl_version="Unknown"
            ssl_issuer=$(echo "$CERT" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //' || true)
            [ -z "$ssl_issuer" ] && ssl_issuer="N/A"
            cert_expiry=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
            [ -z "$cert_expiry" ] && cert_expiry="N/A"
          else
            ssl_version="No SSL/TLS"
            ssl_issuer="N/A"
            cert_expiry="N/A"
          fi
        else
          ssl_version="No SSL/TLS"
          ssl_issuer="N/A"
          cert_expiry="N/A"
        fi

        # Security Headers Check using the exact URL from httpx.json:
        local HEADERS
        HEADERS=$(curl -s -D - "$url" -o /dev/null --max-time "$REQUEST_TIMEOUT" || true)
        sts=$(echo "$HEADERS" | grep -i "Strict-Transport-Security:" | cut -d':' -f2- | xargs || true)
        xfo=$(echo "$HEADERS" | grep -i "X-Frame-Options:" | cut -d':' -f2- | xargs || true)
        csp=$(echo "$HEADERS" | grep -i "Content-Security-Policy:" | cut -d':' -f2- | xargs || true)
        xss=$(echo "$HEADERS" | grep -i "X-XSS-Protection:" | cut -d':' -f2- | xargs || true)
        rp=$(echo "$HEADERS" | grep -i "Referrer-Policy:" | cut -d':' -f2- | xargs || true)
        pp=$(echo "$HEADERS" | grep -i "Permissions-Policy:" | cut -d':' -f2- | xargs || true)
        acao=$(echo "$HEADERS" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs || true)

        # --- Build the JSON record for this domain+URL combination ---
        jq -n --arg domain "$domain" --arg url "$url" \
          --arg spf "$spf" --arg dkim "$dkim" --arg dmarc "$dmarc" --arg dnssec "$dnssec" \
          --arg ssl_version "$ssl_version" --arg ssl_issuer "$ssl_issuer" --arg cert_expiry "$cert_expiry" \
          --arg sts "$sts" --arg xfo "$xfo" --arg csp "$csp" --arg xss "$xss" --arg rp "$rp" --arg pp "$pp" --arg acao "$acao" \
          '{
             Domain: $domain,
             URL: $url,
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
      done >> "$temp_dir/records.json"
    else
      # If no live URL is found in httpx.json for this domain, output one record with defaults.
      jq -n --arg domain "$domain" --arg url "N/A" \
        --arg spf "$spf" --arg dkim "$dkim" --arg dmarc "$dmarc" --arg dnssec "$dnssec" \
        --arg ssl_version "No SSL/TLS" --arg ssl_issuer "N/A" --arg cert_expiry "N/A" \
        --arg sts "" --arg xfo "" --arg csp "" --arg xss "" --arg rp "" --arg pp "" --arg acao "" \
        '{
           Domain: $domain,
           URL: $url,
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
         }' >> "$temp_dir/records.json"
    fi
  done < "$MASTER_SUBS"

  # Combine all generated JSON records into one JSON array.
  if [ ! -s "$temp_dir/records.json" ]; then
    echo "[]" > "$output_file"
  else
    jq -s '.' "$temp_dir/records.json" > "$output_file"
  fi
  rm -r "$temp_dir"
}



##############################################
# Merge line-based JSON -> single-array JSON
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
# API Endpoint Identification
##############################################
run_api_identification() {
  info "Identifying API endpoints..."
  local api_file="$RUN_DIR/api_identification.json"
  echo "[" > "$api_file"
  local first_entry=true
  while read -r domain; do
    # Check if the domain/subdomain contains .api. or -api- or -api.
    if echo "$domain" | grep -E -i '(\.api\.|-api-|-api\.)' > /dev/null; then
      api_status="Yes"
    else
      api_status="No"
    fi
    if [ "$first_entry" = true ]; then
      first_entry=false
    else
      echo "," >> "$api_file"
    fi
    echo "  { \"domain\": \"${domain}\", \"api_endpoint\": \"${api_status}\" }" >> "$api_file"
  done < "$MASTER_SUBS"
  echo "]" >> "$api_file"
}

##############################################
# Colleague Endpoint Identification
##############################################
run_colleague_identification() {
  info "Identifying colleague-facing endpoints..."
  local colleague_file="$RUN_DIR/colleague_identification.json"
  # Define the set of keywords that strongly indicate an internal (employee intended) endpoint.
  # (Note: We intentionally exclude very short tokens like 'qa' to avoid false positives.)
  local tokens=("dev" "development" "test" "testing" "qa" "uat" "stage" "staging" "demo" "sandbox" "lab" "labs" "experimental" "preprod" "pre-production" "pre-prod" "nonprod" "non-production" "non-prod" "perf" "performance" "loadtest" "soaktest" "integration" "integrationtest" "release" "hotfix" "feature" "rc" "beta" "alpha" "internal" "private" "intranet" "corp" "corporate" "employee" "colleague" "partner" "restricted" "secure" "admin" "backoffice" "back-office" "management" "mgmt" "console" "ops" "operations" "dashboard" "sysadmin" "root" "sudo" "superuser" "jenkins" "teamcity" "bamboo" "circleci" "travis" "gitlab" "bitbucket" "gitea" "jira" "confluence" "artifactory" "nexus" "harbor" "grafana" "kibana" "prometheus" "alertmanager" "nagios" "zabbix" "splunk" "posthog" "sentry" "phabricator" "default" "standard" "placeholder" "dummy" "guest" "temp" "example" "portal" "hr" "hrportal" "helpdesk" "support" "servicedesk" "tools" "tooling" "services" "api-internal" "internalapi" "playground" "workshop" "vpn" "local" "localhost" "onprem" "on-prem" "dmz" "bastion" "jumpbox" "cache" "queue" "log" "logs" "monitor" "metrics" "ldap" "ad" "ntp" "smtp-internal" "ftp-internal")
  echo "[" > "$colleague_file"
  local first_entry=true
  while read -r domain; do
    # Convert the domain to lowercase
    local lc_domain
    lc_domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
    local found="No"
    # Split the domain into tokens using dot, hyphen, and underscore as delimiters
    local token
    for token in $(echo "$lc_domain" | tr '.-_ ' ' '); do
      for t in "${tokens[@]}"; do
        if [ "$token" = "$t" ]; then
          found="Yes"
          break 2
        fi
      done
    done
    if [ "$first_entry" = true ]; then
      first_entry=false
    else
      echo "," >> "$colleague_file"
    fi
    echo "  { \"domain\": \"${domain}\", \"colleague_endpoint\": \"${found}\" }" >> "$colleague_file"
  done < "$MASTER_SUBS"
  echo "]" >> "$colleague_file"
}

##############################################
# Build HTML Report
##############################################
build_html_report() {
  info "Building HTML report with analytics..."
  combine_json "$RUN_DIR/dnsx.json"   "$RUN_DIR/dnsx_merged.json"
  combine_json "$RUN_DIR/naabu.json"    "$RUN_DIR/naabu_merged.json"
  combine_json "$RUN_DIR/httpx.json"    "$RUN_DIR/httpx_merged.json"
  mv "$RUN_DIR/dnsx_merged.json"  "$RUN_DIR/dnsx.json"
  mv "$RUN_DIR/naabu_merged.json" "$RUN_DIR/naabu.json"
  mv "$RUN_DIR/httpx_merged.json" "$RUN_DIR/httpx.json"
  local report_html="$RUN_DIR/report.html"
  cat << 'EOF' > "$report_html"
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>External Attack Surface Analysis</title>
      <!-- Chart.js for charts -->
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        :root {
          /* Light theme colors */
          --light-bg-color: #f9f9f9;
          --light-text-color: #333;
          --light-header-bg: #fff;
          --light-header-text: #333;
          --light-table-bg: #fff;
          --light-table-header-bg: #eee;
          --light-table-border: #ddd;
          --light-toggle-bg: #ccc;
          --light-toggle-btn: #fff;

          /* Dark theme colors */
          --dark-bg-color: #1f1f1f;
          --dark-text-color: #f0f0f0;
          --dark-header-bg: #2a2a2a;
          --dark-header-text: #ffffff;
          --dark-table-bg: #2a2a2a;
          --dark-table-header-bg: #3a3a3a;
          --dark-table-border: #444;
          --dark-toggle-bg: #555;
          --dark-toggle-btn: #ffffff;

          /* Active theme variables */
          --bg-color: var(--light-bg-color);
          --text-color: var(--light-text-color);
          --header-bg: var(--light-header-bg);
          --header-text: var(--light-header-text);
          --table-bg: var(--light-table-bg);
          --table-header-bg: var(--light-table-header-bg);
          --table-border: var(--light-table-border);
          --toggle-bg: var(--light-toggle-bg);
          --toggle-btn: var(--light-toggle-btn);

          /* Font sizing */
          --font-size-sm: 12px;
          --font-size-base: 13px;
          --font-size-md: 14px;
          --font-size-lg: 16px;
          --heading-font-size: 22px;
        }

        body.dark {
          --bg-color: var(--dark-bg-color);
          --text-color: var(--dark-text-color);
          --header-bg: var(--dark-header-bg);
          --header-text: var(--dark-header-text);
          --table-bg: var(--dark-table-bg);
          --table-header-bg: var(--dark-table-header-bg);
          --table-border: var(--dark-table-border);
          --toggle-bg: var(--dark-toggle-bg);
          --toggle-btn: var(--dark-toggle-btn);
        }

        body {
          margin: 0;
          background-color: var(--bg-color);
          color: var(--text-color);
          font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
          font-size: var(--font-size-base);
          line-height: 1.4;
        }

        /* HEADER */
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          background-color: var(--header-bg);
          color: var(--header-text);
          padding: 12px 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .header h1 {
          margin: 0;
          font-size: var(--heading-font-size);
          font-weight: 600;
        }

        .toggle-btn {
          background-color: var(--toggle-bg);
          border: none;
          color: var(--toggle-btn);
          padding: 6px 12px;
          cursor: pointer;
          border-radius: 4px;
          font-size: var(--font-size-sm);
          transition: background-color 0.2s, color 0.2s;
        }
        .toggle-btn:hover {
          opacity: 0.9;
        }

        .table-top-controls {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
        }

        /* MAIN CONTAINER */
        .container {
          padding: 20px;
          max-width: 1200px;
          margin: 0 auto;
        }

        /* SCOREBOARD */
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
          font-size: 1.6em;
          font-weight: 500;
        }
        .score-card p {
          margin: 5px 0 0;
          font-size: var(--font-size-sm);
          color: var(--text-color);
        }

        /* CHARTS GRID */
        .charts-grid {
          display: grid;
          gap: 10px;
          grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
          margin-bottom: 20px;
        }
        .chart-container {
          position: relative;
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

        /* SEARCH BOX */
        #searchBox {
          margin: 0;
          padding: 6px 10px;
          width: 250px;
          font-size: var(--font-size-sm);
          border: 1px solid var(--table-border);
          border-radius: 4px;
        }

        /* TABLE CONTROLS */
        .table-controls {
          margin: 0;
          display: flex;
          justify-content: flex-end;
          align-items: center;
        }
        .table-controls label {
          margin-right: 6px;
          font-size: var(--font-size-sm);
        }
        .table-controls select {
          font-size: var(--font-size-sm);
          padding: 4px 8px;
          border: 1px solid var(--table-border);
          border-radius: 4px;
          background-color: var(--table-bg);
          color: var(--text-color);
        }

        /* MAIN TABLE */
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 10px;
          background-color: var(--table-bg);
          font-size: var(--font-size-sm);
        }
        th, td {
          border: 1px solid var(--table-border);
          padding: 8px;
          text-align: left;
          vertical-align: top;
          color: inherit;
        }
        th {
          background-color: var(--table-header-bg);
          font-weight: 600;
        }

        /* FILTER DROPDOWN ROW */
        #filter-row select {
          width: 100%;
          font-size: var(--font-size-sm);
          padding: 2px 4px;
          border: 1px solid var(--table-border);
          border-radius: 3px;
          background-color: var(--table-bg);
          color: var(--text-color);
        }

        /* PAGINATION CONTROLS */
        #paginationControls {
          margin-top: 10px;
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 10px;
        }
        #paginationControls button {
          padding: 6px 12px;
          cursor: pointer;
          font-size: var(--font-size-sm);
          border-radius: 4px;
          border: 1px solid var(--table-border);
          background-color: var(--toggle-bg);
          color: var(--toggle-btn);
          transition: background-color 0.2s, color 0.2s;
        }
        #paginationControls button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        /* Additional header for the last columns */
        th:nth-child(33) {
          white-space: nowrap;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>External Attack Surface Analysis Report</h1>
        <button id="themeToggle" class="toggle-btn">Change View</button>
      </div>
      <div class="container">
        <div class="scoreboard" id="scoreboard"></div>

        <div class="charts-grid">
          <!-- REPLACED chart ID from "priorityChart" to keep it but for the new funnel chart -->
          <div class="chart-container">
            <canvas id="priorityChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="statusCodeChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="loginPieChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="portChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="techChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="certExpiryChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="tlsUsageChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="headersChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="emailSecChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="cdnChart"></canvas>
          </div>
          <div class="chart-container">
            <canvas id="serviceChart"></canvas>
          </div>
          <!-- ADDED: Colleague (Employee Intended) Endpoint Chart -->
          <div class="chart-container">
            <canvas id="colleagueEndpointChart"></canvas>
          </div>
        </div>

        <div class="table-top-controls">
          <input type="text" id="searchBox" placeholder="Filter table (e.g. domain, status code, tech)..." />
          <div class="table-controls">
            <label for="rowsPerPageSelect">Rows per page:</label>
            <select id="rowsPerPageSelect">
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="all">ALL</option>
            </select>
          </div>
        </div>

        <table id="report-table">
          <thead>
            <tr>
              <!-- Arrow is now given a small left margin so itâ€™s clearly to the right of "Risk Score" -->
              <th id="riskScoreHeader">
                Risk Score<span id="riskSortToggle" style="cursor:pointer; user-select:none; margin-left:5px;">▼</span>
              </th>
              <th>Domain</th>
              <th>Purpose</th>
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
              <th>API Endpoint</th>
              <th>Technology Stack</th>
              <th>Status Code</th>
              <th>Content Length</th>
              <th>CDN</th>
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
              <th>Open Ports / Services</th>
            </tr>
            <tr id="filter-row">
              <th>
                <select id="priority-filter">
                  <option value="">All</option>
                </select>
              </th>
              <th><select id="domain-filter"><option value="">All</option></select></th>
              <th><select id="purpose-filter"><option value="">All</option></select></th>
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
              <th><select id="api-endpoint-filter"><option value="">All</option></select></th>
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
              <th><select id="ports-services-filter"><option value="">All</option></select></th>
            </tr>
          </thead>
          <tbody id="report-table-body"></tbody>
        </table>

        <div id="paginationControls"></div>
      </div>

      <script>
  // Plugin to show bar labels
  const barLabelPlugin = {
    id: 'barLabelPlugin',
    afterDatasetsDraw(chart, args, options) {
      const { ctx } = chart;
      const metaSets = chart.getSortedVisibleDatasetMetas().filter(m => m.type === 'bar');
      metaSets.forEach((meta) => {
        meta.data.forEach((element, index) => {
          const value = meta._parsed[index][meta.vScale.axis];
          if (value === 0) return;
          const { x, y } = element.tooltipPosition();
          ctx.save();
          ctx.fillStyle = Chart.defaults.color;
          ctx.font = options.font || '9px sans-serif';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'bottom';
          ctx.fillText(value, x, y - 2);
          ctx.restore();
        });
      });
    }
  };
  Chart.register(barLabelPlugin);

  // Chart variables
  let priorityChart, statusCodeChart, loginChart, portChart, techChart;
  let certExpiryChart, tlsUsageChart, headersChart, emailSecChart, cdnChart, serviceChart, colleagueChart;

  // For table and sorting
  let allTableRows = [];
  let currentPage = 1;
  let rowsPerPage = 20;

  // For risk scoring color gradient
  let riskScores = {};  // domain -> numericScore
  let minRiskScore = Infinity;
  let maxRiskScore = -Infinity;

  // Global sort order for risk score
  let riskSortOrder = "desc";

  const toggleButton = document.getElementById("themeToggle");
  toggleButton.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    updateChartTheme();
  });

  function updateChartTheme() {
    const newColor = getComputedStyle(document.body).getPropertyValue('--text-color').trim();
    Chart.defaults.color = newColor;
    const charts = [
      priorityChart, statusCodeChart, loginChart, portChart, techChart,
      certExpiryChart, tlsUsageChart, headersChart, emailSecChart, cdnChart,
      serviceChart, colleagueChart
    ];
    charts.forEach(chart => {
      if (chart) {
        if (chart.options.scales) {
          if (chart.options.scales.x && chart.options.scales.x.ticks) {
            chart.options.scales.x.ticks.color = newColor;
          }
          if (chart.options.scales.y && chart.options.scales.y.ticks) {
            chart.options.scales.y.ticks.color = newColor;
          }
        }
        if (chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels) {
          chart.options.plugins.legend.labels.color = newColor;
        }
        if (chart.options.plugins && chart.options.plugins.title) {
          chart.options.plugins.title.color = newColor;
        }
        chart.update();
      }
    });
  }

  const formatCell = (arr) => (arr && arr.length) ? arr.join("<br>") : "N/A";

  /**
   * Computes a risk score: bigger = more risk
   */
  function computePriority({
    purpose,
    url,
    loginFound,
    statusCode,
    sslVersion,
    certExpiry,
    sts,
    xfo,
    csp,
    xss,
    rp,
    pp,
    openPortsCount,
    techCount
  }) {
    let score = 0;

    // Check purpose
    if (purpose && purpose.toLowerCase().includes("employee")) {
      score += 1;
    }

    // URL
    if (url && url !== "N/A") {
      score += 1;
    }

    // Login
    if (loginFound === "Yes") {
      score += 1;
    }

    // Status 200
    if (statusCode === 200) {
      score += 1;
    }

    // TLS check: no penalty if TLSv1.2 or TLSv1.3
    if (sslVersion && sslVersion.toUpperCase().includes("TLS")) {
      const versionMatch = sslVersion.match(/TLSv(1\.2|1\.3)/i);
      if (versionMatch) {
        // version is 1.2 or 1.3 => no penalty
        const versionNumber = parseFloat(versionMatch[1]);
        if (versionNumber < 1.2) {
          score += 1;
        }
      } else {
        // older or unrecognized => +1
        score += 1;
      }
    } else {
      // not TLS => +1
      score += 1;
    }

    // Certificate expiry
    if (certExpiry && certExpiry !== "N/A") {
      const expiryDate = new Date(certExpiry);
      const now = new Date();
      const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
      if (!isNaN(diffDays)) {
        if (diffDays <= 7) {
          score += 3;
        } else if (diffDays <= 14) {
          score += 2;
        } else if (diffDays <= 30) {
          score += 1;
        }
      }
    }

    // Missing security headers
    function isHeaderMissing(header) {
      return !header || header.trim().toLowerCase() === "false" || header.trim() === "";
    }
    if (isHeaderMissing(sts)) { score += 1; }
    if (isHeaderMissing(xfo)) { score += 1; }
    if (isHeaderMissing(csp)) { score += 1; }
    if (isHeaderMissing(xss)) { score += 1; }
    if (isHeaderMissing(rp))  { score += 1; }
    if (isHeaderMissing(pp))  { score += 1; }

    // Open ports
    if (openPortsCount && Number.isFinite(openPortsCount)) {
      score += openPortsCount;
    }

    // Technology count => +1 per technology
    if (techCount && Number.isFinite(techCount)) {
      score += techCount;
    }

    return score;
  }

  // Dynamic color: minRiskScore => green, maxRiskScore => red
  function getDynamicColor(score, minScore, maxScore) {
    if (maxScore === minScore) {
      return "rgb(46, 204, 113)";
    }
    const fraction = (score - minScore) / (maxScore - minScore);
    const start = { r: 46, g: 204, b: 113 };
    const end   = { r: 231, g: 76, b: 60 };
    const r = Math.round(start.r + fraction * (end.r - start.r));
    const g = Math.round(start.g + fraction * (end.g - start.g));
    const b = Math.round(start.b + fraction * (end.b - start.b));
    return `rgb(${r}, ${g}, ${b})`;
  }

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

  // Funnel-like chart + other charts
  function buildCharts({
    statusCount,
    priorityCount,
    portCount,
    techCount,
    totalSubdomains,
    liveSubs,
    endpointsCount
  }) {
    const scCanvas = document.getElementById("statusCodeChart");
    const prCanvas = document.getElementById("priorityChart");
    const portCanvas = document.getElementById("portChart");
    const techCanvas = document.getElementById("techChart");

    // Funnel-like chart
    if (prCanvas) {
      const funnelLabels = ["Total Assets", "Live Assets", "Applications"];
      const funnelValues = [totalSubdomains, liveSubs, endpointsCount];

      if (priorityChart) {
        priorityChart.destroy();
      }

      priorityChart = new Chart(prCanvas, {
        type: "bar",
        data: {
          labels: funnelLabels,
          datasets: [{
            label: "Assets Overview",
            data: funnelValues,
            backgroundColor: ["#2980b9", "#8e44ad", "#16a085"]
          }]
        },
        options: {
          responsive: true,
          indexAxis: "x",
          plugins: {
            legend: { display: false },
            title: { display: true, text: "Assets Overview" }
          },
          scales: {
            x: {
              beginAtZero: true,
              title: { display: true, text: "Count" }
            }
          }
        }
      });
    }

    // Status Code Chart
    if (scCanvas) {
      const sortedKeys = Object.keys(statusCount).sort((a, b) => +a - +b);
      statusCodeChart = new Chart(scCanvas, {
        type: "bar",
        data: {
          labels: sortedKeys,
          datasets: [{
            label: "HTTP Status Codes",
            data: sortedKeys.map(l => statusCount[l]),
            backgroundColor: ["#3498db","#1abc9c","#9b59b6","#f1c40f","#e74c3c","#34495e","#95a5a6"]
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: false },
            title: { display: true, text: "HTTP Status Codes" }
          },
          scales: {
            y: { beginAtZero: true }
          }
        }
      });
    }

    // Port Chart
    if (portCanvas) {
      const sortedPorts = Object.keys(portCount).sort((a, b) => +a - +b);
      portChart = new Chart(portCanvas, {
        type: "bar",
        data: {
          labels: sortedPorts,
          datasets: [{
            label: "Open Ports",
            data: sortedPorts.map(p => portCount[p]),
            backgroundColor: "#f39c12"
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: false },
            title: { display: true, text: "Port Usage" }
          },
          scales: {
            y: { beginAtZero: true }
          }
        }
      });
    }

    // Tech Chart
    if (techCanvas) {
      const sortedTech = Object.keys(techCount).sort((a, b) => techCount[b] - techCount[a]);
      const top10 = sortedTech.slice(0, 10);
      techChart = new Chart(techCanvas, {
        type: "bar",
        data: {
          labels: top10,
          datasets: [{
            label: "Tech Usage (Top 10)",
            data: top10.map(t => techCount[t]),
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
          scales: {
            x: { beginAtZero: true }
          }
        }
      });
    }
  }

  function buildLoginPieChart(endpointsCount, loginFoundCount) {
    const canvas = document.getElementById("loginPieChart");
    if (!canvas) return;

    loginChart = new Chart(canvas, {
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
            if (diffDays <= 7) { exp7++; }
            else if (diffDays <= 14) { exp14++; }
            else if (diffDays <= 30) { exp30++; }
          }
        }
      }
    });

    const ctx = document.getElementById("certExpiryChart").getContext("2d");
    certExpiryChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Next 7 Days", "Next 14 Days", "Next 30 Days"],
        datasets: [{
          label: "Certs Expiring",
          data: [exp7, exp14, exp30],
          backgroundColor: ["#e74c3c", "#e67e22", "#3498db"]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          title: { display: true, text: "Certificate Expiry" },
          legend: { display: false }
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

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

    tlsUsageChart = new Chart(ctx, {
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
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  // This chart is still based on domain-level data for simplicity
  function buildHeadersChart(httpxData, secMapDomain) {
    let hstsSet = 0, hstsMissing = 0;
    let xfoSet = 0, xfoMissing = 0;
    let cspSet = 0, cspMissing = 0;

    httpxData.forEach(record => {
      if (record.status_code === 200) {
        const domain = (record.input || "").split(":")[0];
        const sec = secMapDomain[domain] || {};

        const hsts = (sec["Strict-Transport-Security"] || "").trim();
        const xfo  = (sec["X-Frame-Options"] || "").trim();
        const csp  = (sec["Content-Security-Policy"] || "").trim();

        if (hsts) hstsSet++; else hstsMissing++;
        if (xfo)  xfoSet++;  else xfoMissing++;
        if (csp)  cspSet++;  else cspMissing++;
      }
    });

    const ctx = document.getElementById("headersChart").getContext("2d");
    headersChart = new Chart(ctx, {
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

  function buildEmailSecChart(secData) {
    let spfSet = 0, spfMissing = 0;
    let dkimSet = 0, dkimMissing = 0;
    let dmarcSet = 0, dmarcMissing = 0;

    secData.forEach(item => {
      const spf   = item["SPF Record"] || "";
      const dkim  = item["DKIM Record"] || "";
      const dmarc = item["DMARC Record"] || "";

      if (spf.toLowerCase().includes("spf1")) spfSet++; else spfMissing++;
      if (dkim.toLowerCase().includes("dkim1")) dkimSet++; else dkimMissing++;
      if (dmarc.toLowerCase().includes("dmarc1")) dmarcSet++; else dmarcMissing++;
    });

    const ctx = document.getElementById("emailSecChart").getContext("2d");
    emailSecChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["SPF", "DKIM", "DMARC"],
        datasets: [
          { label: "Present", data: [spfSet, dkimSet, dmarcSet], backgroundColor: "#2ecc71" },
          { label: "Missing", data: [spfMissing, dkimMissing, dmarcMissing], backgroundColor: "#e74c3c" }
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
    cdnChart = new Chart(ctx, {
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
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  function buildServiceChart(naabuData) {
    const naabuMap = {};
    const serviceCount = {};

    naabuData.forEach(n => {
      const domain = n.host;
      const port = n.port;
      let service = "Unknown";

      const portServiceDB = {
        "7":"Echo","9":"Discard","13":"Daytime","21":"FTP","22":"SSH","23":"Telnet",
        "25":"SMTP","26":"SMTP","37":"Time","53":"DNS","79":"Finger","80":"HTTP",
        "81":"HTTP","88":"Kerberos","106":"POP3","110":"POP3","111":"RPC","113":"Ident",
        "119":"NNTP","135":"RPC","139":"SMB","143":"IMAP","144":"IMAP","179":"BGP",
        "199":"SMUX","389":"LDAP","427":"SLP","443":"HTTPS","444":"N/A","445":"SMB",
        "465":"SMTPS","513":"rlogin","514":"rsh","515":"Printer","543":"Klogin",
        "544":"Kshell","548":"AFP","554":"RTSP","587":"SMTP Submission","631":"IPP",
        "646":"LDP","873":"rsync","990":"FTPS","993":"IMAPS","995":"POP3S","1433":"MSSQL",
        "1720":"H.323","1723":"PPTP","1755":"Windows Media","1900":"SSDP","2000":"SCCP",
        "2001":"SCCP","2049":"NFS","2121":"FTP-Alt","2717":"MS-SQL","3000":"HTTP-Alt",
        "3128":"Squid","3306":"MySQL","3389":"RDP","3986":"N/A","4899":"N/A","5000":"UPnP",
        "5009":"N/A","5051":"NNTP-Posting","5060":"SIP","5101":"N/A","5190":"ICQ","5357":"WSD",
        "5432":"PostgreSQL","5631":"pcANYWHERE","5666":"NSClient++","5800":"VNC","5900":"VNC",
        "6000":"X11","6001":"X11","6646":"IRC","7070":"RealAudio","8000":"HTTP-Alt",
        "8008":"HTTP-Alt","8009":"AJP13","8080":"HTTP-Alt","8081":"HTTP-Alt","8443":"HTTPS-Alt",
        "8888":"HTTP-Alt","9100":"Printer","9999":"N/A","10000":"N/A","32768":"N/A","49152":"N/A",
        "49153":"N/A","49154":"N/A","49155":"N/A","49156":"N/A","49157":"N/A"
      };

      if (portServiceDB[port]) {
        service = portServiceDB[port];
      }

      if (!naabuMap[domain]) naabuMap[domain] = [];
      naabuMap[domain].push({ port, service });

      serviceCount[service] = (serviceCount[service] || 0) + 1;
    });

    // Attach to window so we can read in buildTableRows
    window.naabuMap = naabuMap;

    const ctx = document.getElementById("serviceChart").getContext("2d");
    const labels = Object.keys(serviceCount).sort((a, b) => serviceCount[b] - serviceCount[a]);
    const data = labels.map(l => serviceCount[l]);

    serviceChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Open Services",
          data,
          backgroundColor: "#9b59b6"
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          title: { display: true, text: "Open Services" }
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  function buildColleagueChart(colleagueData) {
    const countEmployee = colleagueData.filter(x => x.colleague_endpoint === "Yes").length;
    const countCustomer = colleagueData.length - countEmployee;

    const ctx = document.getElementById("colleagueEndpointChart").getContext("2d");
    colleagueChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Employee Intended", "Customer Intended"],
        datasets: [{
          label: "Purpose Count",
          data: [countEmployee, countCustomer],
          backgroundColor: ["#e74c3c", "#2ecc71"]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          title: { display: true, text: "Employee vs Customer Intended Endpoints" },
          legend: { display: false }
        },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  // We'll store row data here for second-pass coloring
  let rowDataStore = [];

  // Build the table rows
  function buildTableRows(combinedData, secMapDomain, secMapUrl, loginMap, apiMap, colleagueMap) {
    allTableRows = [];
    rowDataStore = [];

    Object.keys(combinedData).forEach(domain => {
      const { dns, http } = combinedData[domain];

      const dnsResolvers = dns && dns.resolver ? dns.resolver : [];
      const dnsA = dns && dns.a ? dns.a : [];
      const dnsStatus = dns ? dns.status_code : "N/A";

      // Domain-level fields (SPF, DKIM, DMARC, DNSSEC) from secMapDomain
      const domainSec = secMapDomain[domain] || {};
      const spf    = domainSec["SPF Record"] || "N/A";
      const dkim   = domainSec["DKIM Record"] || "N/A";
      const dmarc  = domainSec["DMARC Record"] || "N/A";
      const dnssec = domainSec["DNSSEC Status"] || "N/A";

      let openPortsHTML = "";
          let openPortsCount = 0;
          if (window.naabuMap && window.naabuMap[domain]) {
            openPortsHTML = window.naabuMap[domain].map(p => `${p.port} (${p.service})`).join("<br>");
            openPortsCount = window.naabuMap[domain].length;
          }

      if (http && http.length) {
        http.forEach(h => {
          // For URL-based fields (SSL/TLS, headers), check secMapUrl
          const urlSec = secMapUrl[h.url] || domainSec; // fallback if no exact URL match
          const sslVersion = urlSec["SSL/TLS Version"] || "N/A";
          const certExpiry = urlSec["Cert Expiry Date"] || "N/A";
          const sslIssuer  = urlSec["SSL/TLS Issuer"] || "N/A";

          const stsFlag = (urlSec["Strict-Transport-Security"] || "").trim() !== "" ? "True" : "False";
          const xfoFlag = (urlSec["X-Frame-Options"] || "").trim() !== "" ? "True" : "False";
          const cspFlag = (urlSec["Content-Security-Policy"] || "").trim() !== "" ? "True" : "False";
          const xssFlag = (urlSec["X-XSS-Protection"] || "").trim() !== "" ? "True" : "False";
          const rpFlag  = (urlSec["Referrer-Policy"] || "").trim() !== "" ? "True" : "False";
          const ppFlag  = (urlSec["Permissions-Policy"] || "").trim() !== "" ? "True" : "False";

          const techArr = Array.isArray(h.tech) ? h.tech : [];
          const sanitizedTech = techArr.map(item => item.replace(/\r?\n|\r/g, " ").trim());
          const techCount = sanitizedTech.length;

          // Compute risk
          const prioScore = computePriority({
            purpose: colleagueMap[domain] === "Yes" ? "Employee Intended" : "Customer Intended",
            url: h.url,
            loginFound: loginMap[h.url] || "No",
            statusCode: h.status_code,
            sslVersion,
            certExpiry,
            sts: urlSec["Strict-Transport-Security"] || "",
            xfo: urlSec["X-Frame-Options"] || "",
            csp: urlSec["Content-Security-Policy"] || "",
            xss: urlSec["X-XSS-Protection"] || "",
            rp:  urlSec["Referrer-Policy"] || "",
            pp:  urlSec["Permissions-Policy"] || "",
            openPortsCount,
            techCount
          });

          if (prioScore < minRiskScore) minRiskScore = prioScore;
          if (prioScore > maxRiskScore) maxRiskScore = prioScore;

          riskScores[domain] = prioScore;
          rowDataStore.push({ domain, prioScore });

          // Build the row
          const row = document.createElement("tr");
          row.innerHTML = `
            <td><!-- color assigned in second pass --></td>
            <td>${domain}</td>
            <td>${colleagueMap[domain] === "Yes" ? "Employee Intended" : "Customer Intended"}</td>
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
            <td>${apiMap[domain] || "No"}</td>
            <td>${sanitizedTech.length ? sanitizedTech.join("<br>") : "N/A"}</td>
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
            <td>${(window.naabuMap && window.naabuMap[domain]) ? window.naabuMap[domain].map(p => `${p.port} (${p.service})`).join("<br>") : "N/A"}</td>
          `;
          allTableRows.push(row);
        });
      } else {
        // If no HTTP records
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>N/A</td>
          <td>${domain}</td>
          <td>${colleagueMap[domain] === "Yes" ? "Employee Intended" : "Customer Intended"}</td>
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
          <td>N/A</td>
          <td>${spf}</td>
          <td>${dkim}</td>
          <td>${dmarc}</td>
          <td>${dnssec}</td>
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
        `;
        allTableRows.push(row);
      }
    });
  }

  // Apply final colors for risk
  function finalizeColors() {
    allTableRows.forEach(row => {
      const cells = row.getElementsByTagName("td");
      const scoreCell = cells[0];
      const domainCell = cells[1];
      const domain = domainCell.innerText.trim();

      if (scoreCell.innerText === "N/A") {
        return;
      }

      const entry = rowDataStore.find(r => r.domain === domain);
      if (!entry) {
        scoreCell.innerText = "N/A";
        return;
      }

      const prioScore = entry.prioScore;
      scoreCell.innerText = prioScore;

      const color = getDynamicColor(prioScore, minRiskScore, maxRiskScore);
      scoreCell.style.backgroundColor = color;
      scoreCell.style.color = "#fff";
    });
  }

  function getFilteredRows() {
    const query = document.getElementById("searchBox").value.toLowerCase();

    const filters = {
      priority:    document.getElementById("priority-filter").value.toLowerCase(),
      domain:      document.getElementById("domain-filter").value.toLowerCase(),
      purpose:     document.getElementById("purpose-filter").value.toLowerCase(),
      resolvers:   document.getElementById("resolvers-filter").value.toLowerCase(),
      arecords:    document.getElementById("arecords-filter").value.toLowerCase(),
      dnsstatus:   document.getElementById("dnsstatus-filter").value.toLowerCase(),
      cdnname:     document.getElementById("cdnname-filter").value.toLowerCase(),
      cdntype:     document.getElementById("cdntype-filter").value.toLowerCase(),
      port:        document.getElementById("port-filter").value.toLowerCase(),
      url:         document.getElementById("url-filter").value.toLowerCase(),
      redirect:    document.getElementById("redirect-filter").value.toLowerCase(),
      title:       document.getElementById("title-filter").value.toLowerCase(),
      webserver:   document.getElementById("webserver-filter").value.toLowerCase(),
      login:       document.getElementById("login-filter").value.toLowerCase(),
      apiEndpoint: document.getElementById("api-endpoint-filter").value.toLowerCase(),
      tech:        document.getElementById("tech-filter").value.toLowerCase(),
      statuscode:  document.getElementById("statuscode-filter").value.toLowerCase(),
      contentlength: document.getElementById("contentlength-filter").value.toLowerCase(),
      cdn:         document.getElementById("cdn-filter").value.toLowerCase(),
      spf:         document.getElementById("spf-filter").value.toLowerCase(),
      dkim:        document.getElementById("dkim-filter").value.toLowerCase(),
      dmarc:       document.getElementById("dmarc-filter").value.toLowerCase(),
      dnssec:      document.getElementById("dnssec-filter").value.toLowerCase(),
      sslversion:  document.getElementById("sslversion-filter").value.toLowerCase(),
      certexpiry:  document.getElementById("certexpiry-filter").value.toLowerCase(),
      sslissuer:   document.getElementById("sslissuer-filter").value.toLowerCase(),
      sts:         document.getElementById("sts-filter").value.toLowerCase(),
      xfo:         document.getElementById("xfo-filter").value.toLowerCase(),
      csp:         document.getElementById("csp-filter").value.toLowerCase(),
      xss:         document.getElementById("xss-filter").value.toLowerCase(),
      rp:          document.getElementById("rp-filter").value.toLowerCase(),
      pp:          document.getElementById("pp-filter").value.toLowerCase(),
      portsservices: document.getElementById("ports-services-filter").value.toLowerCase(),
    };

    const filtered = allTableRows.filter((row) => {
      const cells = row.getElementsByTagName("td");
      if (filters.priority && cells[0].innerText.toLowerCase() !== filters.priority) return false;
      if (filters.domain     && cells[1].innerText.toLowerCase() !== filters.domain) return false;
      if (filters.purpose    && cells[2].innerText.toLowerCase() !== filters.purpose) return false;
      if (filters.resolvers  && cells[3].innerText.toLowerCase() !== filters.resolvers) return false;
      if (filters.arecords   && cells[4].innerText.toLowerCase() !== filters.arecords) return false;
      if (filters.dnsstatus  && cells[5].innerText.toLowerCase() !== filters.dnsstatus) return false;
      if (filters.cdnname    && cells[6].innerText.toLowerCase() !== filters.cdnname) return false;
      if (filters.cdntype    && cells[7].innerText.toLowerCase() !== filters.cdntype) return false;
      if (filters.port       && cells[8].innerText.toLowerCase() !== filters.port) return false;
      if (filters.url        && cells[9].innerText.toLowerCase() !== filters.url) return false;
      if (filters.redirect   && cells[10].innerText.toLowerCase() !== filters.redirect) return false;
      if (filters.title      && cells[11].innerText.toLowerCase() !== filters.title) return false;
      if (filters.webserver  && cells[12].innerText.toLowerCase() !== filters.webserver) return false;
      if (filters.login      && cells[13].innerText.toLowerCase() !== filters.login) return false;
      if (filters.apiEndpoint && cells[14].innerText.toLowerCase() !== filters.apiEndpoint) return false;
      if (filters.tech       && cells[15].innerText.toLowerCase() !== filters.tech) return false;
      if (filters.statuscode && cells[16].innerText.toLowerCase() !== filters.statuscode) return false;
      if (filters.contentlength && cells[17].innerText.toLowerCase() !== filters.contentlength) return false;
      if (filters.cdn        && cells[18].innerText.toLowerCase() !== filters.cdn) return false;
      if (filters.spf        && cells[19].innerText.toLowerCase() !== filters.spf) return false;
      if (filters.dkim       && cells[20].innerText.toLowerCase() !== filters.dkim) return false;
      if (filters.dmarc      && cells[21].innerText.toLowerCase() !== filters.dmarc) return false;
      if (filters.dnssec     && cells[22].innerText.toLowerCase() !== filters.dnssec) return false;
      if (filters.sslversion && cells[23].innerText.toLowerCase() !== filters.sslversion) return false;
      if (filters.certexpiry && cells[24].innerText.toLowerCase() !== filters.certexpiry) return false;
      if (filters.sslissuer  && cells[25].innerText.toLowerCase() !== filters.sslissuer) return false;
      if (filters.sts        && cells[26].innerText.toLowerCase() !== filters.sts) return false;
      if (filters.xfo        && cells[27].innerText.toLowerCase() !== filters.xfo) return false;
      if (filters.csp        && cells[28].innerText.toLowerCase() !== filters.csp) return false;
      if (filters.xss        && cells[29].innerText.toLowerCase() !== filters.xss) return false;
      if (filters.rp         && cells[30].innerText.toLowerCase() !== filters.rp) return false;
      if (filters.pp         && cells[31].innerText.toLowerCase() !== filters.pp) return false;
      if (filters.portsservices && !cells[32].innerText.toLowerCase().includes(filters.portsservices)) return false;
      if (query && !row.innerText.toLowerCase().includes(query)) return false;
      return true;
    });

    // Sort by risk score
    filtered.sort((a, b) => {
      const scoreA = parseInt(a.cells[0].innerText) || 0;
      const scoreB = parseInt(b.cells[0].innerText) || 0;
      return riskSortOrder === "asc" ? scoreA - scoreB : scoreB - scoreA;
    });

    return filtered;
  }

  function renderTable(filteredRows) {
    const tBody = document.getElementById("report-table-body");
    tBody.innerHTML = "";

    let startIndex = 0;
    let endIndex = filteredRows.length;

    if (rowsPerPage !== "all" && rowsPerPage !== Infinity) {
      startIndex = (currentPage - 1) * rowsPerPage;
      endIndex = startIndex + rowsPerPage;
    }

    const rowsToShow = filteredRows.slice(startIndex, endIndex);
    rowsToShow.forEach(row => tBody.appendChild(row));
    renderPaginationControls(filteredRows.length);
  }

  function renderPaginationControls(totalRows) {
    const paginationDiv = document.getElementById("paginationControls");
    paginationDiv.innerHTML = "";

    if (rowsPerPage === "all" || rowsPerPage === Infinity) return;

    const totalPages = Math.ceil(totalRows / rowsPerPage);
    const pageInfo = document.createElement("span");
    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    paginationDiv.appendChild(pageInfo);

    const prevBtn = document.createElement("button");
    prevBtn.textContent = "Prev";
    prevBtn.disabled = currentPage === 1;
    prevBtn.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        renderTable(getFilteredRows());
      }
    });
    paginationDiv.appendChild(prevBtn);

    const nextBtn = document.createElement("button");
    nextBtn.textContent = "Next";
    nextBtn.disabled = currentPage === totalPages;
    nextBtn.addEventListener("click", () => {
      if (currentPage < totalPages) {
        currentPage++;
        renderTable(getFilteredRows());
      }
    });
    paginationDiv.appendChild(nextBtn);
  }

  function onFilterChange() {
    currentPage = 1;
    renderTable(getFilteredRows());
  }

  function updateRowsPerPage() {
    const select = document.getElementById("rowsPerPageSelect");
    const value = select.value;
    if (value === "all") rowsPerPage = Infinity;
    else rowsPerPage = parseInt(value, 10);
    currentPage = 1;
    renderTable(getFilteredRows());
  }

  function populateColumnFilters() {
    const uniqueCols = Array.from({ length: 33 }, () => new Set());
    allTableRows.forEach((row) => {
      const cells = row.getElementsByTagName("td");
      for (let col = 0; col < 33; col++) {
        uniqueCols[col].add(cells[col].innerText.trim());
      }
    });

    function fillSelectOptions(selectId, values) {
      const select = document.getElementById(selectId);
      const existing = select.querySelectorAll("option:not([value=''])");
      existing.forEach((opt) => opt.remove());

      // Sort numeric columns descending
      if (selectId === "priority-filter") {
        values = values.filter(v => !isNaN(v)).sort((a, b) => b - a);
      } else {
        values.sort();
      }

      values.forEach((val) => {
        if (val.toLowerCase() === "asc" || val.toLowerCase() === "desc") {
          return;
        }
        const option = document.createElement("option");
        option.value = val;
        option.textContent = val;
        select.appendChild(option);
      });
    }

    fillSelectOptions("priority-filter",   [...uniqueCols[0]]);
    fillSelectOptions("domain-filter",     [...uniqueCols[1]]);
    fillSelectOptions("purpose-filter",    [...uniqueCols[2]]);
    fillSelectOptions("resolvers-filter",  [...uniqueCols[3]]);
    fillSelectOptions("arecords-filter",   [...uniqueCols[4]]);
    fillSelectOptions("dnsstatus-filter",  [...uniqueCols[5]]);
    fillSelectOptions("cdnname-filter",    [...uniqueCols[6]]);
    fillSelectOptions("cdntype-filter",    [...uniqueCols[7]]);
    fillSelectOptions("port-filter",       [...uniqueCols[8]]);
    fillSelectOptions("url-filter",        [...uniqueCols[9]]);
    fillSelectOptions("redirect-filter",   [...uniqueCols[10]]);
    fillSelectOptions("title-filter",      [...uniqueCols[11]]);
    fillSelectOptions("webserver-filter",  [...uniqueCols[12]]);
    fillSelectOptions("login-filter",      [...uniqueCols[13]]);
    fillSelectOptions("api-endpoint-filter", [...uniqueCols[14]]);
    fillSelectOptions("tech-filter",       [...uniqueCols[15]]);
    fillSelectOptions("statuscode-filter", [...uniqueCols[16]]);
    fillSelectOptions("contentlength-filter", [...uniqueCols[17]]);
    fillSelectOptions("cdn-filter",        [...uniqueCols[18]]);
    fillSelectOptions("spf-filter",        [...uniqueCols[19]]);
    fillSelectOptions("dkim-filter",       [...uniqueCols[20]]);
    fillSelectOptions("dmarc-filter",      [...uniqueCols[21]]);
    fillSelectOptions("dnssec-filter",     [...uniqueCols[22]]);
    fillSelectOptions("sslversion-filter", [...uniqueCols[23]]);
    fillSelectOptions("certexpiry-filter", [...uniqueCols[24]]);
    fillSelectOptions("sslissuer-filter",  [...uniqueCols[25]]);
    fillSelectOptions("sts-filter",        [...uniqueCols[26]]);
    fillSelectOptions("xfo-filter",        [...uniqueCols[27]]);
    fillSelectOptions("csp-filter",        [...uniqueCols[28]]);
    fillSelectOptions("xss-filter",        [...uniqueCols[29]]);
    fillSelectOptions("rp-filter",         [...uniqueCols[30]]);
    fillSelectOptions("pp-filter",         [...uniqueCols[31]]);
    fillSelectOptions("ports-services-filter", [...uniqueCols[32]]);
  }

  function attachFilterEvents() {
    [
      "priority-filter","domain-filter","purpose-filter","resolvers-filter","arecords-filter","dnsstatus-filter",
      "cdnname-filter","cdntype-filter","port-filter","url-filter","redirect-filter","title-filter",
      "webserver-filter","login-filter","api-endpoint-filter","tech-filter","statuscode-filter","contentlength-filter",
      "cdn-filter","spf-filter","dkim-filter","dmarc-filter","dnssec-filter","sslversion-filter","certexpiry-filter",
      "sslissuer-filter","sts-filter","xfo-filter","csp-filter","xss-filter","rp-filter","pp-filter",
      "ports-services-filter"
    ].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", onFilterChange);
    });
  }

  document.getElementById("searchBox").addEventListener("input", onFilterChange);
  document.getElementById("rowsPerPageSelect").addEventListener("change", updateRowsPerPage);

  document.getElementById("riskSortToggle").addEventListener("click", function() {
    riskSortOrder = (riskSortOrder === "asc") ? "desc" : "asc";
    this.textContent = (riskSortOrder === "asc") ? "▲" : "▼";
    renderTable(getFilteredRows());
  });

  async function loadData() {
    try {
      // Fetch all JSON files
      const [dnsxRes, naabuRes, httpxRes, loginRes, secRes, apiRes, colleagueRes] = await Promise.all([
        fetch("dnsx.json"),
        fetch("naabu.json"),
        fetch("httpx.json"),
        fetch("login.json"),
        fetch("securitycompliance.json"),
        fetch("api_identification.json"),
        fetch("colleague_identification.json")
      ]);
      const dnsxData        = await dnsxRes.json().catch(() => []);
      const naabuData       = await naabuRes.json().catch(() => []);
      const httpxData       = await httpxRes.json().catch(() => []);
      const loginData       = await loginRes.json().catch(() => []);
      const secData         = await secRes.json().catch(() => []);
      const apiData         = await apiRes.json().catch(() => []);
      const colleagueData   = await colleagueRes.json().catch(() => []);

      // Build two maps from securitycompliance.json
      const secMapDomain = {};  // domain => first record for domain (SPF, DKIM, DMARC, DNSSEC)
      const secMapUrl = {};     // url => exact record for SSL/TLS and headers
      secData.forEach(item => {
        if (item.Domain && !secMapDomain[item.Domain]) {
          secMapDomain[item.Domain] = item;
        }
        if (item.URL) {
          secMapUrl[item.URL] = item;
        }
      });

      const loginMap = {};
      loginData.forEach(item => {
        loginMap[item.url] = item.login_detection.login_found;
      });

      const apiMap = {};
      apiData.forEach(item => {
        apiMap[item.domain] = item.api_endpoint;
      });

      const colleagueMap = {};
      colleagueData.forEach(item => {
        colleagueMap[item.domain] = item.colleague_endpoint;
      });

      const endpointsCount = httpxData.length;
      const loginFoundCount = loginData.filter(item => item.login_detection.login_found === "Yes").length;
      const liveSubs = dnsxData.filter(d => d.status_code === "NOERROR").length;
      const domainSet = new Set();
      dnsxData.forEach(d => { if (d.host) domainSet.add(d.host); });
      const totalSubdomains = domainSet.size;

      buildLoginPieChart(endpointsCount, loginFoundCount);
      buildScoreboard({ totalSubdomains, liveSubs, totalHttpx: endpointsCount, loginFoundCount });

      // Status code counts
      const statusCount = {};
      httpxData.forEach(h => {
        const code = h.status_code || 0;
        statusCount[code] = (statusCount[code] || 0) + 1;
      });

      // priorityCount not directly used in funnel, but kept for reference
      const priorityCount = {};

      httpxData.forEach(h => {
        const domain = (h.input || "").split(":")[0];
        const prioScore = computePriority({
          purpose: colleagueMap[domain] === "Yes" ? "Employee Intended" : "Customer Intended",
          url: h.url,
          loginFound: loginMap[h.url] || "No",
          statusCode: h.status_code,
          sslVersion: secMapDomain[domain] ? secMapDomain[domain]["SSL/TLS Version"] : "N/A",
          certExpiry: secMapDomain[domain] ? secMapDomain[domain]["Cert Expiry Date"] : "N/A",
          sts: secMapDomain[domain] ? secMapDomain[domain]["Strict-Transport-Security"] : "",
          xfo: secMapDomain[domain] ? secMapDomain[domain]["X-Frame-Options"] : "",
          csp: secMapDomain[domain] ? secMapDomain[domain]["Content-Security-Policy"] : "",
          xss: secMapDomain[domain] ? secMapDomain[domain]["X-XSS-Protection"] : "",
          rp:  secMapDomain[domain] ? secMapDomain[domain]["Referrer-Policy"] : "",
          pp:  secMapDomain[domain] ? secMapDomain[domain]["Permissions-Policy"] : "",
          openPortsCount: 0,
          techCount: (h.tech && h.tech.length) ? h.tech.length : 0
        });
        if (!priorityCount[domain] || prioScore > priorityCount[domain]) {
          priorityCount[domain] = prioScore;
        }
        if (prioScore < minRiskScore) minRiskScore = prioScore;
        if (prioScore > maxRiskScore) maxRiskScore = prioScore;
      });

      // Port usage counts
      const portCount = {};
      naabuData.forEach(n => {
        const p = n.port || "unknown";
        portCount[p] = (portCount[p] || 0) + 1;
      });

      // Tech usage counts
      const techCount = {};
      httpxData.forEach(h => {
        if (Array.isArray(h.tech)) {
          h.tech.forEach(t => {
            techCount[t] = (techCount[t] || 0) + 1;
          });
        }
      });

      // Build main charts
      buildCharts({
        statusCount,
        priorityCount,
        portCount,
        techCount,
        totalSubdomains,
        liveSubs,
        endpointsCount
      });
      buildServiceChart(naabuData);
      buildColleagueChart(colleagueData);

      // Combine DNS + HTTP data
      const combinedData = {};
      dnsxData.forEach(d => {
        combinedData[d.host] = { dns: d, http: [] };
      });
      httpxData.forEach(h => {
        const domain = (h.input || "").split(":")[0];
        if (!combinedData[domain]) combinedData[domain] = { dns: null, http: [] };
        combinedData[domain].http.push(h);
      });

      // Build table rows
      buildTableRows(combinedData, secMapDomain, secMapUrl, loginMap, apiMap, colleagueMap);
      finalizeColors();
      populateColumnFilters();
      attachFilterEvents();
      renderTable(getFilteredRows());

      // For the certificate expiry + TLS usage charts
      const validDomains = new Set();
      httpxData.forEach(h => {
        if (h.url && h.url !== "N/A") {
          validDomains.add((h.input || "").split(":")[0]);
        }
      });
      const secDataValid = secData.filter(item => validDomains.has(item.Domain));

      if (secDataValid.length > 0) {
        buildCertExpiryChart(secDataValid);
        buildTLSUsageChart(secDataValid);
      } else {
        document.getElementById("certExpiryChart").parentElement.innerHTML =
          "<p>No valid website data available for certificate analysis.</p>";
        document.getElementById("tlsUsageChart").parentElement.innerHTML =
          "<p>No valid website data available for TLS usage analysis.</p>";
      }

      buildHeadersChart(httpxData, secMapDomain);
      buildEmailSecChart(secData);
      buildCDNChart(httpxData);

      updateChartTheme();
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
# Show final summary table
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
  echo "============================================="
}

##############################################
# Main Execution
##############################################
main() {
  run_chaos
  run_subfinder
  run_assetfinder
  run_crtsh
  info "Merging subdomains..."
  while read -r domain; do
    echo "$domain" >> "$ALL_TEMP"
    echo "www.$domain" >> "$ALL_TEMP"
  done < "$PRIMARY_DOMAINS_FILE"
  sort -u "$ALL_TEMP" > "$MASTER_SUBS"
  rm -f "$ALL_TEMP"
  run_dnsx
  run_naabu
  run_httpx
  run_login_detection
  run_security_compliance
  run_api_identification
  run_colleague_identification
  build_html_report
  show_summary
}

main
