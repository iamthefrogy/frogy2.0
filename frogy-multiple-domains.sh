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
# Helper: Print with colors (minimal logs)
##############################################
info()    { echo -e "\033[96m[+] $*\033[0m"; }
warning() { echo -e "\033[93m[!] $*\033[0m"; }
error()   { echo -e "\033[91m[-] $*\033[0m"; }

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
# CHAOS
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
  local crt_file="$RUN_DIR/whois.txtls"
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
        | egrep -v '(Whois|domains|proxy|PRIVACY|REDACTED|DNStination|Protected|Registration Private)' \
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
# DNSX – Live Domain Check
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
# Naabu – Port Scanning (Custom port list)
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
# HTTPX – Web Recon
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
  if [ ! -f "$input_file" ]; then
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    return
  fi
  local timeout_duration="10"
  local urls
  urls=$(jq -r '.url' "$input_file")
  echo "[" > "$output_file"
  local first_entry=true
  detect_login() {
      local headers_file="$1"
      local body_file="$2"
      local final_url="$3"
      local -a reasons=()
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
      if grep -qi -E '(iniciar[[:space:]]+sesión|connexion|anmelden|accedi|entrar|inloggen)' "$body_file"; then
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
      if [ ${#reasons[@]:-0} -gt 0 ]; then
          login_found="Yes"
      fi
      local json_details
      json_details=$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s .)
      jq -n --arg login_found "$login_found" --argjson details "$json_details" \
            '{login_found: $login_found, login_details: $details}'
  }
  for url in $urls; do
      local headers_file="final_headers.tmp"
      local body_file="final_body.tmp"
      rm -f "$headers_file" "$body_file"
      local curl_err="curl_err.tmp"
      rm -f "$curl_err"
      set +e
      curl -s -S -L --max-time "$timeout_duration" -D "$headers_file" -o "$body_file" "$url" 2> "$curl_err"
      local curl_exit=$?
      set -e
      if [ $curl_exit -eq 35 ]; then
          info "Skipping $url due to SSL error."
          rm -f "$headers_file" "$body_file" "$curl_err"
          continue
      fi
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
      local final_url
      final_url=$(curl -s -o /dev/null -w "%{url_effective}" -L --max-time "$timeout_duration" "$url")
      [ -z "$final_url" ] && final_url="$url"
      local detection_json
      detection_json=$(detect_login "$headers_file" "$body_file" "$final_url")
      if echo "$detection_json" | grep -q '"login_found": "Yes"'; then
          LOGIN_FOUND_COUNT=$((LOGIN_FOUND_COUNT + 1))
      fi
      if [ "$first_entry" = true ]; then
          first_entry=false
      else
          echo "," >> "$output_file"
      fi
      echo "  { \"url\": \"${url}\", \"final_url\": \"${final_url}\", \"login_detection\": $detection_json }" >> "$output_file"
      rm -f "$headers_file" "$body_file"
  done
  echo "]" >> "$output_file"
  rm -f *.tmp
}

##############################################
# Security Compliance Detection
##############################################
securitycompliance() {
  info "Analyzing security hygiene (it will take some time)..."
  local input_file="$MASTER_SUBS"
  local output_file="$RUN_DIR/securitycompliance.json"
  local REQUEST_TIMEOUT=4
  if [ ! -s "$input_file" ]; then
    echo "Error: Input file '$input_file' not found or is empty." >&2
    return 1
  fi
  analyze_domain() {
    local domain="$1"
    domain=$(echo "$domain" | tr -d '\r' | xargs)
    [ -z "$domain" ] && return
    local spf
    spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" || true)
    [ -z "$spf" ] && spf="No SPF Record"
    local dkim
    dkim=$(dig +short TXT "default._domainkey.$domain" 2>/dev/null | grep -i "v=DKIM1" || true)
    [ -z "$dkim" ] && dkim="No DKIM Record"
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC1" || true)
    [ -z "$dmarc" ] && dmarc="No DMARC Record"
    local dnskey dnssec
    dnskey=$(dig +short DNSKEY "$domain" 2>/dev/null || true)
    if [ -z "$dnskey" ]; then
      dnssec="DNSSEC Not Enabled"
    else
      dnssec="DNSSEC Enabled"
    fi
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
  local temp_dir
  temp_dir=$(mktemp -d)
  while IFS= read -r domain || [ -n "$domain" ]; do
    domain=$(echo "$domain" | tr -d '\r')
    [ -z "$domain" ] && continue
    local sanitized
    sanitized=$(echo "$domain" | tr '/.' '_')
    analyze_domain "$domain" > "$temp_dir/${sanitized}.json"
  done < "$MASTER_SUBS"
  shopt -s nullglob
  local files=("$temp_dir"/*.json)
  if [ ${#files[@]} -eq 0 ]; then
    echo "[]" > "$output_file"
  else
    jq -s '.' "${files[@]}" > "$output_file"
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
      /* NEW: Additional header for Open Ports/Services column */
      th:nth-child(31) {
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
            <th><select id="ports-services-filter"><option value="">All</option></select></th>
          </tr>
        </thead>
        <tbody id="report-table-body"></tbody>
      </table>
      <div id="paginationControls"></div>
    </div>
    <script>
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
    </script>
    <script>
      let priorityChart, statusCodeChart, loginChart, portChart, techChart;
      let certExpiryChart, tlsUsageChart, headersChart, emailSecChart, cdnChart, serviceChart;
      let allTableRows = [];
      let currentPage = 1;
      let rowsPerPage = 20;
      const toggleButton = document.getElementById("themeToggle");
      toggleButton.addEventListener("click", () => {
        document.body.classList.toggle("dark");
        updateChartTheme();
      });
      function updateChartTheme() {
        const newColor = getComputedStyle(document.body).getPropertyValue('--text-color').trim();
        Chart.defaults.color = newColor;
        const charts = [priorityChart, statusCodeChart, loginChart, portChart, techChart,
                        certExpiryChart, tlsUsageChart, headersChart, emailSecChart, cdnChart, serviceChart];
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
      function computePriority(httpRecord, dnsRecord) {
        let score = 0;
        if (httpRecord.status_code === 200) score += 5;
        else if ([301,302].includes(httpRecord.status_code)) score += 3;
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
          default: return "inherit";
        }
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
      function buildCharts({ statusCount, priorityCount, portCount, techCount }) {
        const scCanvas = document.getElementById("statusCodeChart");
        const prCanvas = document.getElementById("priorityChart");
        const portCanvas = document.getElementById("portChart");
        const techCanvas = document.getElementById("techChart");
        if (prCanvas) {
          priorityChart = new Chart(prCanvas, {
            type: "bar",
            data: {
              labels: ["P0", "P1", "P2", "P3", "P4"],
              datasets: [{
                label: "Priority Buckets",
                data: ["P0", "P1", "P2", "P3", "P4"].map(l => priorityCount[l] || 0),
                backgroundColor: ["#e74c3c", "#e67e22", "#2ecc71", "#3498db", "#85c1e9"]
              }]
            },
            options: {
              responsive: true,
              plugins: { legend: { display: false }, title: { display: true, text: "Asset Attractiveness by Hackers" } },
              scales: { y: { beginAtZero: true } }
            }
          });
        }
        if (scCanvas) {
          statusCodeChart = new Chart(scCanvas, {
            type: "bar",
            data: {
              labels: Object.keys(statusCount).sort((a, b) => +a - +b),
              datasets: [{
                label: "HTTP Status Codes",
                data: Object.keys(statusCount).sort((a, b) => +a - +b).map(l => statusCount[l]),
                backgroundColor: ["#3498db","#1abc9c","#9b59b6","#f1c40f","#e74c3c","#34495e","#95a5a6"]
              }]
            },
            options: {
              responsive: true,
              plugins: { legend: { display: false }, title: { display: true, text: "HTTP Status Codes" } },
              scales: { y: { beginAtZero: true } }
            }
          });
        }
        if (portCanvas) {
          portChart = new Chart(portCanvas, {
            type: "bar",
            data: {
              labels: Object.keys(portCount).sort((a, b) => +a - +b),
              datasets: [{
                label: "Open Ports",
                data: Object.keys(portCount).sort((a, b) => +a - +b).map(p => portCount[p]),
                backgroundColor: "#f39c12"
              }]
            },
            options: {
              responsive: true,
              plugins: { legend: { display: false }, title: { display: true, text: "Port Usage" } },
              scales: { y: { beginAtZero: true } }
            }
          });
        }
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
              plugins: { legend: { display: false }, title: { display: true, text: "Top 10 Technologies" } },
              scales: { x: { beginAtZero: true } }
            }
          });
        }
      }
      function buildLoginPieChart(endpointsCount, loginFoundCount) {
        const canvas = document.getElementById("loginPieChart");
        if (canvas) {
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
              plugins: { title: { display: true, text: "Login Interfaces Identified" }, legend: { display: false } }
            }
          });
        }
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
            datasets: [{ label: "Certs Expiring", data: [exp7, exp14, exp30], backgroundColor: ["#e74c3c", "#e67e22", "#3498db"] }]
          },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "Certificate Expiry" }, legend: { display: false } },
            scales: { y: { beginAtZero: true } }
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
          data: { labels, datasets: [{ label: "TLS Version Usage", data, backgroundColor: "#2ecc71" }] },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "SSL/TLS Usage" }, legend: { display: false } },
            scales: { y: { beginAtZero: true } }
          }
        });
      }
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
        headersChart = new Chart(ctx, {
          type: "bar",
          data: {
            labels: ["HSTS", "X-Frame Options", "CSP"],
            datasets: [
              { label: "Present", data: [hstsSet, xfoSet, cspSet], backgroundColor: "#2ecc71" },
              { label: "Missing", data: [hstsMissing, xfoMissing, cspMissing], backgroundColor: "#e74c3c" }
            ]
          },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "Security Headers (Status 200)" }, tooltip: { mode: "index", intersect: false } },
            scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }
          }
        });
      }
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
            plugins: { title: { display: true, text: "Email Security Records" }, tooltip: { mode: "index", intersect: false } },
            scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }
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
            datasets: [{ label: "CDN Usage Distribution", data, backgroundColor: "#3498db" }]
          },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "CDN Usage" }, legend: { display: false } },
            scales: { y: { beginAtZero: true } }
          }
        });
      }
      // NEW: Build Service Chart (Open Ports by Service)
      function buildServiceChart(naabuData) {
        const naabuMap = {};
        const serviceCount = {};
        naabuData.forEach(n => {
          const domain = n.host;
          const port = n.port;
          let service = "Unknown";
          const portServiceDB = {
            "7": "Echo", "9": "Discard", "13": "Daytime", "21": "FTP", "22": "SSH",
            "23": "Telnet", "25": "SMTP", "26": "SMTP", "37": "Time", "53": "DNS",
            "79": "Finger", "80": "HTTP", "81": "HTTP", "88": "Kerberos", "106": "POP3",
            "110": "POP3", "111": "RPC", "113": "Ident", "119": "NNTP", "135": "RPC",
            "139": "SMB", "143": "IMAP", "144": "IMAP", "179": "BGP", "199": "SMUX",
            "389": "LDAP", "427": "SLP", "443": "HTTPS", "444": "N/A", "445": "SMB",
            "465": "SMTPS", "513": "rlogin", "514": "rsh", "515": "Printer",
            "543": "Klogin", "544": "Kshell", "548": "AFP", "554": "RTSP", "587": "SMTP Submission",
            "631": "IPP", "646": "LDP", "873": "rsync", "990": "FTPS", "993": "IMAPS",
            "995": "POP3S", "1433": "MSSQL", "1720": "H.323", "1723": "PPTP", "1755": "Windows Media",
            "1900": "SSDP", "2000": "CISCO SCCP", "2001": "CISCO SCCP", "2049": "NFS",
            "2121": "FTP-Alt", "2717": "MS-SQL", "3000": "HTTP-Alt", "3128": "Squid",
            "3306": "MySQL", "3389": "RDP", "3986": "N/A", "4899": "N/A", "5000": "UPnP",
            "5009": "N/A", "5051": "NNTP-Posting", "5060": "SIP", "5101": "N/A", "5190": "ICQ",
            "5357": "WSD", "5432": "PostgreSQL", "5631": "pcANYWHERE", "5666": "NSClient++",
            "5800": "VNC", "5900": "VNC", "6000": "X11", "6001": "X11", "6646": "IRC",
            "7070": "RealAudio", "8000": "HTTP-Alt", "8008": "HTTP-Alt", "8009": "AJP13",
            "8080": "HTTP-Alt", "8081": "HTTP-Alt", "8443": "HTTPS-Alt", "8888": "HTTP-Alt",
            "9100": "Printer", "9999": "N/A", "10000": "N/A", "32768": "N/A",
            "49152": "N/A", "49153": "N/A", "49154": "N/A", "49155": "N/A", "49156": "N/A", "49157": "N/A"
          };
          if (portServiceDB[port]) { service = portServiceDB[port]; }
          if (!naabuMap[domain]) naabuMap[domain] = [];
          naabuMap[domain].push({ port, service });
          serviceCount[service] = (serviceCount[service] || 0) + 1;
        });
        window.naabuMap = naabuMap;
        const ctx = document.getElementById("serviceChart").getContext("2d");
        const labels = Object.keys(serviceCount).sort((a, b) => serviceCount[b] - serviceCount[a]);
        const data = labels.map(l => serviceCount[l]);
        serviceChart = new Chart(ctx, {
          type: "bar",
          data: {
            labels,
            datasets: [{ label: "Open Ports by Service", data, backgroundColor: "#9b59b6" }]
          },
          options: {
            responsive: true,
            plugins: { legend: { display: false }, title: { display: true, text: "Open Services" } },
            scales: { y: { beginAtZero: true } }
          }
        });
      }
      function buildTableRows(combinedData, secMap, loginMap) {
        allTableRows = [];
        Object.keys(combinedData).forEach(domain => {
          const { dns, http } = combinedData[domain];
          const dnsResolvers = dns && dns.resolver ? dns.resolver : [];
          const dnsA = dns && dns.a ? dns.a : [];
          const dnsStatus = dns ? dns.status_code : "N/A";
          const sec = secMap[domain] || {};
          const spf = sec["SPF Record"] || "N/A";
          const dkim = sec["DKIM Record"] || "N/A";
          const dmarc = sec["DMARC Record"] || "N/A";
          const dnssec = sec["DNSSEC Status"] || "N/A";
          const sslVersion = sec["SSL/TLS Version"] || "N/A";
          const certExpiry = sec["Cert Expiry Date"] || "N/A";
          const sslIssuer = sec["SSL/TLS Issuer"] || "N/A";
          const stsFlag = (sec["Strict-Transport-Security"] || "").trim() !== "" ? "True" : "False";
          const xfoFlag = (sec["X-Frame-Options"] || "").trim() !== "" ? "True" : "False";
          const cspFlag = (sec["Content-Security-Policy"] || "").trim() !== "" ? "True" : "False";
          const xssFlag = (sec["X-XSS-Protection"] || "").trim() !== "" ? "True" : "False";
          const rpFlag = (sec["Referrer-Policy"] || "").trim() !== "" ? "True" : "False";
          const ppFlag = (sec["Permissions-Policy"] || "").trim() !== "" ? "True" : "False";
          let openPortsHTML = "";
          if (window.naabuMap && window.naabuMap[domain]) {
            openPortsHTML = window.naabuMap[domain].map(p => `${p.port} (${p.service})`).join("<br>");
          }
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
                <td>${openPortsHTML}</td>
              `;
              allTableRows.push(row);
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
              <td>N/A</td>
            `;
            allTableRows.push(row);
          }
        });
      }
      function getFilteredRows() {
        const query = document.getElementById("searchBox").value.toLowerCase();
        const filters = {
          priority: document.getElementById("priority-filter").value.toLowerCase(),
          domain: document.getElementById("domain-filter").value.toLowerCase(),
          resolvers: document.getElementById("resolvers-filter").value.toLowerCase(),
          arecords: document.getElementById("arecords-filter").value.toLowerCase(),
          dnsstatus: document.getElementById("dnsstatus-filter").value.toLowerCase(),
          cdnname: document.getElementById("cdnname-filter").value.toLowerCase(),
          cdntype: document.getElementById("cdntype-filter").value.toLowerCase(),
          port: document.getElementById("port-filter").value.toLowerCase(),
          url: document.getElementById("url-filter").value.toLowerCase(),
          redirect: document.getElementById("redirect-filter").value.toLowerCase(),
          title: document.getElementById("title-filter").value.toLowerCase(),
          webserver: document.getElementById("webserver-filter").value.toLowerCase(),
          login: document.getElementById("login-filter").value.toLowerCase(),
          tech: document.getElementById("tech-filter").value.toLowerCase(),
          statuscode: document.getElementById("statuscode-filter").value.toLowerCase(),
          contentlength: document.getElementById("contentlength-filter").value.toLowerCase(),
          cdn: document.getElementById("cdn-filter").value.toLowerCase(),
          spf: document.getElementById("spf-filter").value.toLowerCase(),
          dkim: document.getElementById("dkim-filter").value.toLowerCase(),
          dmarc: document.getElementById("dmarc-filter").value.toLowerCase(),
          dnssec: document.getElementById("dnssec-filter").value.toLowerCase(),
          sslversion: document.getElementById("sslversion-filter").value.toLowerCase(),
          certexpiry: document.getElementById("certexpiry-filter").value.toLowerCase(),
          sslissuer: document.getElementById("sslissuer-filter").value.toLowerCase(),
          sts: document.getElementById("sts-filter").value.toLowerCase(),
          xfo: document.getElementById("xfo-filter").value.toLowerCase(),
          csp: document.getElementById("csp-filter").value.toLowerCase(),
          xss: document.getElementById("xss-filter").value.toLowerCase(),
          rp: document.getElementById("rp-filter").value.toLowerCase(),
          pp: document.getElementById("pp-filter").value.toLowerCase(),
          portsservices: document.getElementById("ports-services-filter").value.toLowerCase()
        };
        return allTableRows.filter((row) => {
          const cells = row.getElementsByTagName("td");
          if (filters.priority   && cells[0].innerText.toLowerCase() !== filters.priority) return false;
          if (filters.domain     && cells[1].innerText.toLowerCase() !== filters.domain) return false;
          if (filters.resolvers  && cells[2].innerText.toLowerCase() !== filters.resolvers) return false;
          if (filters.arecords   && cells[3].innerText.toLowerCase() !== filters.arecords) return false;
          if (filters.dnsstatus  && cells[4].innerText.toLowerCase() !== filters.dnsstatus) return false;
          if (filters.cdnname    && cells[5].innerText.toLowerCase() !== filters.cdnname) return false;
          if (filters.cdntype    && cells[6].innerText.toLowerCase() !== filters.cdntype) return false;
          if (filters.port       && cells[7].innerText.toLowerCase() !== filters.port) return false;
          if (filters.url        && cells[8].innerText.toLowerCase() !== filters.url) return false;
          if (filters.redirect   && cells[9].innerText.toLowerCase() !== filters.redirect) return false;
          if (filters.title      && cells[10].innerText.toLowerCase() !== filters.title) return false;
          if (filters.webserver  && cells[11].innerText.toLowerCase() !== filters.webserver) return false;
          if (filters.login      && cells[12].innerText.toLowerCase() !== filters.login) return false;
          if (filters.tech       && cells[13].innerText.toLowerCase() !== filters.tech) return false;
          if (filters.statuscode && cells[14].innerText.toLowerCase() !== filters.statuscode) return false;
          if (filters.contentlength && cells[15].innerText.toLowerCase() !== filters.contentlength) return false;
          if (filters.cdn        && cells[16].innerText.toLowerCase() !== filters.cdn) return false;
          if (filters.spf        && cells[17].innerText.toLowerCase() !== filters.spf) return false;
          if (filters.dkim       && cells[18].innerText.toLowerCase() !== filters.dkim) return false;
          if (filters.dmarc      && cells[19].innerText.toLowerCase() !== filters.dmarc) return false;
          if (filters.dnssec     && cells[20].innerText.toLowerCase() !== filters.dnssec) return false;
          if (filters.sslversion && cells[21].innerText.toLowerCase() !== filters.sslversion) return false;
          if (filters.certexpiry && cells[22].innerText.toLowerCase() !== filters.certexpiry) return false;
          if (filters.sslissuer  && cells[23].innerText.toLowerCase() !== filters.sslissuer) return false;
          if (filters.sts        && cells[24].innerText.toLowerCase() !== filters.sts) return false;
          if (filters.xfo        && cells[25].innerText.toLowerCase() !== filters.xfo) return false;
          if (filters.csp        && cells[26].innerText.toLowerCase() !== filters.csp) return false;
          if (filters.xss        && cells[27].innerText.toLowerCase() !== filters.xss) return false;
          if (filters.rp         && cells[28].innerText.toLowerCase() !== filters.rp) return false;
          if (filters.pp         && cells[29].innerText.toLowerCase() !== filters.pp) return false;
          if (filters.portsservices && !cells[30].innerText.toLowerCase().includes(filters.portsservices)) return false;
          if (query && !row.innerText.toLowerCase().includes(query)) return false;
          return true;
        });
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
        rowsToShow.forEach((row) => tBody.appendChild(row));
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
        prevBtn.addEventListener("click", () => { if (currentPage > 1) { currentPage--; renderTable(getFilteredRows()); } });
        paginationDiv.appendChild(prevBtn);
        const nextBtn = document.createElement("button");
        nextBtn.textContent = "Next";
        nextBtn.disabled = currentPage === totalPages;
        nextBtn.addEventListener("click", () => { if (currentPage < totalPages) { currentPage++; renderTable(getFilteredRows()); } });
        paginationDiv.appendChild(nextBtn);
      }
      function onFilterChange() { currentPage = 1; renderTable(getFilteredRows()); }
      function updateRowsPerPage() {
        const select = document.getElementById("rowsPerPageSelect");
        const value = select.value;
        if (value === "all") { rowsPerPage = Infinity; } else { rowsPerPage = parseInt(value, 10); }
        currentPage = 1; renderTable(getFilteredRows());
      }
      function populateColumnFilters() {
        const uniqueCols = Array.from({ length: 31 }, () => new Set());
        allTableRows.forEach((row) => {
          const cells = row.getElementsByTagName("td");
          for (let col = 0; col < 31; col++) { uniqueCols[col].add(cells[col].innerText.trim()); }
        });
        function fillSelectOptions(selectId, values) {
          const select = document.getElementById(selectId);
          const existing = select.querySelectorAll("option:not([value=''])");
          existing.forEach((opt) => opt.remove());
          values.forEach((val) => {
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
        fillSelectOptions("ports-services-filter", [...uniqueCols[30]].sort());
      }
      function attachFilterEvents() {
        [
          "priority-filter", "domain-filter", "resolvers-filter", "arecords-filter", "dnsstatus-filter",
          "cdnname-filter", "cdntype-filter", "port-filter", "url-filter", "redirect-filter", "title-filter",
          "webserver-filter", "login-filter", "tech-filter", "statuscode-filter", "contentlength-filter",
          "cdn-filter", "spf-filter", "dkim-filter", "dmarc-filter", "dnssec-filter", "sslversion-filter",
          "certexpiry-filter", "sslissuer-filter", "sts-filter", "xfo-filter", "csp-filter", "xss-filter",
          "rp-filter", "pp-filter", "ports-services-filter"
        ].forEach((id) => {
          const el = document.getElementById(id);
          if (el) { el.addEventListener("change", onFilterChange); }
        });
      }
      document.getElementById("searchBox").addEventListener("input", onFilterChange);
      document.getElementById("rowsPerPageSelect").addEventListener("change", updateRowsPerPage);
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
          const loginMap = {};
          loginData.forEach(item => { loginMap[item.url] = item.login_detection.login_found; });
          const secMap = {};
          secData.forEach(item => { secMap[item.Domain] = item; });
          const endpointsCount = httpxData.length;
          const loginFoundCount = loginData.filter(item => item.login_detection.login_found === "Yes").length;
          const liveSubs = dnsxData.filter(d => d.status_code === "NOERROR").length;
          const domainSet = new Set();
          dnsxData.forEach(d => { if (d.host) domainSet.add(d.host); });
          const totalSubdomains = domainSet.size;
          buildLoginPieChart(endpointsCount, loginFoundCount);
          buildScoreboard({ totalSubdomains, liveSubs, totalHttpx: endpointsCount, loginFoundCount });
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
          buildServiceChart(naabuData);
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
          buildTableRows(combinedData, secMap, loginMap);
          populateColumnFilters();
          attachFilterEvents();
          renderTable(getFilteredRows());
          const validDomains = new Set();
          httpxData.forEach(h => { if (h.url && h.url !== "N/A") { validDomains.add((h.input || "").split(":")[0]); } });
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
          buildHeadersChart(httpxData, secMap);
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
  securitycompliance
  build_html_report
  show_summary
}

main
