#!/usr/bin/env bash
# Exit immediately if any command fails, unset variables are errors, and fail on pipe errors.
set -euo pipefail

##############################################
# Global counters for summary metrics
##############################################
CHAOS_COUNT=0
SUBFINDER_COUNT=0
ASSETFINDER_COUNT=0
CRT_COUNT=0
DNSX_LIVE_COUNT=0
HTTPX_LIVE_COUNT=0
LOGIN_FOUND_COUNT=0

##############################################
# Validate Input Arguments
##############################################
# The script expects at least one argument: a file containing primary domains.
if [ "$#" -lt 1 ]; then
  echo -e "\033[91m[-] Usage: $0 <primary_domains_file>\033[0m"
  exit 1
fi

# Assign the first argument to a variable and check if the file exists.
PRIMARY_DOMAINS_FILE="$1"
if [ ! -f "$PRIMARY_DOMAINS_FILE" ]; then
  echo -e "\033[91m[-] File '$PRIMARY_DOMAINS_FILE' not found!\033[0m"
  exit 1
fi

##############################################
# Create a unique output directory for this run
##############################################
# The run directory is timestamped for uniqueness.
RUN_DIR="output/run-$(date +%Y%m%d%H%M%S)"
mkdir -p "$RUN_DIR/raw_output/raw_http_responses"
mkdir -p "$RUN_DIR/logs"

##############################################
# Global file paths for temporary subdomain lists
##############################################
ALL_TEMP="$RUN_DIR/all_temp_subdomains.txt"
MASTER_SUBS="$RUN_DIR/master_subdomains.txt"
> "$ALL_TEMP"      # Empty (or create) the file
> "$MASTER_SUBS"   # Empty (or create) the file

##############################################
# Option toggles for different reconnaissance tools
##############################################
# Set each tool to "true" or "false" as needed
USE_CHAOS="false"
USE_SUBFINDER="true"
USE_ASSETFINDER="true"
USE_DNSX="true"
USE_NAABU="true"
USE_HTTPX="true"

##############################################
# Logging Functions (with timestamps)
##############################################
# info: print informational messages
info()    { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [+] $*"; }
# warning: print warning messages
warning() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [!] $*"; }
# error: print error messages
error()   { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [-] $*"; }

##############################################
# Function: merge_and_count
# Purpose: Merge subdomain results from a given file into a global temporary file
# and update the corresponding counter based on the source.
##############################################
merge_and_count() {
  local file="$1"         # Input file containing subdomains from one tool
  local source_name="$2"  # The tool name (e.g., "Chaos", "Subfinder")
  local count=0
  if [[ -s "$file" ]]; then
    count=$(wc -l < "$file")
    cat "$file" >> "$ALL_TEMP"
  fi
  # Update counters based on the tool used
  case "$source_name" in
    "Chaos")       CHAOS_COUNT=$((CHAOS_COUNT + count)) ;;
    "Subfinder")   SUBFINDER_COUNT=$((SUBFINDER_COUNT + count)) ;;
    "Assetfinder") ASSETFINDER_COUNT=$((ASSETFINDER_COUNT + count)) ;;
    "Certificate") CRT_COUNT=$((CRT_COUNT + count)) ;;
  esac
}

##############################################
# Function: run_chaos
# Purpose: Query the Chaos database (if enabled) and merge its subdomain results.
##############################################
run_chaos() {
  if [[ "$USE_CHAOS" == "true" ]]; then
    info "Running Chaos..."
    local chaos_index="output/$cdir/logs/chaos_index.json"
    # Download the Chaos index file
    curl -s https://chaos-data.projectdiscovery.io/index.json -o "$chaos_index"
    # Find the URL for the current directory (cdir variable should be set externally)
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
# Function: run_subfinder
# Purpose: Run the Subfinder tool on the primary domains and merge the subdomains.
##############################################
run_subfinder() {
  if [[ "$USE_SUBFINDER" == "true" ]]; then
    info "[1/13] Running Subfinder..."
    subfinder -dL "$PRIMARY_DOMAINS_FILE" -all -silent \
      -o "$RUN_DIR/subfinder.txt" \
      >/dev/null 2>&1 || true
    merge_and_count "$RUN_DIR/subfinder.txt" "Subfinder"
  fi
}

##############################################
# Function: run_assetfinder
# Purpose: Run Assetfinder for each primary domain and merge the results.
##############################################
run_assetfinder() {
  if [[ "$USE_ASSETFINDER" == "true" ]]; then
    info "[2/13] Running Assetfinder..."
    while read -r domain; do
      assetfinder --subs-only "$domain" >> "$RUN_DIR/assetfinder.txt" 2>/dev/null || true
    done < "$PRIMARY_DOMAINS_FILE"
    merge_and_count "$RUN_DIR/assetfinder.txt" "Assetfinder"
  fi
}

##############################################
# Function: run_crtsh
# Purpose: Query crt.sh for certificate data and extract subdomains.
##############################################
run_crtsh() {
  info "[3/13] Running crt.sh..."
  local crt_file="$RUN_DIR/whois.txt"
  > "$crt_file"
  while read -r domain; do
    {
      # Temporarily disable exit on error for this block
      set +e
      local registrant
      # Attempt to extract the registrant organization from whois data
      registrant=$(whois "$domain" 2>/dev/null \
        | grep -i "Registrant Organization" \
        | cut -d ":" -f2 \
        | xargs \
        | sed 's/,/%2C/g; s/ /+/g' \
        | egrep -v '(Whois|whois|WHOIS|domains|DOMAINS|Domains|domain|DOMAIN|Domain|proxy|Proxy|PROXY|PRIVACY|privacy|Privacy|REDACTED|redacted|Redacted|DNStination|WhoisGuard|Protected|protected|PROTECTED|Registration Private|REGISTRATION PRIVATE|registration private)' \
        || true)
      if [[ -n "$registrant" ]]; then
        # Query crt.sh using the registrant information
        curl -s "https://crt.sh/?q=$registrant" \
          | grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' \
          | sed -e 's/^<TD>//;s/<\/TD>$//' \
          >> "$crt_file"
      fi
      # Also query crt.sh using the domain and JSON output
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
# Function: run_dnsx
# Purpose: Run dnsx tool to check which subdomains are live.
##############################################
run_dnsx() {
  if [[ "$USE_DNSX" == "true" ]]; then
    info "[5/13] Running dnsx..."
    dnsx -silent \
         -l "$MASTER_SUBS" \
         -o "$RUN_DIR/dnsx.json" \
         -j \
         >/dev/null 2>&1 || true
    # Count live domains based on the "NOERROR" status code from dnsx output
    DNSX_LIVE_COUNT=$(jq -r 'select(.status_code=="NOERROR") | .host' "$RUN_DIR/dnsx.json" | sort -u | wc -l)
  fi
}

##############################################
# Function: run_naabu
# Purpose: Run naabu port scanner against discovered subdomains.
##############################################
run_naabu() {
  if [[ "$USE_NAABU" == "true" ]]; then
    info "[6/13] Running naabu..."
    naabu -silent \
          -l "$MASTER_SUBS" \
          -p "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157" \
          -o "$RUN_DIR/naabu.json" \
          -j \
          >/dev/null 2>&1 || true
    # Process naabu JSON to extract unique host:port pairs
    local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
    jq -r '"\(.host):\(.port)"' "$RUN_DIR/naabu.json" | sort -u > "$final_urls_ports"
  fi
}

##############################################
# Function: run_httpx
# Purpose: Run httpx to probe live web endpoints using the ports identified.
##############################################
run_httpx() {
  if [[ "$USE_HTTPX" == "true" ]]; then
    info "[7/13] Running httpx..."
    local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
    httpx -silent \
          -l "$final_urls_ports" \
          -j \
          -o "$RUN_DIR/httpx.json" \
          >/dev/null 2>&1 || true
    # Count the number of live websites detected by httpx.
    HTTPX_LIVE_COUNT=$(wc -l < "$RUN_DIR/httpx.json")
  fi
}

##############################################
# Function: run_login_detection
# Purpose: Detect login interfaces on discovered web endpoints.
# Detailed Explanation:
#   1. Reads each URL from the httpx output.
#   2. Uses curl to fetch headers and body.
#   3. Applies a series of regex searches (via grep) to detect login elements.
#   4. Returns a JSON object indicating if login was found and lists the reasons.
##############################################
run_login_detection() {
  info "[8/13] Detecting Login panels..."
  local input_file="$RUN_DIR/httpx.json"
  local output_file="$RUN_DIR/login.json"

  # Exit if input file or jq is not available.
  if [ ! -f "$input_file" ]; then
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    return
  fi

  local urls
  urls=$(jq -r '.url' "$input_file")

  # Start JSON array output for login detection
  echo "[" > "$output_file"
  local first_entry=true

  # Helper function: detect_login
  # It examines header and body files for indicators of a login interface.
  detect_login() {
      local headers_file="$1"
      local body_file="$2"
      local final_url="$3"
      local -a reasons=()

      # Each grep command below checks for patterns that might indicate a login form.
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

      # Build a JSON array of the reasons using jq.
      local json_details
      json_details=$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s .)

      # Return a JSON object with the login detection results.
      jq -n --arg login_found "$login_found" --argjson details "$json_details" \
            '{login_found: $login_found, login_details: $details}'
  }

  # Process each URL from the httpx data.
  for url in $urls; do
      local headers_file="final_headers.tmp"
      local body_file="final_body.tmp"
      rm -f "$headers_file" "$body_file"

      local curl_err="curl_err.tmp"
      rm -f "$curl_err"

      # First, fetch headers and body from the URL using curl.
      set +e
      curl -s -S -L \
           -D "$headers_file" \
           -o "$body_file" \
           "$url" \
           2> "$curl_err"
      local curl_exit=$?
      set -e

      # If curl returns error code 35 (SSL connect error), skip this URL.
      if [ $curl_exit -eq 35 ]; then
          info "Skipping $url due to SSL error."
          rm -f "$headers_file" "$body_file" "$curl_err"
          continue
      fi

      # If any other error occurred, output JSON with login_found "No" and continue.
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

      # Get the final URL after redirections.
      set +e
      local final_url
      final_url=$(curl -s -o /dev/null -w "%{url_effective}" -L "$url")
      local final_curl_exit=$?
      set -e

      # If fetching the final URL fails, fallback to the original URL.
      if [ $final_curl_exit -ne 0 ] || [ -z "$final_url" ]; then
          final_url="$url"
      fi

      # Run the login detection function on the fetched data.
      local detection_json
      detection_json=$(detect_login "$headers_file" "$body_file" "$final_url")

      # If login is detected, increment the LOGIN_FOUND_COUNT.
      if echo "$detection_json" | grep -q '"login_found": "Yes"'; then
          LOGIN_FOUND_COUNT=$((LOGIN_FOUND_COUNT + 1))
      fi

      # Append the detection result for this URL to the output JSON file.
      if [ "$first_entry" = true ]; then
          first_entry=false
      else
          echo "," >> "$output_file"
      fi

      echo "  { \"url\": \"${url}\", \"final_url\": \"${final_url}\", \"login_detection\": $detection_json }" >> "$output_file"

      rm -f "$headers_file" "$body_file"
  done

  # Close the JSON array.
  echo "]" >> "$output_file"

  # Clean up any temporary files.
  rm -f *.tmp
}

##############################################
# Function: run_security_compliance
# Purpose: Check various security settings (DNS, SSL, headers) for each domain.
# Detailed Explanation:
#   - For each domain in MASTER_SUBS, the function retrieves DNS TXT records for SPF,
#     DKIM, and DMARC, and checks for DNSSEC.
#   - It then matches live URL records from httpx.json to extract certificate and header information.
#   - The final output is a JSON record per domain with security compliance details.
##############################################
run_security_compliance() {
  info "[9/13] Analyzing security hygiene using..."
  local output_file="$RUN_DIR/securitycompliance.json"

  # Ensure the MASTER_SUBS and httpx.json files exist.
  if [ ! -f "$MASTER_SUBS" ]; then
    echo "Error: MASTER_SUBS file not found!" >&2
    return 1
  fi
  if [ ! -f "$RUN_DIR/httpx.json" ]; then
    echo "Error: httpx.json not found!" >&2
    return 1
  fi

  # Create a temporary directory to store intermediate JSON records.
  local temp_dir
  temp_dir=$(mktemp -d)

  # Process each domain from MASTER_SUBS.
  while IFS= read -r domain || [ -n "$domain" ]; do
    domain=$(echo "$domain" | tr -d '\r' | xargs)
    [ -z "$domain" ] && continue

    # --- Domain-level DNS Checks ---
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

    # --- Process live URL records from httpx.json ---
    # Filter the httpx.json file for records that start with the domain.
    local matches
    matches=$(jq -c --arg domain "$domain" 'select(.input | startswith($domain))' "$RUN_DIR/httpx.json")

    if [ -n "$matches" ]; then
      # For each matching live URL record, extract SSL and header details.
      echo "$matches" | while IFS= read -r record; do
        local url ssl_version ssl_issuer cert_expiry sts xfo csp xss rp pp acao
        url=$(echo "$record" | jq -r '.url')
        # Extract host and port from the URL
        if [[ "$url" =~ ^https://([^:]+):([0-9]+) ]]; then
          local host port
          host="${BASH_REMATCH[1]}"
          port="${BASH_REMATCH[2]}"
        else
          host=""
          port=""
        fi

        # If the URL is HTTPS, perform SSL checks.
        if [ -n "$host" ]; then
          local ssl_output CERT
          ssl_output=$(echo | timeout 7 openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null || true)
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

        # Fetch HTTP headers to check security settings.
        local HEADERS
        HEADERS=$(curl -s -D - "$url" -o /dev/null || true)
        sts=$(echo "$HEADERS" | grep -i "Strict-Transport-Security:" | cut -d':' -f2- | xargs || true)
        xfo=$(echo "$HEADERS" | grep -i "X-Frame-Options:" | cut -d':' -f2- | xargs || true)
        csp=$(echo "$HEADERS" | grep -i "Content-Security-Policy:" | cut -d':' -f2- | xargs || true)
        xss=$(echo "$HEADERS" | grep -i "X-XSS-Protection:" | cut -d':' -f2- | xargs || true)
        rp=$(echo "$HEADERS" | grep -i "Referrer-Policy:" | cut -d':' -f2- | xargs || true)
        pp=$(echo "$HEADERS" | grep -i "Permissions-Policy:" | cut -d':' -f2- | xargs || true)
        acao=$(echo "$HEADERS" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs || true)

        # Build and output a JSON record with the security compliance details.
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
      # If no live URL is found, output a record with default values.
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

  # Combine all JSON records into one JSON array and output to the security compliance file.
  if [ ! -s "$temp_dir/records.json" ]; then
    echo "[]" > "$output_file"
  else
    jq -s '.' "$temp_dir/records.json" > "$output_file"
  fi
  rm -r "$temp_dir"
}

##############################################
# Function: combine_json
# Purpose: Merge a line-based JSON file into a single JSON array.
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
# Function: run_api_identification
# Purpose: Identify API endpoints based on simple pattern matching in domain names.
##############################################
run_api_identification() {
  info "[10/13] Identifying API endpoints..."
  local api_file="$RUN_DIR/api_identification.json"
  # Begin JSON array output
  echo "[" > "$api_file"
  local first_entry=true
  while read -r domain; do
    # Check if the domain name contains common API-related strings.
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
# Function: run_colleague_identification
# Purpose: Identify endpoints intended for internal/colleague use based on keywords in domain names.
##############################################
run_colleague_identification() {
  info "[11/13] Identifying colleague-facing endpoints..."
  local colleague_file="$RUN_DIR/colleague_identification.json"
  # Define a list of keywords that indicate internal or employee-intended endpoints.
  local tokens=("dev" "development" "test" "testing" "qa" "uat" "stage" "staging" "demo" "sandbox" "lab" "labs" "experimental" "preprod" "pre-production" "pre-prod" "nonprod" "non-production" "non-prod" "perf" "performance" "loadtest" "soaktest" "integration" "integrationtest" "release" "hotfix" "feature" "rc" "beta" "alpha" "internal" "private" "intranet" "corp" "corporate" "employee" "colleague" "partner" "restricted" "secure" "admin" "backoffice" "back-office" "management" "mgmt" "console" "ops" "operations" "dashboard" "sysadmin" "root" "sudo" "superuser" "jenkins" "teamcity" "bamboo" "circleci" "travis" "gitlab" "bitbucket" "gitea" "jira" "confluence" "artifactory" "nexus" "harbor" "grafana" "kibana" "prometheus" "alertmanager" "nagios" "zabbix" "splunk" "posthog" "sentry" "phabricator" "default" "standard" "placeholder" "dummy" "guest" "temp" "example" "portal" "hr" "hrportal" "helpdesk" "support" "servicedesk" "tools" "tooling" "services" "api-internal" "internalapi" "playground" "workshop" "vpn" "local" "localhost" "onprem" "on-prem" "dmz" "bastion" "jumpbox" "cache" "queue" "log" "logs" "monitor" "metrics" "ldap" "ad" "ntp" "smtp-internal" "ftp-internal")
  echo "[" > "$colleague_file"
  local first_entry=true
  while read -r domain; do
    # Convert domain to lowercase for consistent matching.
    local lc_domain
    lc_domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
    local found="No"
    # Split the domain into tokens using common delimiters.
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
# Function: build_html_report
# Purpose: Combine the various JSON outputs and generate the final HTML report.
# Detailed Explanation:
#   - Combines JSON files from dnsx, naabu, and httpx.
#   - Moves merged JSON files into place.
#   - Writes the complete HTML (including embedded JavaScript and CSS) to the report file.
##############################################
build_html_report() {
  info "[12/13] Building HTML report with analytics..."
  combine_json "$RUN_DIR/dnsx.json"   "$RUN_DIR/dnsx_merged.json"
  combine_json "$RUN_DIR/naabu.json"    "$RUN_DIR/naabu_merged.json"
  combine_json "$RUN_DIR/httpx.json"    "$RUN_DIR/httpx_merged.json"
  mv "$RUN_DIR/dnsx_merged.json"  "$RUN_DIR/dnsx.json"
  mv "$RUN_DIR/naabu_merged.json" "$RUN_DIR/naabu.json"
  mv "$RUN_DIR/httpx_merged.json" "$RUN_DIR/httpx.json"
  local report_html="$RUN_DIR/report.html"
  # Use a heredoc to generate the HTML file with embedded CSS and JavaScript.
  cat << 'EOF' > "$report_html"


    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>External Attack Surface Analysis</title>
        <!-- Chart.js for charts -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
          /* Root CSS variables for theme colors and font sizes */
          :root {
            /* Light theme colors */
            --light-bg-color: #f9f9f9;
            --light-text-color: #333;
            --light-header-bg: #fff;
            --light-header-text: #333;
            --light-table-bg: #fff;
            --light-table-header-bg: #eee;
            --light-table-border: #ddd;
            --light-toggle-bg: #757574;
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

            /* Active theme variables (default to light) */
            --bg-color: var(--light-bg-color);
            --text-color: var(--light-text-color);
            --header-bg: var(--light-header-bg);
            --header-text: var(--light-header-text);
            --table-bg: var(--light-table-bg);
            --table-header-bg: var(--light-table-header-bg);
            --table-border: var(--light-table-border);
            --toggle-bg: var(--light-toggle-bg);
            --toggle-btn: var(--light-toggle-btn);

            /* Font sizing variables */
            --font-size-sm: 12px;
            --font-size-base: 13px;
            --font-size-md: 14px;
            --font-size-lg: 16px;
            --heading-font-size: 22px;
          }

          /* Dark theme override */
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

          /* Basic styles for body and fonts */
          body {
            margin: 0;
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            font-size: var(--font-size-base);
            line-height: 1.4;
          }

          /* HEADER styles */
          .header {
            position: relative;
            background-color: var(--header-bg);
            color: var(--header-text);
            text-align: center; /* centers the heading horizontally */
            padding: 12px 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          }

          .header h1 {
            margin: 0;
          }

          /* Keep the toggle button on the right */
          .toggle-btn {
            position: absolute;
            right: 20px;
            top: 12px; /* adjust as needed to align vertically */
            background-color: var(--toggle-bg);
            border: none;
            color: var(--toggle-btn);
            cursor: pointer;
            border-radius: 4px;
            font-size: var(--font-size-m);
            transition: background-color 0.2s, color 0.2s;
          }
          /* Keep the toggle button on the right */
          .csv-btn {
            position: absolute;
            right: 20px;
            top: 35px; /* adjust as needed to align vertically */
            background-color: var(--toggle-bg);
            border: none;
            color: var(--toggle-btn);
            cursor: pointer;
            border-radius: 4px;
            font-size: var(--font-size-m);
            transition: background-color 0.5s, color 0.2s;
          }

          .toggle-btn:hover {
            opacity: 0.9;
          }

          /* Top controls for table filters and pagination */
          .table-top-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
          }

          /* Container for the entire report */
          .container {
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
          }

          /* Scoreboard styles for summary cards */
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

          .hint{
            color: red;
          }
          /* Grid layout for charts */
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
            height: 100% !important;
          }

          /* Search box styling */
          #searchBox {
            margin: 0;
            padding: 6px 10px;
            width: 250px;
            font-size: var(--font-size-sm);
            border: 1px solid var(--table-border);
            border-radius: 4px;
          }

          /* Table controls styling */
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

          /* Main table styling */
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

          /* Filter dropdown styling in table header */
          #filter-row select {
            width: 100%;
            font-size: var(--font-size-sm);
            padding: 2px 4px;
            border: 1px solid var(--table-border);
            border-radius: 3px;
            background-color: var(--table-bg);
            color: var(--text-color);
          }

          /* Pagination controls styling */
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

          /* Ensuring proper display for the last header column */
          th:nth-child(33) {
            white-space: nowrap;
          }
        </style>
      </head>
      <body>
        <!-- Header section with title and theme toggle button -->
        <div class="header">
          <h1>External Attack Surface Analysis Report</h1>
          <button id="themeToggle" class="toggle-btn">DARK THEME</button>
          <button id="exportCsvButton" class="csv-btn">EXPORT CSV</button>
        </div>
        <div class="container">
          <!-- Scoreboard section for summary metrics -->
          <div class="scoreboard" id="scoreboard"></div>

          <!-- Grid of charts -->
          <div class="charts-grid">
            <div class="chart-container">
              <canvas id="priorityChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="domainCountChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="colleagueEndpointChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="loginBarChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="statusCodeChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="portChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="serviceChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="techChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="tlsUsageChart"></canvas>
            </div>
            <div class="chart-container">
              <canvas id="certExpiryChart"></canvas>
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
              <canvas id="cdnTypeChart"></canvas>
            </div>
          </div>

          <!-- Controls above the table: search box and rows per page selector -->
          <div class="table-top-controls">
            <input type="text" id="searchBox" placeholder="Filter table (e.g. domain, status code, tech)..." />
            <div class="hint">
            <h4>Mouseover to Risk Score to Evaluate Reasons for Scoring</h2>
            </div>
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

          <!-- Main report table with dynamic filters in header -->
          <table id="report-table">
            <thead>
              <tr>
                <th id="riskScoreHeader">
                  Attack Surface Score<span id="riskSortToggle" style="cursor:pointer; user-select:none; margin-left:5px;">▼</span>
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
              <!-- Second header row for filter dropdowns per column -->
              <tr id="filter-row">
                <th><select id="priority-filter"><option value="">All</option></select></th>
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

          <!-- Container for pagination controls -->
          <div id="paginationControls"></div>
        </div>

        <script>
          // Plugin for displaying labels on bars in charts
          const barLabelPlugin = {
            id: 'barLabelPlugin',
            afterDatasetsDraw(chart, args, options) {
              const { ctx } = chart;
              // Filter visible bar datasets
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
          // Register the custom plugin with Chart.js.
          Chart.register(barLabelPlugin);

          // Declare global variables for charts, table rows, pagination, and risk scores.
          let priorityChart, domainCountChart, statusCodeChart, loginChart, portChart, techChart, certExpiryChart, tlsUsageChart, headersChart, emailSecChart, cdnChart, serviceChart, colleagueChart, cdnTypeChart;
          let allTableRows = [];
          let currentPage = 1;
          let rowsPerPage = 20;
          let riskScores = {};
          let minRiskScore = Infinity;
          let maxRiskScore = -Infinity;
          let riskSortOrder = "desc";

          // --- Begin CSV Export Code ---
          // Function to trigger CSV download from a CSV string
          function downloadCSV(csv, filename) {
            var csvFile = new Blob([csv], { type: "text/csv" });
            var downloadLink = document.createElement("a");
            downloadLink.download = filename;
            downloadLink.href = window.URL.createObjectURL(csvFile);
            downloadLink.style.display = "none";
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
          }

          // Function to extract all table data (using the global array) and generate CSV content
          function exportAllTableRowsToCSV(filename) {
            var csv = [];
            // Get the first header row (from the table header)
            var headerRow = document.querySelectorAll("#report-table thead tr")[0];
            var headers = [];
            headerRow.querySelectorAll("th").forEach(function(th) {
              headers.push('"' + th.innerText.trim().replace(/"/g, '""') + '"');
            });
            csv.push(headers.join(","));

            // Use the global allTableRows array (which holds every row) instead of only the visible rows
            allTableRows.forEach(function(row) {
              var cols = row.querySelectorAll("td");
              var rowData = [];
              cols.forEach(function(td) {
                rowData.push('"' + td.innerText.trim().replace(/"/g, '""') + '"');
              });
              csv.push(rowData.join(","));
            });

            // Trigger the download of the CSV file
            downloadCSV(csv.join("\n"), filename);
          }

          // Attach event listener to the Export CSV button
          document.getElementById("exportCsvButton").addEventListener("click", function() {
            exportAllTableRowsToCSV("report.csv");
          });
          // --- End CSV Export Code ---

          // Theme toggle button event to switch between light and dark themes.
          const toggleButton = document.getElementById("themeToggle");
          toggleButton.addEventListener("click", () => {
            document.body.classList.toggle("dark");
            updateChartTheme();
          });

          // Function to update chart colors based on current theme.
          function updateChartTheme() {
            const newColor = getComputedStyle(document.body).getPropertyValue('--text-color').trim();
            Chart.defaults.color = newColor;
            const charts = [
              priorityChart, domainCountChart, statusCodeChart, loginChart,
              portChart, techChart, certExpiryChart, tlsUsageChart,
              headersChart, emailSecChart, cdnChart, serviceChart, colleagueChart, cdnTypeChart
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

          // Utility function to format array values for table cells.
          function formatCell(arr) {
            return (arr && arr.length) ? arr.join("<br>") : "N/A";
          }

          // Function: computePriority
          // Purpose: Calculate a risk score for a given asset based on various parameters.
          // Also returns an array of debug reasons explaining each part of the score.
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
            const reasons = [];

            // Check domain purpose: bonus if employee-oriented.
            if (purpose && purpose.toLowerCase().includes("employee")) {
              score += 1;
              reasons.push("+1 (Potential employee-intended domain found)");
            }

            // Bonus for having a live URL.
            if (url && url !== "N/A") {
              score += 1;
              reasons.push("+1 (Domain has live application)");
            }

            // Bonus if a login interface is detected.
            if (loginFound === "Yes") {
              score += 1;
              reasons.push("+1 (Login interface found on application)");
            }

            // Bonus for a 200 HTTP status code.
            if (statusCode === 200) {
              score += 1;
              reasons.push("+1 (Application has 200 status code)");
            }

            // Evaluate SSL/TLS version; penalize older versions.
            if (sslVersion) {
              const cleanVersion = sslVersion.replace(/\s+/g, '');
              if (/^TLSv(1\.2|1\.3)$/i.test(cleanVersion)) {
                reasons.push("+0 (Version of TLS is latest (1.2 or 1.3))");
              } else if (/^TLSv(1\.0|1\.1)$/i.test(cleanVersion)) {
                score += 1;
                reasons.push("+1 (TLSv1.0 or TLSv1.1)");
              } else if (/^SSLv(1\.0|2\.0|3\.0)$/i.test(cleanVersion)) {
                score += 5;
                reasons.push("+5 (SSLv1/2/3)");
              }
            } else {
              score += 1;
              reasons.push("+1 (no sslVersion reported)");
            }

            // Check certificate expiry; score increases if expiry is soon.
            if (certExpiry && certExpiry !== "N/A") {
              const expiryDate = new Date(certExpiry);
              const now = new Date();
              const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
              if (!isNaN(diffDays)) {
                if (diffDays <= 7) {
                  score += 3;
                  reasons.push("+3 (cert expires in ≤7 days)");
                } else if (diffDays <= 14) {
                  score += 2;
                  reasons.push("+2 (cert expires in ≤14 days)");
                } else if (diffDays <= 30) {
                  score += 1;
                  reasons.push("+1 (cert expires in ≤30 days)");
                }
              }
            }

            // Evaluate presence of critical security headers.
            function missingHeader(val) {
              return !val || val.trim() === "" || val.trim().toLowerCase() === "false";
            }
            if (missingHeader(sts)) {
              score += 1;
              reasons.push("+1 (missing security header - HSTS)");
            }
            if (missingHeader(xfo)) {
              score += 1;
              reasons.push("+1 (missing security header - X-Frame-Options)");
            }
            if (missingHeader(csp)) {
              score += 1;
              reasons.push("+1 (missing security header - CSP)");
            }
            if (missingHeader(xss)) {
              score += 1;
              reasons.push("+1 (missing security header - X-XSS-Protection)");
            }
            if (missingHeader(rp)) {
              score += 1;
              reasons.push("+1 (missing security header - Referrer-Policy)");
            }
            if (missingHeader(pp)) {
              score += 1;
              reasons.push("+1 (missing security header - Permissions-Policy)");
            }

            // Add score based on number of open ports.
            if (openPortsCount && Number.isFinite(openPortsCount)) {
              score += openPortsCount;
              reasons.push(`+${openPortsCount} (count of unique open ports on this domain)`);
            }

            // Add score based on number of technologies detected.
            if (techCount && Number.isFinite(techCount)) {
              score += techCount;
              reasons.push(`+${techCount} (count of unique tech stack found for this application)`);
            }

            return { score, debug: reasons };
          }

          // Function: getDynamicColor
          // Purpose: Calculate a color gradient (from green to red) based on the risk score.
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

          // Function: buildScoreboard
          // Purpose: Update the score cards with summary metrics.
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

          // Function: buildCharts
          // Purpose: Create multiple charts using Chart.js based on various data sets.
          function buildCharts({
            statusCount,
            priorityCount,
            portCount,
            techCount,
            totalSubdomains,
            liveSubs,
            endpointsCount
          }) {
            // Build Assets Overview chart.
            const scCanvas = document.getElementById("statusCodeChart");
            const prCanvas = document.getElementById("priorityChart");
            const portCanvas = document.getElementById("portChart");
            const techCanvas = document.getElementById("techChart");

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

            // Build HTTP Status Codes chart.
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

            // Build Top 10 Open Ports chart.
            if (portCanvas) {
              const sortedPorts = Object.keys(portCount).sort((a, b) => portCount[b] - portCount[a]);
              const top10Ports = sortedPorts.slice(0, 10);
              portChart = new Chart(portCanvas, {
                type: "bar",
                data: {
                  labels: top10Ports,
                  datasets: [{
                    label: "Open Ports",
                    data: top10Ports.map(p => portCount[p]),
                    backgroundColor: "#f39c12"
                  }]
                },
                options: {
                  responsive: true,
                  plugins: {
                    legend: { display: false },
                    title: { display: true, text: "Top 10 Ports" }
                  },
                  scales: {
                    y: { beginAtZero: true }
                  }
                }
              });
            }

            // Build Top 10 Technologies chart.
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
                  indexAxis: "x", // keep it horizontal
                  plugins: {
                    legend: { display: false },
                    title: { display: true, text: "Top 10 Technologies" }
                  },
                  scales: {
                    x: { beginAtZero: true,
                      ticks: {
                        // Rotate labels by -45 or -60 degrees, for example
                        maxRotation: 60,
                        minRotation: 70
                      }
                     }
                  }
                }
              });
            }
          }

          // Function: buildCDNTypeChart
          // Purpose: Create a bar chart to show distribution of CDN types.
          function buildCDNTypeChart(httpxData) {
            const cdnTypeCounts = {};
            httpxData.forEach(record => {
              let cdnType = record.cdn_type;
              if (cdnType && cdnType !== "N/A") {
                cdnType = cdnType.trim();
                cdnTypeCounts[cdnType] = (cdnTypeCounts[cdnType] || 0) + 1;
              }
            });
            const labels = Object.keys(cdnTypeCounts);
            const data = labels.map(l => cdnTypeCounts[l]);
            const ctx = document.getElementById("cdnTypeChart").getContext("2d");
            cdnTypeChart = new Chart(ctx, {
              type: "bar",
              data: {
                labels,
                datasets: [{
                  label: "CDN Type Distribution",
                  data,
                  backgroundColor: "#27ae60"
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  title: { display: true, text: "CDN Type Usage" },
                  legend: { display: false }
                },
                scales: {
                  y: { beginAtZero: true }
                }
              }
            });
          }

          // Function: buildDomainCountChart
          // Purpose: Create a chart showing the top 10 domains based on active URLs.
          function buildDomainCountChart(httpxData) {
          const domainCount = {};
          httpxData.forEach(h => {
            if (h.url && h.url !== "N/A") {
              const domain = (h.input || "").split(":")[0];
              domainCount[domain] = (domainCount[domain] || 0) + 1;
            }
          });

          const sortedDomains = Object.keys(domainCount).sort(
            (a, b) => domainCount[b] - domainCount[a]
          );
          const top10 = sortedDomains.slice(0, 10);
          const data = top10.map(d => domainCount[d]);
          const ctx = document.getElementById("domainCountChart").getContext("2d");

          domainCountChart = new Chart(ctx, {
            type: "bar",
            data: {
              labels: top10,
              datasets: [
                {
                  label: "Top 10 Domains (Active URLs)",
                  data,
                  backgroundColor: "#2980b9"
                }
              ]
            },
            options: {
              responsive: true,
              indexAxis: "x",
              plugins: {
                legend: { display: false },
                title: {
                  display: true,
                  text: "Top 10 Domains by Active URLs"
                }
              },
              scales: {
                x: {
                  beginAtZero: true,
                  ticks: {
                    stepSize: 1,     // Ensure integer increments
                    maxRotation: 100,
                    minRotation: 70
                  }
                }
              }
            }
          });
        }

          // Function: buildLoginBarChart
          // Purpose: Create a bar chart to show the count of endpoints with and without login interfaces.
          function buildLoginBarChart(endpointsCount, loginFoundCount) {
            const canvas = document.getElementById("loginBarChart");
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

          // Function: buildCertExpiryChart
          // Purpose: Create a chart to show certificate expiry in the next 7, 14, and 30 days.
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

          // Function: buildTLSUsageChart
          // Purpose: Create a chart showing usage of different SSL/TLS versions.
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

          // Function: buildHeadersChart
    // Purpose: Create a chart comparing the presence and absence of all key security headers.
    // Headers evaluated: Strict-Transport-Security (HSTS), X-Frame-Options, Content-Security-Policy (CSP),
    // X-XSS-Protection, Referrer-Policy, and Permissions-Policy.
    function buildHeadersChart(httpxData, secMapUrlParam) {
      let hstsPresent = 0, hstsMissing = 0;
      let xfoPresent = 0, xfoMissing = 0;
      let cspPresent = 0, cspMissing = 0;
      let xssPresent = 0, xssMissing = 0;
      let rpPresent = 0, rpMissing = 0;
      let ppPresent = 0, ppMissing = 0;

      httpxData.forEach(record => {
        // Get the domain from the input field (split by ":" in case port is appended)
        const sec = secMapUrlParam[record.url] || {};


        // For each header, trim and verify that its value is not empty, "N/A", or "false"
        const hsts = (sec["Strict-Transport-Security"] || "").trim();
        if (hsts && hsts.toLowerCase() !== "n/a" && hsts.toLowerCase() !== "false") {
          hstsPresent++;
        } else {
          hstsMissing++;
        }

        const xfo = (sec["X-Frame-Options"] || "").trim();
        if (xfo && xfo.toLowerCase() !== "n/a" && xfo.toLowerCase() !== "false") {
          xfoPresent++;
        } else {
          xfoMissing++;
        }

        const csp = (sec["Content-Security-Policy"] || "").trim();
        if (csp && csp.toLowerCase() !== "n/a" && csp.toLowerCase() !== "false") {
          cspPresent++;
        } else {
          cspMissing++;
        }

        const xss = (sec["X-XSS-Protection"] || "").trim();
        if (xss && xss.toLowerCase() !== "n/a" && xss.toLowerCase() !== "false") {
          xssPresent++;
        } else {
          xssMissing++;
        }

        const rp = (sec["Referrer-Policy"] || "").trim();
        if (rp && rp.toLowerCase() !== "n/a" && rp.toLowerCase() !== "false") {
          rpPresent++;
        } else {
          rpMissing++;
        }

        const pp = (sec["Permissions-Policy"] || "").trim();
        if (pp && pp.toLowerCase() !== "n/a" && pp.toLowerCase() !== "false") {
          ppPresent++;
        } else {
          ppMissing++;
        }
      });

      const ctx = document.getElementById("headersChart").getContext("2d");
      headersChart = new Chart(ctx, {
        type: "bar",
        data: {
          labels: ["HSTS", "X-Frame-Options", "CSP", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"],
          datasets: [
            { label: "Present", data: [hstsPresent, xfoPresent, cspPresent, xssPresent, rpPresent, ppPresent], backgroundColor: "#2ecc71" },
            { label: "Missing", data: [hstsMissing, xfoMissing, cspMissing, xssMissing, rpMissing, ppMissing], backgroundColor: "#e74c3c" }
          ]
        },
        options: {
          responsive: true,
          indexAxis: "x",
          plugins: {
            title: { display: true, text: "Security Headers" },
            tooltip: { mode: "index", intersect: false }
          },
          scales: {
            x: { stacked: true },
            y: { stacked: true, beginAtZero: true }
          }
        }
      });
    }

          // Function: buildEmailSecChart
          // Purpose: Create a chart showing the presence or absence of email security records.
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

          // Function: buildCDNChart
          // Purpose: Create a chart showing CDN usage statistics.
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
                  label: "CDN Usage",
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

          // Function: buildServiceChart
          // Purpose: Create a chart showing the top 10 open services from port scanning.
          function buildServiceChart(naabuData) {
            const naabuMap = {};
            const serviceCount = {};
            naabuData.forEach(n => {
              const domain = n.host;
              const port = n.port;
              let service = "Unknown";
              // Map well-known ports to their corresponding service names.
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
            window.naabuMap = naabuMap;
            const ctx = document.getElementById("serviceChart").getContext("2d");
            const sortedServices = Object.keys(serviceCount).sort((a, b) => serviceCount[b] - serviceCount[a]);
            const top10Services = sortedServices.slice(0, 10);
            const data = top10Services.map(service => serviceCount[service]);
            serviceChart = new Chart(ctx, {
              type: "bar",
              data: {
                labels: top10Services,
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
                  title: { display: true, text: "Top 10 Services" }
                },
                scales: {
                  y: { beginAtZero: true }
                }
              }
            });
          }

          // Function: buildColleagueChart
          // Purpose: Create a chart comparing endpoints intended for employees versus customers.
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

          // Global array to store table row elements and additional data.
          let rowDataStore = [];

          // Function: buildTableRows
          // Purpose: Build table rows using combined data from DNS and HTTP results.
          // It also calculates risk scores using computePriority() and applies tooltips.
          function buildTableRows(combinedData, secMapDomain, secMapUrl, loginMap, apiMap, colleagueMap) {
            allTableRows = [];
            rowDataStore = [];
            Object.keys(combinedData).forEach(domain => {
              const { dns, http } = combinedData[domain];
              const dnsResolvers = dns && dns.resolver ? dns.resolver : [];
              const dnsA = dns && dns.a ? dns.a : [];
              const dnsStatus = dns ? dns.status_code : "N/A";
              const domainSec = secMapDomain[domain] || {};
              const spf    = domainSec["SPF Record"] || "N/A";
              const dkim   = domainSec["DKIM Record"] || "N/A";
              const dmarc  = domainSec["DMARC Record"] || "N/A";
              const dnssec = domainSec["DNSSEC Status"] || "N/A";
              let openPortsCount = 0;
              if (window.naabuMap && window.naabuMap[domain]) {
                openPortsCount = window.naabuMap[domain].length;
              }
              if (http && http.length) {
                http.forEach(h => {
                  const urlSec = secMapUrl[h.url] || domainSec;
                  const sslVersion = urlSec["SSL/TLS Version"] || "N/A";
                  const certExpiry = urlSec["Cert Expiry Date"] || "N/A";
                  const sslIssuer  = urlSec["SSL/TLS Issuer"] || "N/A";
                  const stsFlag = (urlSec["Strict-Transport-Security"] || "").trim();
                  const xfoFlag = (urlSec["X-Frame-Options"] || "").trim();
                  const cspFlag = (urlSec["Content-Security-Policy"] || "").trim();
                  const xssFlag = (urlSec["X-XSS-Protection"] || "").trim();
                  const rpFlag  = (urlSec["Referrer-Policy"] || "").trim();
                  const ppFlag  = (urlSec["Permissions-Policy"] || "").trim();
                  const techArr = Array.isArray(h.tech) ? h.tech : [];
                  const sanitizedTech = techArr.map(item => item.replace(/\r?\n|\r/g, " ").trim());
                  const techCount = sanitizedTech.length;

                  // Calculate the risk score and get debugging reasons.
                  const { score, debug } = computePriority({
                    purpose: colleagueMap[domain] === "Yes" ? "Employee Intended" : "Customer Intended",
                    url: h.url,
                    loginFound: loginMap[h.url] || "No",
                    statusCode: h.status_code,
                    sslVersion,
                    certExpiry,
                    sts: stsFlag,
                    xfo: xfoFlag,
                    csp: cspFlag,
                    xss: xssFlag,
                    rp:  rpFlag,
                    pp:  ppFlag,
                    openPortsCount,
                    techCount
                  });

                  // Update global min and max risk scores for dynamic coloring.
                  if (score < minRiskScore) minRiskScore = score;
                  if (score > maxRiskScore) maxRiskScore = score;
                  riskScores[domain] = score;
                  rowDataStore.push({ domain, prioScore: score });

                  // Create a new table row and populate its cells.
                  const row = document.createElement("tr");
                  row.innerHTML = `
                    <td><!-- risk score cell; we set text + tooltip below --></td>
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
                    <td>${stsFlag ? "True" : "False"}</td>
                    <td>${xfoFlag ? "True" : "False"}</td>
                    <td>${cspFlag ? "True" : "False"}</td>
                    <td>${xssFlag ? "True" : "False"}</td>
                    <td>${rpFlag ? "True" : "False"}</td>
                    <td>${ppFlag ? "True" : "False"}</td>
                    <td>${
                      (window.naabuMap && window.naabuMap[domain])
                      ? window.naabuMap[domain].map(p => `${p.port} (${p.service})`).join("<br>")
                      : "N/A"
                    }</td>
                  `;
                  // Add the new row to the global list.
                  allTableRows.push(row);

                  // Set the risk score cell's text and add a tooltip with debug reasons.
                  const scoreCell = row.getElementsByTagName("td")[0];
                  scoreCell.innerText = score;
                  scoreCell.title = debug.join("\n");
                });
              } else {
                // If there is no HTTP data, create a default row.
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

          // Function: finalizeColors
          // Purpose: Apply dynamic background colors to risk score cells based on their value.
          function finalizeColors() {
            allTableRows.forEach(row => {
              const cells = row.getElementsByTagName("td");
              const scoreCell = cells[0];
              if (scoreCell.innerText === "N/A") {
                return;
              }
              const prioScore = parseInt(scoreCell.innerText, 10) || 0;
              const color = getDynamicColor(prioScore, minRiskScore, maxRiskScore);
              scoreCell.style.backgroundColor = color;
              scoreCell.style.color = "#fff";
            });
          }

          // Function: getFilteredRows
          // Purpose: Filter table rows based on search query and each column's filter dropdown.
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
            // Sort rows by risk score (ascending or descending)
            filtered.sort((a, b) => {
              const scoreA = parseInt(a.cells[0].innerText) || 0;
              const scoreB = parseInt(b.cells[0].innerText) || 0;
              return riskSortOrder === "asc" ? scoreA - scoreB : scoreB - scoreA;
            });
            return filtered;
          }

          // Function: renderTable
          // Purpose: Render the filtered rows in the table body with pagination.
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

          // Function: renderPaginationControls
          // Purpose: Create and display pagination controls below the table.
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

          // Function: onFilterChange
          // Purpose: Reset pagination and re-render table rows when a filter changes.
          function onFilterChange() {
            currentPage = 1;
            renderTable(getFilteredRows());
          }

          // Function: updateRowsPerPage
          // Purpose: Update the global rowsPerPage based on the dropdown and re-render the table.
          function updateRowsPerPage() {
            const select = document.getElementById("rowsPerPageSelect");
            const value = select.value;
            if (value === "all") rowsPerPage = Infinity;
            else rowsPerPage = parseInt(value, 10);
            currentPage = 1;
            renderTable(getFilteredRows());
          }

          // Function: populateColumnFilters
          // Purpose: Populate filter dropdowns for each table column with unique values.
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

          // Attach event listeners to the search box, rows per page dropdown, and risk sort toggle.
          document.getElementById("searchBox").addEventListener("input", onFilterChange);
          document.getElementById("rowsPerPageSelect").addEventListener("change", updateRowsPerPage);
          document.getElementById("riskSortToggle").addEventListener("click", function() {
            riskSortOrder = (riskSortOrder === "asc") ? "desc" : "asc";
            this.textContent = (riskSortOrder === "asc") ? "▲" : "▼";
            renderTable(getFilteredRows());
          });

          // Async function: loadData
          // Purpose: Load JSON data from various files, build charts, table rows, and render the HTML report.
          async function loadData() {
            try {
              const [dnsxRes, naabuRes, httpxRes, loginRes, secRes, apiRes, colleagueRes] = await Promise.all([
                fetch("dnsx.json"),
                fetch("naabu.json"),
                fetch("httpx.json"),
                fetch("login.json"),
                fetch("securitycompliance.json"),
                fetch("api_identification.json"),
                fetch("colleague_identification.json")
              ]);
              const dnsxData      = await dnsxRes.json().catch(() => []);
              const naabuData     = await naabuRes.json().catch(() => []);
              const httpxData     = await httpxRes.json().catch(() => []);
              const loginData     = await loginRes.json().catch(() => []);
              const secData       = await secRes.json().catch(() => []);
              const apiData       = await apiRes.json().catch(() => []);
              const colleagueData = await colleagueRes.json().catch(() => []);

              // Build security maps for domains and URLs.
              const secMapDomain = {};
              const secMapUrl = {};
              secData.forEach(item => {
                if (item.Domain && !secMapDomain[item.Domain]) {
                  secMapDomain[item.Domain] = item;
                }
                if (item.URL) {
                  secMapUrl[item.URL] = item;
                }
              });

              // Map login detection results.
              const loginMap = {};
              loginData.forEach(item => {
                loginMap[item.url] = item.login_detection.login_found;
              });

              // Map API endpoint identification.
              const apiMap = {};
              apiData.forEach(item => {
                apiMap[item.domain] = item.api_endpoint;
              });

              // Map colleague endpoint identification.
              const colleagueMap = {};
              colleagueData.forEach(item => {
                colleagueMap[item.domain] = item.colleague_endpoint;
              });

              // Calculate summary metrics.
              const endpointsCount = httpxData.length;
              const loginFoundCount = loginData.filter(item => item.login_detection.login_found === "Yes").length;
              const liveSubs = dnsxData.filter(d => d.status_code === "NOERROR").length;
              const domainSet = new Set();
              dnsxData.forEach(d => { if (d.host) domainSet.add(d.host); });
              const totalSubdomains = domainSet.size;

              // Build summary scoreboard and charts.
              buildScoreboard({ totalSubdomains, liveSubs, totalHttpx: endpointsCount, loginFoundCount });
              buildLoginBarChart(endpointsCount, loginFoundCount);

              const statusCount = {};
              httpxData.forEach(h => {
                const code = h.status_code || 0;
                statusCount[code] = (statusCount[code] || 0) + 1;
              });

              const priorityCount = {};
              httpxData.forEach(h => {
                const domain = (h.input || "").split(":")[0];
                const { score } = computePriority({
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
                if (!priorityCount[domain] || score > priorityCount[domain]) {
                  priorityCount[domain] = score;
                }
                if (score < minRiskScore) minRiskScore = score;
                if (score > maxRiskScore) maxRiskScore = score;
              });

              const portCount = {};
              naabuData.forEach(n => {
                const p = n.port || "unknown";
                portCount[p] = (portCount[p] || 0) + 1;
              });

              const techCount = {};
              httpxData.forEach(h => {
                if (Array.isArray(h.tech)) {
                  h.tech.forEach(t => {
                    techCount[t] = (techCount[t] || 0) + 1;
                  });
                }
              });

              buildCharts({
                statusCount,
                priorityCount,
                portCount,
                techCount,
                totalSubdomains,
                liveSubs,
                endpointsCount
              });
              buildDomainCountChart(httpxData);
              buildServiceChart(naabuData);
              buildColleagueChart(colleagueData);

              // Combine DNS and HTTP data for table rows.
              const combinedData = {};
              dnsxData.forEach(d => {
                combinedData[d.host] = { dns: d, http: [] };
              });
              httpxData.forEach(h => {
                const domain = (h.input || "").split(":")[0];
                if (!combinedData[domain]) combinedData[domain] = { dns: null, http: [] };
                combinedData[domain].http.push(h);
              });

              // Build table rows, apply risk colors, populate filter dropdowns,
              // add event listeners for filter changes, and render the table.
              buildTableRows(combinedData, secMapDomain, secMapUrl, loginMap, apiMap, colleagueMap);
              finalizeColors();
              populateColumnFilters();
              document.querySelectorAll('#filter-row select').forEach(select => {
                select.addEventListener('change', onFilterChange);
              });
              renderTable(getFilteredRows());

              // For certificate and TLS charts, filter valid domains from httpx.
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
              buildHeadersChart(httpxData, secMapUrl); // pass secMapUrl as the second arg
              buildEmailSecChart(secData);
              buildCDNChart(httpxData);
              buildCDNTypeChart(httpxData);
              updateChartTheme();
            } catch (err) {
              console.error("Error loading data or building report:", err);
            }
          }

          // Kick off the data loading and report rendering process.
          loadData();
        </script>
      </body>
    </html>

EOF
  info "[13/13] HTML report generated at: $report_html"
}

##############################################
# Function: show_summary
# Purpose: Display a final summary table of the recon results.
##############################################
show_summary() {
  local combined_pre_dedup=$((CHAOS_COUNT + SUBFINDER_COUNT + ASSETFINDER_COUNT + CRT_COUNT))
  local final_subdomains_count
  final_subdomains_count=$(wc -l < "$MASTER_SUBS")
  echo ""
  echo "=============== RECON SUMMARY ==============="
  printf "%-28s %s\n" "Total assets pre-deduplication:" "$combined_pre_dedup"
  printf "%-28s %s\n" "Final assets post-deduplication:" "$final_subdomains_count"
  printf "%-28s %s\n" "Total Live assets:" "$DNSX_LIVE_COUNT"
  printf "%-28s %s\n" "Total Live websites:" "$HTTPX_LIVE_COUNT"
  echo "============================================="
}

##############################################
# Main Execution Function
# Purpose: Sequentially execute all recon functions, build the report, and show summary.
##############################################
main() {
  run_chaos
  run_subfinder
  run_assetfinder
  run_crtsh
  info "[4/13] Merging subdomains..."
  # Append each primary domain and its www subdomain to ALL_TEMP.
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

# Start the main process.
main
