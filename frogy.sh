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

# --- Begin logging configuration (store only in logs) ---
# Redirect STDERR (which xtrace uses) to the log file.
exec 2> "$RUN_DIR/logs/logs.log"
set -x
# --- End logging configuration ---

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
    subfinder -dL "$PRIMARY_DOMAINS_FILE" -silent -all -o "$RUN_DIR/subfinder.txt" >/dev/null 2>&1 || true
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
          -p "7,9,13,21,22,23,25,26,37,53,66,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,443,457,465,513,514,515,543,544,548,554,587,631,646,7647,8000,8001,8008,8080,8081,8085,8089,8090,873,8880,8888,9000,9080,9100,990,993,995,1024,1025,1026,1027,1028,1029,10443,1080,1100,1110,1241,1352,1433,1434,1521,1720,1723,1755,1900,1944,2000,2001,2049,2121,2301,2717,3000,3128,32768,3306,3389,3986,4000,4001,4002,4100,4567,4899,49152-49157,5000,5001,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5801,5802,5900,5985,6000,6001,6346,6347,6646,7001,7002,7070,7170,7777,8800,9999,10000,20000,30821" \
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
    httpx -silent \
          -l "$final_urls_ports" \
          -screenshot \
          >/dev/null 2>&1 || true
    # Count the number of live websites detected by httpx.
    HTTPX_LIVE_COUNT=$(wc -l < "$RUN_DIR/httpx.json")
  fi
}

gather_screenshots() {
  local screenshot_map_file="$RUN_DIR/screenshot_map.json"
  echo "{" > "$screenshot_map_file"
  local first=true

  # Loop over each subfolder in $RUN_DIR/screenshot
  for folder in "$RUN_DIR/screenshot"/*; do
    [ -d "$folder" ] || continue  # skip if not a directory
    local base="$(basename "$folder")"
    # Find the first .png in that folder (httpx -screenshot usually creates one .png)
    local pngfile
    pngfile=$(find "$folder" -maxdepth 1 -type f -iname "*.png" | head -n1)
    if [ -n "$pngfile" ]; then
      # Create a relative path for use in HTML (so that report.html can load it)
      local relpath="screenshot/$base/$(basename "$pngfile")"
      if [ "$first" = true ]; then
        first=false
      else
        echo "," >> "$screenshot_map_file"
      fi
      echo -n "\"$base\": \"$relpath\"" >> "$screenshot_map_file"
    fi
  done

  echo "}" >> "$screenshot_map_file"
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
# Security Compliance and Hygine Checks
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
    local spf dkim dmarc dnskey dnssec ns txt srv ptr mx soa caa

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

    # Additional DNS records
    ns=$(dig +short NS "$domain" 2>/dev/null || true)
    [ -z "$ns" ] && ns="No NS records found"

    txt=$(dig +short TXT "$domain" 2>/dev/null || true)
    [ -z "$txt" ] && txt="No TXT records found"

    srv=$(dig +short SRV "$domain" 2>/dev/null || true)
    [ -z "$srv" ] && srv="No SRV records found"

    # --- Reverse DNS (PTR) from resolved A record ---
    local a_record
    local ptr=""
    a_record=$(dig +short A "$domain" 2>/dev/null | head -n 1)
    if [ -n "$a_record" ]; then
      ptr=$(dig +short -x "$a_record" 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true)
    fi
    [ -z "$ptr" ] && ptr="No PTR record found"

    mx=$(dig +short MX "$domain" 2>/dev/null || true)
    [ -z "$mx" ] && mx="No MX records found"

    soa=$(dig +short SOA "$domain" 2>/dev/null || true)
    [ -z "$soa" ] && soa="No SOA record found"

    caa=$(dig +short CAA "$domain" 2>/dev/null || true)
    [ -z "$caa" ] && caa="No CAA records found"

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
          --arg ns "$ns" --arg txt "$txt" --arg srv "$srv" --arg ptr "$ptr" --arg mx "$mx" --arg soa "$soa" --arg caa "$caa" \
          --arg ssl_version "$ssl_version" --arg ssl_issuer "$ssl_issuer" --arg cert_expiry "$cert_expiry" \
          --arg sts "$sts" --arg xfo "$xfo" --arg csp "$csp" --arg xss "$xss" --arg rp "$rp" --arg pp "$pp" --arg acao "$acao" \
          '{
             Domain: $domain,
             URL: $url,
             "SPF Record": $spf,
             "DKIM Record": $dkim,
             "DMARC Record": $dmarc,
             "DNSSEC Status": $dnssec,
             "NS Records": $ns,
             "TXT Records": $txt,
             "SRV Records": $srv,
             "PTR Record": $ptr,
             "MX Records": $mx,
             "SOA Record": $soa,
             "CAA Records": $caa,
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
        --arg ns "$ns" --arg txt "$txt" --arg srv "$srv" --arg ptr "$ptr" --arg mx "$mx" --arg soa "$soa" --arg caa "$caa" \
        --arg ssl_version "No SSL/TLS" --arg ssl_issuer "N/A" --arg cert_expiry "N/A" \
        --arg sts "" --arg xfo "" --arg csp "" --arg xss "" --arg rp "" --arg pp "" --arg acao "" \
        '{
           Domain: $domain,
           URL: $url,
           "SPF Record": $spf,
           "DKIM Record": $dkim,
           "DMARC Record": $dmarc,
           "DNSSEC Status": $dnssec,
           "NS Records": $ns,
           "TXT Records": $txt,
           "SRV Records": $srv,
           "PTR Record": $ptr,
           "MX Records": $mx,
           "SOA Record": $soa,
           "CAA Records": $caa,
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
  local tokens=("qa01" "www-preprod" "uat9" "uat02" "workspace" "staging4" "api-uat" "ngcp-qa2" "webstg" "aem-stage2" "staging3" "canary" "hd-qa74" "uat05" "stgapps" "sit3" "ngcp-prf" "staging-dcm" "stage-mycosta" "edg-stg" "apidev" "uat-aka" "aem-dev2" "aem-qa2" "api-preprod" "shopecomqa" "uat03" "accounts-e2e" "uat7" "test4" "api-qa" "admin-academy" "staging-api" "prodcms" "wiop-stage" "api-stage" "preprod-www" "qa-api" "www-int" "gleague-dev" "prod-qa" "www-uat" "globalstg" "stg1" "pes-preprod" "matrix-preprod" "qa-us" "stage65-engage" "qaperf" "docs-test" "mcprod" "qa02-www" "www-qa2" "cqa" "portalstage" "wiop-qa" "server4" "sit-www" "test-shop" "api-product" "qa-ie" "www-qa3" "cstage" "testint" "perf-www" "mydesk-uat" "wwwdev" "qa5" "qa31" "api-prod" "uat6" "integ" "ux-stage" "aktest-www" "www-stg" "backoffice" "www-qa1" "uat5" "test3" "prodtest" "qa4" "preprod-corporate" "uat8" "emails" "develop" "www-qa" "www-dev" "dev-api" "uat-preview" "wwwtst" "int-www" "www-staging" "uat-www" "api-test" "server3" "homolog" "secure-api" "akamai-staging" "akamai-pat" "stg2" "stagecms" "confluence" "qa-www" "mcstaging" "stage3" "cdev" "cdev2" "dev-www" "cos-internal" "console" "uat3" "stage65" "dev3" "autoconfig" "pilot" "server2" "dashboard" "preview-test" "intranet" "e2e" "uat4" "uat-pdp" "lockerroom" "idp" "staff" "preview-uat-pdp" "upload" "infra" "api1" "lab" "failover" "extranet" "wip" "api3" "dr" "matrix-uat" "sit2" "testing" "jira" "webqa" "preprod2" "storage" "config" "gitlab" "git" "signin" "api-dev" "backend" "shadow" "api" "mail" "svc" "dev" "stage" "staging" "test" "qa" "uat" "stg" "prod" "bastion" "preprod" "login" "admin" "ingress" "preview" "portal" "vpn" "auth" "int" "traefik" "localhost" "remote" "support" "accounts" "developer" "development" "tools" "sandbox" "tst" "demo" "qa2" "perf" "uat2" "control" "sso" "sit" "acc" "dev1" "dev2" "access" "uat1" "internal" "training" "server1" "purge" "edit" "pre" "client" "qa3" "pro" "identity" "ppe" "integration" "manage" "monitoring" "proxy" "corp" "dev" "development" "test" "testing" "qa" "uat" "stage" "staging" "demo" "sandbox" "lab" "labs" "experimental" "preprod" "pre-production" "pre-prod" "nonprod" "non-production" "non-prod" "perf" "performance" "loadtest" "soaktest" "integration" "integrationtest" "release" "hotfix" "feature" "rc" "beta" "alpha" "internal" "private" "intranet" "corp" "corporate" "employee" "colleague" "partner" "restricted" "secure" "admin" "backoffice" "back-office" "management" "mgmt" "console" "ops" "operations" "dashboard" "sysadmin" "root" "sudo" "superuser" "jenkins" "teamcity" "bamboo" "circleci" "travis" "gitlab" "bitbucket" "gitea" "jira" "confluence" "artifactory" "nexus" "harbor" "grafana" "kibana" "prometheus" "alertmanager" "nagios" "zabbix" "splunk" "posthog" "sentry" "phabricator" "default" "standard" "placeholder" "dummy" "guest" "temp" "example" "portal" "hr" "hrportal" "helpdesk" "support" "servicedesk" "tools" "tooling" "services" "api-internal" "internalapi" "playground" "workshop" "vpn" "local" "localhost" "onprem" "on-prem" "dmz" "bastion" "jumpbox" "cache" "queue" "log" "logs" "monitor" "metrics" "ldap" "ad" "ntp" "smtp-internal" "ftp-internal")
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

  cat header.html > report.html
  echo -n "const dnsxData = " >> report.html
  cat $RUN_DIR/dnsx.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const naabuData = " >> report.html
  cat $RUN_DIR/naabu.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const httpxData = " >> report.html
  cat $RUN_DIR/httpx.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const loginData = " >> report.html
  cat $RUN_DIR/login.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const secData = " >> report.html
  echo "" >> report.html
  cat $RUN_DIR/securitycompliance.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const apiData = " >> report.html
  cat $RUN_DIR/api_identification.json | tr -d "\n" >> report.html
  echo "" >> report.html
  echo -n "const colleagueData = " >> report.html
  cat $RUN_DIR/colleague_identification.json| tr -d "\n" >> report.html
  echo "" >> report.html
  cat footer.html >> report.html
  sed -i.bak '/%%SCREENSHOT_MAP%%/{
    r '"$RUN_DIR/screenshot_map.json"'
    d
  }' report.html && rm -f report.html.bak

  mv report.html $RUN_DIR/

  info "[13/13] Report generated at $RUN_DIR/report.html"
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
  mv output/response $RUN_DIR/
  mv output/screenshot $RUN_DIR/
  gather_screenshots
  run_login_detection
  run_security_compliance
  run_api_identification
  run_colleague_identification
  build_html_report
  show_summary
}

# Start the main process.
main
