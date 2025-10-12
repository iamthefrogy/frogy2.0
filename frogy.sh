#!/usr/bin/env bash
set -euo pipefail
set -o errtrace

# Enhanced error trap for context on failures
log_err() {
	local ec=$?
	local cmd=${BASH_COMMAND}
	echo "ERR: exit ${ec} at ${BASH_SOURCE[0]}:${BASH_LINENO[0]} while running: ${cmd}" >&2
}
trap log_err ERR

# This function will be called automatically whenever the script exits.
SCRIPT_START_TIME=$(date +%s)

script_cleanup() {
	local exit_code=$?
	if [ $exit_code -ne 0 ]; then
		error "Script exited unexpectedly with code $exit_code."
		error "The last command to run was near line ${BASH_LINENO[0]} in the function '${FUNCNAME[1]}'."
		error "Check the detailed trace log for more context: $RUN_DIR/logs/logs.log"
	else
		info "Script finished successfully."
		local end_time
		end_time=$(date +%s)
		local duration=$((end_time - SCRIPT_START_TIME))
		local hours=$((duration / 3600))
		local minutes=$(((duration % 3600) / 60))
		local seconds=$((duration % 60))
		if (( hours > 0 )); then
			info "Total execution time: ${hours}h ${minutes}m ${seconds}s"
		else
			info "Total execution time: ${minutes}m ${seconds}s"
		fi
	fi
}

# Register the 'script_cleanup' function to run on EXIT.
trap script_cleanup EXIT

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
GAU_COUNT=0
# Block Detection - The script will exit if the percentage of live websites found by httpx is lower than this threshold. Set to "0" to disable.
BLOCK_DETECTION_THRESHOLD="20" # (Exit if < 20% success rate)

##############################################
# Function: check_dependencies
# Purpose: Verify all required external tools are installed before starting.
##############################################
check_dependencies() {
	info "Verifying required tools..."
	local missing_tools=()
	# Add ALL external commands used in the script to this list
	local required_tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx" "katana" "jq" "curl" "whois" "dig" "openssl" "xargs" "unzip" "grep" "sed" "awk")

	for tool in "${required_tools[@]}"; do
		if ! command -v "$tool" &>/dev/null; then
			missing_tools+=("$tool")
		fi
	done

	if [ ${#missing_tools[@]} -ne 0 ]; then
		error "FATAL: The following required tools are not installed or not in your PATH:"
		for tool in "${missing_tools[@]}"; do
			echo -e "${RED}  - $tool${NC}"
		done
		# Exit immediately because the script cannot continue without these tools.
		exit 1
	fi
	info "All required tools are present."
}

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
if [[ ! -f "$PRIMARY_DOMAINS_FILE" || ! -r "$PRIMARY_DOMAINS_FILE" ]]; then
	echo -e "\033[91m[-] File '$PRIMARY_DOMAINS_FILE' not found or not readable!\033[0m" >&2
	exit 1
fi
if ! awk '!/^\s*$/ { if ($0 !~ /^[A-Za-z0-9.-]+$/) { exit 1 } }' "$PRIMARY_DOMAINS_FILE"; then
	error "Input file contains invalid domain lines."
	exit 1
fi

##############################################
# Create a unique output directory for this run. # The run directory is timestamped for uniqueness.
##############################################
RUN_DIR="output/run-$(date +%Y%m%d%H%M%S)"
mkdir -p "$RUN_DIR/raw_output/raw_http_responses"
mkdir -p "$RUN_DIR/logs"

# Verify output paths are writable
if [[ ! -w "$RUN_DIR" || ! -w "$RUN_DIR/logs" ]]; then
	error "Output directory '$RUN_DIR' or its 'logs' subdir is not writable."
	exit 1
fi

# Begin logging configuration (store only in logs) - Redirect STDERR (which xtrace uses) to the log file.
exec 2>"$RUN_DIR/logs/logs.log"
set -x

##############################################
# Global file paths for temporary subdomain lists
##############################################
ALL_TEMP="$RUN_DIR/all_temp_subdomains.txt"
MASTER_SUBS="$RUN_DIR/master_subdomains.txt"
>"$ALL_TEMP"
>"$MASTER_SUBS"

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
USE_GAU="true"

# Default naabu scan mode; override via NAABU_SCAN_MODE env (auto|syn|connect).
NAABU_SCAN_MODE="${NAABU_SCAN_MODE:-auto}"

##############################################
# Logging Functions (with timestamps)
##############################################
# info: print informational messages
RED='\033[0;31m'
NC='\033[0m' # No Color
info() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [+] $*"; }
# warning: print warning messages
warning() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [!] $*"; }
# error: print error messages
error() { echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [-] $*${NC}"; }

# Helper: count JSON records in newline-delimited or array form
json_count() {
	local file="$1"
	[[ -s "$file" ]] || { echo 0; return; }
	jq -s 'if length == 0 then 0 elif length == 1 and (.[0]|type=="array") then (.[0]|length) else length end' "$file" 2>/dev/null || wc -l <"$file"
}

##############################################
# Function: merge_and_count
# Purpose: Merge subdomain results from a given file into a global temporary file and update the corresponding counter based on the source.
##############################################
merge_and_count() {
	local file="$1"        # Input file containing subdomains from one tool
	local source_name="$2" # The tool name (e.g., "Chaos", "Subfinder")
	local count=0
	if [[ -s "$file" ]]; then
		count=$(wc -l <"$file")
		cat "$file" >>"$ALL_TEMP"
	fi
	# Update counters based on the tool used
	case "$source_name" in
	"Chaos") CHAOS_COUNT=$((CHAOS_COUNT + count)) ;;
	"Subfinder") SUBFINDER_COUNT=$((SUBFINDER_COUNT + count)) ;;
	"Assetfinder") ASSETFINDER_COUNT=$((ASSETFINDER_COUNT + count)) ;;
	"Certificate") CRT_COUNT=$((CRT_COUNT + count)) ;;
	"GAU") GAU_COUNT=$((GAU_COUNT + count)) ;;
	esac

}

##############################################
# Function: run_chaos
# Purpose: Query the Chaos database (if enabled) and merge its subdomain results.
##############################################
run_chaos() {
	if [[ "$USE_CHAOS" == "true" ]]; then
		info "Running Chaos..."
		local cdir
		cdir="$(basename "$RUN_DIR")"
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
				cat ./*.txt >chaos.txt
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
		info "[1/15] Running Subfinder..."
		subfinder -dL "$PRIMARY_DOMAINS_FILE" -silent -all -o "$RUN_DIR/subfinder.txt" >/dev/null 2>&1 || true
		merge_and_count "$RUN_DIR/subfinder.txt" "Subfinder"
	fi
}

##############################################
# Function: run_assetfinder
# Purpose: Run Assetfinder for each primary domain and merge the results.
##############################################
run_assetfinder() {
	if [[ "$USE_ASSETFINDER" != "true" ]]; then
		return 0
	fi
	info "[2/15] Running Assetfinder..."
	local assetfinder_output="$RUN_DIR/assetfinder.txt"
	>"$assetfinder_output"
	local asset_status=0
	if ! while IFS= read -r domain || [[ -n "$domain" ]]; do
		domain=$(echo "$domain" | tr -d '\r' | xargs)
		[[ -z "$domain" ]] && continue
		assetfinder --subs-only "$domain" 2>/dev/null || true
	done <"$PRIMARY_DOMAINS_FILE" | sort -u >>"$assetfinder_output"; then
		warning "Assetfinder encountered an error; continuing without its results."
		asset_status=1
	fi
	merge_and_count "$assetfinder_output" "Assetfinder"
	return $asset_status
}

##############################################
# Function: run_crtsh
# Purpose: Query crt.sh for certificate data and extract subdomains.
##############################################
run_crtsh() {
	info "[3/15] Running crt.sh..."
	local crt_file="$RUN_DIR/whois.txt"
	>"$crt_file"
	local crt_status=0
	if ! while read -r domain; do
		{
			# Temporarily disable exit on error for this block
			set +e
			local registrant
			# Attempt to extract the registrant organization from whois data
			registrant=$(whois "$domain" 2>/dev/null |
				grep -i "Registrant Organization" |
				cut -d ":" -f2 |
				xargs |
				sed 's/,/%2C/g; s/ /+/g' |
				egrep -v '(Whois|whois|WHOIS|domains|DOMAINS|Domains|domain|DOMAIN|Domain|proxy|Proxy|PROXY|PRIVACY|privacy|Privacy|REDACTED|redacted|Redacted|DNStination|WhoisGuard|Protected|protected|PROTECTED|Registration Private|REGISTRATION PRIVATE|registration private)' ||
				true)
			if [[ -n "$registrant" ]]; then
				# Query crt.sh using the registrant information
				curl -s "https://crt.sh/?q=$registrant" |
					grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' |
					sed -e 's/^<TD>//;s/<\/TD>$//' \
						>>"$crt_file"
			fi
			# Also query crt.sh using the domain and JSON output
			curl -s "https://crt.sh/?q=$domain&output=json" |
				jq -r ".[].name_value" 2>/dev/null |
				sed 's/\*\.//g' \
					>>"$crt_file"
		} || true
		set -e
	done <"$PRIMARY_DOMAINS_FILE"; then
		warning "crt.sh lookups encountered an error; continuing."
		crt_status=1
	fi
	merge_and_count "$crt_file" "Certificate"
	return $crt_status
}

##############################################
# Function: run_gau
# Purpose: Use gau (wayback) to discover archived URLs, extract hostnames
##############################################
run_gau() {
	if [[ "$USE_GAU" != "true" ]]; then
		return 0
	fi
	info "[4/15] Running GAU…"

	mkdir -p "$RUN_DIR/raw_output/gau"
	local raw_urls="$RUN_DIR/raw_output/gau/urls.txt"
	local hosts_extracted="$RUN_DIR/raw_output/gau/hosts_extracted.txt"
	local out="$RUN_DIR/gau_subdomains.txt"

	: >"$raw_urls"
	: >"$hosts_extracted"
	: >"$out"

	local gau_status=0
	if ! while read -r domain; do
		gau "$domain" \
			--providers wayback \
			--subs \
			--threads 10 \
			--timeout 60 \
			--retries 2 \
			>>"$raw_urls" 2>/dev/null || true
	done <"$PRIMARY_DOMAINS_FILE"; then
		warning "GAU encountered an error while fetching historical URLs; continuing."
		gau_status=1
	fi

	if ! awk -F/ 'NF>=3 {h=$3; sub(/:.*/,"",h); print tolower(h)}' "$raw_urls" |
		sed 's/[[:space:]]//g' |
		grep -E '^[A-Za-z0-9.-]+$' \
			>"$hosts_extracted"; then
		warning "Failed to normalize GAU hostnames; continuing with available data."
		gau_status=1
	fi

	if ! sort -u "$hosts_extracted" >"$out"; then
		warning "Failed to deduplicate GAU results; continuing with raw data."
		gau_status=1
	fi

	merge_and_count "$out" "GAU"
	return $gau_status
}

##############################################
# Function: run_dnsx
# Purpose: Run dnsx tool to check which subdomains are live.
##############################################
run_dnsx() {
	if [[ "$USE_DNSX" == "true" ]]; then
		info "[6/15] Running dnsx..."
		dnsx -silent \
			-rl 50 \
			-t 25 \
			-l "$MASTER_SUBS" \
			-o "$RUN_DIR/dnsx.json" \
			-j \
			>/dev/null 2>&1 || true
		if [[ -s "$RUN_DIR/dnsx.json" ]]; then
			# Count live domains based on the "NOERROR" status code from dnsx output
			DNSX_LIVE_COUNT=$(jq -r 'select(.status_code=="NOERROR") | .host' "$RUN_DIR/dnsx.json" | sort -u | wc -l)
		else
			DNSX_LIVE_COUNT=0
		fi
	fi
}

##############################################
# Function: run_naabu
# Purpose: Run naabu port scanner against discovered subdomains.
##############################################
run_naabu() {
	if [[ "$USE_NAABU" == "true" ]]; then
		info "[7/15] Running naabu..."
		if [ ! -s "$MASTER_SUBS" ]; then
			warning "Master subdomains file is empty. Skipping naabu."
			return
		fi
		local -a naabu_base_args=(
			-silent
			-l "$MASTER_SUBS"
			-p "7,9,13,21,22,23,25,26,37,53,66,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,443,457,465,513,514,515,543,544,548,554,587,631,646,7647,8000,8001,8008,8080,8081,8085,8089,8090,873,8880,8888,9000,9080,9100,990,993,995,1024,1025,1026,1027,1028,1029,10443,1080,1100,1110,1241,1352,1433,1434,1521,1720,1723,1755,1900,1944,2000,2001,2049,2121,2301,2717,3000,3128,32768,3306,3389,3986,4000,4001,4002,4100,4567,4899,49152-49157,5000,5001,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5801,5802,5900,5985,6000,6001,6346,6347,6646,7001,7002,7070,7170,7777,8800,9999,10000,20000,30821"
			-o "$RUN_DIR/naabu.json"
			-json
		)

		run_naabu_pass() {
			rm -f "$RUN_DIR/naabu.json"
			naabu "${naabu_base_args[@]}" "$@" >/dev/null || true
		}

		local scan_mode="${NAABU_SCAN_MODE,,}"
		case "$scan_mode" in
		connect)
			info "Running naabu in TCP connect mode (-sC -Pn)."
			run_naabu_pass -sC -Pn
			;;
		syn | auto | "")
			run_naabu_pass
			;;
		*)
			warning "Unknown NAABU_SCAN_MODE='${NAABU_SCAN_MODE}'. Defaulting to SYN scan."
			run_naabu_pass
			;;
		esac

		local total_hits
		total_hits=$(json_count "$RUN_DIR/naabu.json")

		# Process naabu JSON to extract unique host:port pairs
		local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
		if [[ -s "$RUN_DIR/naabu.json" ]]; then
			jq -r '"\(.host):\(.port)"' "$RUN_DIR/naabu.json" | sort -u >"$final_urls_ports"
		else
			> "$final_urls_ports"
		fi
	fi
}

##############################################
# Function: run_httpx
# Purpose: Run httpx to probe live web endpoints using the ports identified.
##############################################
run_httpx() {
	if [[ "$USE_HTTPX" == "true" ]]; then
		info "[8/15] Running httpx..."
		local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
		local httpx_json_file="$RUN_DIR/httpx.json"

		# If naabu found no open ports, there's nothing for httpx to do.
		if [ ! -s "$final_urls_ports" ]; then
			warning "Input file for httpx is empty. Skipping."
			>"$httpx_json_file"
			HTTPX_LIVE_COUNT=0
			return
		fi

		httpx -silent \
			-t 5 \
			-rl 15 \
			-timeout 15 \
			-retries 2 \
			-l "$final_urls_ports" \
			-json \
			-o "$RUN_DIR/httpx.json" \
			>/dev/null || true

		# Ensure the JSON file exists even if httpx produced nothing.
		if [[ ! -f "$httpx_json_file" ]]; then
			>"$httpx_json_file"
		fi

		# Count live endpoints
		HTTPX_LIVE_COUNT=$(wc -l <"$RUN_DIR/httpx.json" || echo 0)

		# Ensure the default output dirs exist
		mkdir -p output/screenshot output/response

		# Verify runtime output dirs are writable
		if [[ ! -w "output/screenshot" || ! -w "output/response" ]]; then
			error "Output directories under ./output are not writable."
			exit 1
		fi

		# 2) Screenshot + store raw HTTP bodies
		#    • PNGs → output/screenshot (default)
		#    • Responses → output/response (must specify)
		httpx -silent \
	   	-t 5 \
		  -rl 15 \
		  -timeout 15 \
		  -retries 2 \
			-l "$final_urls_ports" \
			-ss \
			>/dev/null || true

		# --- DYNAMIC BLOCK DETECTION LOGIC ---
		local naabu_target_count
		naabu_target_count=$(wc -l <"$final_urls_ports")
		if [[ -s "$httpx_json_file" ]]; then
			HTTPX_LIVE_COUNT=$(wc -l <"$httpx_json_file")
		else
			HTTPX_LIVE_COUNT=0
		fi

		local success_rate=0
		if [[ "$naabu_target_count" -gt 0 ]]; then
			success_rate=$((HTTPX_LIVE_COUNT * 100 / naabu_target_count))
		fi

		# If the success rate is below the threshold, emit a warning so the operator can decide next steps.
		if [[ "$BLOCK_DETECTION_THRESHOLD" -gt 0 && "$naabu_target_count" -gt 10 && "$success_rate" -lt "$BLOCK_DETECTION_THRESHOLD" ]]; then
			warning "httpx success rate ${success_rate}% fell below ${BLOCK_DETECTION_THRESHOLD}%. Results may be incomplete."
		fi

		# Only run detection if we have a meaningful number of targets and the threshold is enabled.
		if [[ "$naabu_target_count" -gt 10 && "$BLOCK_DETECTION_THRESHOLD" -gt 0 ]]; then
			info "Web Scan Success Rate: ${success_rate}% (${HTTPX_LIVE_COUNT} live websites found / ${naabu_target_count} total live targets)"

			if [[ "$success_rate" -lt "$BLOCK_DETECTION_THRESHOLD" ]]; then
				warning "Success rate remains below the ${BLOCK_DETECTION_THRESHOLD}% threshold. Results may be incomplete (consider lowering BLOCK_DETECTION_THRESHOLD or changing IP)."
			fi
		fi
	fi
}

##############################################
# Function: gather_screenshot
# Purpose: Gathering screenshots
##############################################

gather_screenshots() {
	local screenshot_map_file="$RUN_DIR/screenshot_map.json"
	local screenshot_dir="$RUN_DIR/screenshot"

	printf '{\n' >"$screenshot_map_file"

	local sep=""
	for folder in "$screenshot_dir"/*/; do
		[ -d "$folder" ] || continue
		local host="$(basename "$folder")"

		local png
		png=$(find "$folder" -maxdepth 1 -type f -iname '*.png' | head -n1)
		[ -z "$png" ] && continue # skip if no screenshot

		local relpath="${png#$RUN_DIR/}"

		printf '%s' "$sep" >>"$screenshot_map_file"
		printf '  "%s": "%s"\n' "$host" "$relpath" >>"$screenshot_map_file"

		sep=","
	done

	printf '}\n' >>"$screenshot_map_file"
}

##############################################
# Function: run_katana
# Purpose: Crawl live URLs (from httpx.json) and save per-URL links into one JSON file.
##############################################
run_katana() {
	info "[9/15] Crawling links with Katana..."
	local httpx_file="$RUN_DIR/httpx.json"
	local output_file="$RUN_DIR/katana_links.json"

	if [ ! -s "$httpx_file" ]; then
		echo "{}" >"$output_file"
		return
	fi

	local seeds="$RUN_DIR/katana_seeds.txt"
	jq -r 'if type=="array" then (.[] | .url) else .url end' "$httpx_file" | sort -u >"$seeds"

	echo "{" >"$output_file"
	local first=true

	local depth="${KATANA_DEPTH:-3}"
	local timeout="${KATANA_TIMEOUT:-60}"

	while IFS= read -r url; do
		[ -z "$url" ] && continue
		local tmp="$RUN_DIR/katana_tmp.txt"
		katana -silent -c 5 -rl 30 -timeout 15 -u "$url" -d "$depth" -ct "$timeout" 2>/dev/null | sort -u >"$tmp" || true

		local links_json
		links_json=$(jq -R -s -c 'split("\n") | map(select(length>0))' "$tmp")

		if [ "$first" = true ]; then first=false; else echo "," >>"$output_file"; fi
		printf '  "%s": %s\n' "$url" "$links_json" >>"$output_file"

		rm -f "$tmp"
	done <"$seeds"

	echo "}" >>"$output_file"
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
	info "[10/15] Detecting Login panels..."
	local input_file="$RUN_DIR/httpx.json"
	local output_file="$RUN_DIR/login.json"

	: "${CURL_CONNECT_TIMEOUT:=10}" # seconds
	: "${CURL_MAX_TIME:=25}"        # seconds

	# Exit if input file or jq is not available.
	if [ ! -f "$input_file" ]; then
		return
	fi
	if ! command -v jq >/dev/null 2>&1; then
		return
	fi

	local urls
	urls=$(jq -r '.url' "$input_file")
	local tmp_dir
	tmp_dir=$(mktemp -d) || {
		error "mktemp failed"
		return
	}
	# Start JSON array output for login detection
	echo "[" >"$output_file"
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
		local headers_file
		headers_file="$(mktemp -p "$tmp_dir" headers.XXXXXX)"
		local body_file
		body_file="$(mktemp -p "$tmp_dir" body.XXXXXX)"
		local curl_err
		curl_err="$(mktemp -p "$tmp_dir" curl.XXXXXX)"

		if ! curl -s -S -L \
			--connect-timeout "$CURL_CONNECT_TIMEOUT" \
			--max-time "$CURL_MAX_TIME" \
			-D "$headers_file" \
			-o "$body_file" \
			"$url" \
			2>"$curl_err"; then
			curl_exit=$?
			# SSL connect error → skip this target cleanly
			if [ $curl_exit -eq 35 ]; then
				rm -f "$headers_file" "$body_file" "$curl_err"
				continue
			fi
			# Any other error → emit a record and continue
			if [ "$first_entry" = true ]; then
				first_entry=false
			else
				echo "," >>"$output_file"
			fi
			echo " { \"url\": \"${url}\", \"final_url\": \"\", \"login_detection\": { \"login_found\": \"No\", \"login_details\": [] } }" >>"$output_file"
			rm -f "$headers_file" "$body_file" "$curl_err"
			continue
		fi
		rm -f "$curl_err"

		# Get the final URL after redirections.
		set +e
		local final_url
		final_url=$(curl -s -S -L \
			--connect-timeout "$CURL_CONNECT_TIMEOUT" \
			--max-time "$CURL_MAX_TIME" \
			-o /dev/null -w "%{url_effective}" "$url")
		local final_curl_exit=$?

		# If fetching the final URL fails, fallback to the original URL.
		if [ $final_curl_exit -ne 0 ] || [ -z "$final_url" ]; then
			final_url="$url"
		fi
		set -e
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
			echo "," >>"$output_file"
		fi

		echo "  { \"url\": \"${url}\", \"final_url\": \"${final_url}\", \"login_detection\": $detection_json }" >>"$output_file"

		rm -f "$headers_file" "$body_file"
	done

	# Close the JSON array.
	echo "]" >>"$output_file"

	# Clean up any temporary files.
	rm -rf -- "$tmp_dir"
}

##############################################
# Security Compliance and Hygine Checks
##############################################
run_security_compliance() {
	info "[11/15] Analyzing security hygiene using..."
	local output_file="$RUN_DIR/securitycompliance.json"
	local sec_workers="${SEC_WORKERS:-6}"
	if (( sec_workers < 1 )); then
		sec_workers=1
	fi
	local dig_opts=("+time=3" "+tries=1")

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

	# Split httpx results by domain to avoid repeated jq scans.
	local httpx_split_dir
	httpx_split_dir=$(mktemp -d)
	if [ -s "$RUN_DIR/httpx.json" ]; then
		while IFS=$'\t' read -r dom record; do
			[[ -z "$dom" || -z "$record" ]] && continue
			printf '%s\n' "$record" >>"$httpx_split_dir/${dom}.jsonl"
		done < <(jq -rc '[(.input | split(":")[0]), tostring] | @tsv' "$RUN_DIR/httpx.json")
	fi

	process_security_domain() {
		local domain="$1"
		local safe_domain="$2"
		local records_file="$3"
		local out_dir="$4"

		[ -z "$domain" ] && return
		local output_file_path="$out_dir/${safe_domain}.jsonl"
		>"$output_file_path"

		# --- Domain-level DNS Checks ---
		local spf dkim dmarc dnskey dnssec ns txt srv ptr mx soa caa

		spf=$(dig "${dig_opts[@]}" +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" | head -n 1 || true)
		[ -z "$spf" ] && spf="No SPF Record"

		dkim=$(dig "${dig_opts[@]}" +short TXT "default._domainkey.$domain" 2>/dev/null | grep -i "v=DKIM1" | head -n 1 || true)
		[ -z "$dkim" ] && dkim="No DKIM Record"

		dmarc=$(dig "${dig_opts[@]}" +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC1" | head -n 1 || true)
		[ -z "$dmarc" ] && dmarc="No DMARC Record"

		dnskey=$(dig "${dig_opts[@]}" +short DNSKEY "$domain" 2>/dev/null || true)
		if [ -z "$dnskey" ]; then
			dnssec="DNSSEC Not Enabled"
		else
			dnssec="DNSSEC Enabled"
		fi

		ns=$(dig "${dig_opts[@]}" +short NS "$domain" 2>/dev/null || true)
		[ -z "$ns" ] && ns="No NS records found"

		txt=$(dig "${dig_opts[@]}" +short TXT "$domain" 2>/dev/null || true)
		[ -z "$txt" ] && txt="No TXT records found"

		srv=$(dig "${dig_opts[@]}" +short SRV "$domain" 2>/dev/null || true)
		[ -z "$srv" ] && srv="No SRV records found"

		local a_record ptr=""
		a_record=$(dig "${dig_opts[@]}" +short A "$domain" 2>/dev/null | head -n 1)
		if [ -n "$a_record" ]; then
			ptr=$(dig "${dig_opts[@]}" +short -x "$a_record" 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true)
		fi
		[ -z "$ptr" ] && ptr="No PTR record found"

		mx=$(dig "${dig_opts[@]}" +short MX "$domain" 2>/dev/null || true)
		[ -z "$mx" ] && mx="No MX records found"

		soa=$(dig "${dig_opts[@]}" +short SOA "$domain" 2>/dev/null || true)
		[ -z "$soa" ] && soa="No SOA record found"

		caa=$(dig "${dig_opts[@]}" +short CAA "$domain" 2>/dev/null || true)
		[ -z "$caa" ] && caa="No CAA records found"

		local record_found=false
		if [[ -f "$records_file" ]]; then
			while IFS= read -r record_line || [ -n "$record_line" ]; do
				[[ -z "$record_line" ]] && continue
				record_found=true
				local url host port
				url=$(jq -r '.url' <<<"$record_line")
				if [[ "$url" =~ ^https://([^:/]+):?([0-9]*) ]]; then
					host="${BASH_REMATCH[1]}"
					port="${BASH_REMATCH[2]:-443}"
				else
					host=""
					port=""
				fi

				local ssl_version ssl_issuer cert_expiry
				if [ -n "$host" ]; then
					local ssl_output cert
					ssl_output=$(echo | timeout 7 openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null || true)
					cert=$(echo "$ssl_output" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)
					if [ -n "$cert" ]; then
						ssl_version=$(echo "$ssl_output" | grep -i "Protocol:" | head -1 | awk -F": " '{print $2}' || true)
						[ -z "$ssl_version" ] && ssl_version="Unknown"
						ssl_issuer=$(echo "$cert" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //' || true)
						[ -z "$ssl_issuer" ] && ssl_issuer="N/A"
						cert_expiry=$(echo "$cert" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
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

				local headers
				headers=$(curl -s --max-time 15 --connect-timeout 5 -D - "$url" -o /dev/null || true)
				local sts xfo csp xss rp pp acao
				sts=$(echo "$headers" | grep -i "Strict-Transport-Security:" | cut -d':' -f2- | xargs || true)
				xfo=$(echo "$headers" | grep -i "X-Frame-Options:" | cut -d':' -f2- | xargs || true)
				csp=$(echo "$headers" | grep -i "Content-Security-Policy:" | cut -d':' -f2- | xargs || true)
				xss=$(echo "$headers" | grep -i "X-XSS-Protection:" | cut -d':' -f2- | xargs || true)
				rp=$(echo "$headers" | grep -i "Referrer-Policy:" | cut -d':' -f2- | xargs || true)
				pp=$(echo "$headers" | grep -i "Permissions-Policy:" | cut -d':' -f2- | xargs || true)
				acao=$(echo "$headers" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs || true)

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
          }' >>"$output_file_path"
			done <"$records_file"
		fi

		if [ "$record_found" = false ]; then
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
        }' >>"$output_file_path"
		fi
	}

	local -a domain_order=()
	while IFS= read -r domain || [ -n "$domain" ]; do
		domain=$(echo "$domain" | tr -d '\r' | xargs)
		[ -z "$domain" ] && continue
		domain_order+=("$domain")

		local safe_domain
		safe_domain=$(echo "$domain" | sed 's/[^A-Za-z0-9._-]/_/g')
		local record_file="$httpx_split_dir/${domain}.jsonl"

		process_security_domain "$domain" "$safe_domain" "$record_file" "$temp_dir" &
		while [ "$(jobs -pr | wc -l | tr -d ' ')" -ge "$sec_workers" ]; do
			sleep 0.1
		done
	done <"$MASTER_SUBS"
	wait

	local records_file="$temp_dir/records.jsonl"
	>"$records_file"
	for domain in "${domain_order[@]}"; do
		local safe_domain
		safe_domain=$(echo "$domain" | sed 's/[^A-Za-z0-9._-]/_/g')
		local part_file="$temp_dir/${safe_domain}.jsonl"
		[ -f "$part_file" ] && cat "$part_file" >>"$records_file"
	done

	rm -rf "$httpx_split_dir"

	# Process each domain from MASTER_SUBS.
	# Combine all JSON records into one JSON array and output to the security compliance file.
	if [ ! -s "$records_file" ]; then
		echo "[]" >"$output_file"
	else
		jq -s '.' "$records_file" >"$output_file"
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
		jq -cs . "$infile" >"$outfile" 2>/dev/null || echo "[]" >"$outfile"
	else
		echo "[]" >"$outfile"
	fi
}

##############################################
# Function: run_api_identification
# Purpose: Identify API endpoints based on simple pattern matching in domain names.
##############################################
run_api_identification() {
	info "[12/15] Identifying API endpoints..."
	local api_file="$RUN_DIR/api_identification.json"
	# Begin JSON array output
	echo "[" >"$api_file"
	local first_entry=true
	while read -r domain; do
		# Check if the domain name contains common API-related strings.
		if echo "$domain" | grep -E -i '(\.api\.|-api-|-api\.)' >/dev/null; then
			api_status="Yes"
		else
			api_status="No"
		fi
		if [ "$first_entry" = true ]; then
			first_entry=false
		else
			echo "," >>"$api_file"
		fi
		echo "  { \"domain\": \"${domain}\", \"api_endpoint\": \"${api_status}\" }" >>"$api_file"
	done <"$MASTER_SUBS"
	echo "]" >>"$api_file"
}

##############################################
# Function: run_colleague_identification
# Purpose: Identify endpoints intended for internal/colleague use based on keywords in domain names.
##############################################
run_colleague_identification() {
	info "[13/15] Identifying colleague-facing endpoints..."
	local colleague_file="$RUN_DIR/colleague_identification.json"
	local keywords_file="colleague_keywords.txt"

	if [ ! -f "$keywords_file" ]; then
		warning "Keywords file '$keywords_file' not found. Skipping."
		echo "[]" >"$colleague_file"
		return
	fi
	# Read all keywords from the file into the 'tokens' array
	mapfile -t tokens <"$keywords_file"
	echo "[" >"$colleague_file"
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
			echo "," >>"$colleague_file"
		fi
		echo "  { \"domain\": \"${domain}\", \"colleague_endpoint\": \"${found}\" }" >>"$colleague_file"
	done <"$MASTER_SUBS"
	echo "]" >>"$colleague_file"
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
	info "[14/15] Building HTML report with analytics..."
	combine_json "$RUN_DIR/dnsx.json" "$RUN_DIR/dnsx_merged.json"
	combine_json "$RUN_DIR/naabu.json" "$RUN_DIR/naabu_merged.json"
	combine_json "$RUN_DIR/httpx.json" "$RUN_DIR/httpx_merged.json"
	mv "$RUN_DIR/dnsx_merged.json" "$RUN_DIR/dnsx.json"
	mv "$RUN_DIR/naabu_merged.json" "$RUN_DIR/naabu.json"
	mv "$RUN_DIR/httpx_merged.json" "$RUN_DIR/httpx.json"

	cat header.html >report.html
	echo -n "const dnsxData = " >>report.html
	cat $RUN_DIR/dnsx.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const naabuData = " >>report.html
	cat $RUN_DIR/naabu.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const httpxData = " >>report.html
	cat $RUN_DIR/httpx.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const loginData = " >>report.html
	cat $RUN_DIR/login.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const secData = " >>report.html
	echo "" >>report.html
	cat $RUN_DIR/securitycompliance.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const apiData = " >>report.html
	cat $RUN_DIR/api_identification.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const colleagueData = " >>report.html
	cat $RUN_DIR/colleague_identification.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const katanaData = " >>report.html
	cat $RUN_DIR/katana_links.json | tr -d "\n" >>report.html
	echo "" >>report.html

	cat footer.html >>report.html
	sed -i.bak '/%%SCREENSHOT_MAP%%/{
    r '"$RUN_DIR/screenshot_map.json"'
    d
  }' report.html && rm -f report.html.bak

	mkdir -p "$RUN_DIR/assets"
	cp assets/report.css "$RUN_DIR/assets/report.css"

	mv report.html $RUN_DIR/

	info "[15/15] Report generated at $RUN_DIR/report.html"
}

##############################################
# Function: show_summary
# Purpose: Display a final summary table of the recon results.
##############################################
show_summary() {
	local combined_pre_dedup=$((CHAOS_COUNT + SUBFINDER_COUNT + ASSETFINDER_COUNT + CRT_COUNT + GAU_COUNT))
	local final_subdomains_count
	final_subdomains_count=$(wc -l <"$MASTER_SUBS")
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
	check_dependencies
	run_chaos
	run_subfinder
	if ! run_assetfinder; then
		warning "Assetfinder step encountered an error and was skipped."
	fi
	if ! run_crtsh; then
		warning "crt.sh lookup step encountered an error and was skipped."
	fi
	if ! run_gau; then
		warning "GAU step encountered an error and was skipped."
	fi
	info "[5/15] Merging subdomains..."
	# Append each primary domain and its www subdomain to ALL_TEMP.
	while read -r domain; do
		echo "$domain" >>"$ALL_TEMP"
		echo "www.$domain" >>"$ALL_TEMP"
	done <"$PRIMARY_DOMAINS_FILE"
	sort -u "$ALL_TEMP" >"$MASTER_SUBS"
	rm -f "$ALL_TEMP"
	run_dnsx
	run_naabu
	run_httpx
	run_katana
	[[ -d output/response ]] && mv output/response "$RUN_DIR/"
	[[ -d output/screenshot ]] && mv output/screenshot "$RUN_DIR/"
	gather_screenshots
	run_login_detection
	run_security_compliance
	run_api_identification
	run_colleague_identification
	build_html_report
	show_summary
}
# Entry point
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
