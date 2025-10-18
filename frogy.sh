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

declare -A CLOUD_IP_ASN_CACHE=()
declare -A CLOUD_IP_PROVIDER_CACHE=()
declare -A CLOUD_IP_NETWORK_CACHE=()
declare -A CLOUD_IP_PTR_CACHE=()
declare -A CLOUD_CNAME_CACHE=()

##############################################
# Function: check_dependencies
# Purpose: Verify all required external tools are installed before starting.
##############################################
check_dependencies() {
	info "Verifying required tools..."
	local missing_tools=()
	# Add ALL external commands used in the script to this list
	local required_tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx" "katana" "jq" "curl" "whois" "dig" "openssl" "tlsx" "xargs" "unzip" "grep" "sed" "awk")

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
# Port catalogue for Naabu scans (top ports + category coverage)
##############################################
PORT_SPEC_FILE="assets/port-spec.txt"

generate_port_list() {
	local outfile="$1"
	local spec_file="$PORT_SPEC_FILE"
	local tmp
	tmp=$(mktemp)
	: >"$tmp"
	if [[ -f "$spec_file" ]]; then
		while IFS= read -r raw_spec; do
			local spec
			spec=$(echo "$raw_spec" | tr -d '[:space:]')
			[[ -z "$spec" || "$spec" == \#* ]] && continue
			if [[ "$spec" =~ ^([0-9]+)-([0-9]+)$ ]]; then
				local start=${BASH_REMATCH[1]}
				local end=${BASH_REMATCH[2]}
				if ((start <= end)); then
					for ((port=start; port<=end; port++)); do
						echo "$port" >>"$tmp"
					done
				fi
			elif [[ "$spec" =~ ^[0-9]+$ ]]; then
				echo "$spec" >>"$tmp"
			else
				warning "Skipping invalid port specification '$raw_spec' in $spec_file"
			fi
		done <"$spec_file"
	else
		warning "Port specification file '$spec_file' not found. Falling back to default top ports."
		local -a fallback_ports=("7" "9" "13" "21-23" "25-26" "37" "53" "79-81" "88" "106" "110-111" "113" "119" "135" "139" "143-144" "179" "199" "389" "427" "443-445" "465" "513-515" "543-544" "548" "554" "587" "631" "646" "873" "990" "993" "995" "1025-1029" "1110" "1433" "1720" "1723" "1755" "1900" "2000-2001" "2049" "2121" "2717" "3000" "3128" "3306" "3389" "3986" "4899" "5000" "5009" "5051" "5060" "5101" "5190" "5357" "5432" "5631" "5666" "5800" "5900" "6000-6001" "6646" "7070" "8000" "8008-8009" "8080-8081" "8443" "8888" "9100" "9999-10000" "32768" "49152-49157")
		for f_spec in "${fallback_ports[@]}"; do
			if [[ "$f_spec" =~ ^([0-9]+)-([0-9]+)$ ]]; then
				local start=${BASH_REMATCH[1]}
				local end=${BASH_REMATCH[2]}
				for ((port=start; port<=end; port++)); do
					echo "$port" >>"$tmp"
				done
			else
				echo "$f_spec" >>"$tmp"
			fi
		done
	fi
	sort -n "$tmp" | uniq >"$outfile"
	rm -f "$tmp"
}

join_unique() {
	local delimiter="$1"
	shift
	if (( $# == 0 )); then
		echo ""
		return
	fi
	local -A seen=()
	local -a unique=()
	local item trimmed
	for item in "$@"; do
		trimmed=$(echo "$item" | tr -d '\r' | xargs)
		[[ -z "$trimmed" ]] && continue
		if [[ -z "${seen[$trimmed]:-}" ]]; then
			seen[$trimmed]=1
			unique+=("$trimmed")
		fi
	done
	if (( ${#unique[@]} == 0 )); then
		echo ""
		return
	fi
	local IFS="$delimiter"
	printf '%s' "${unique[*]}"
}

normalize_hostname() {
	local value="$1"
	value=$(echo "$value" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
	value=${value%.}
	echo "$value"
}

enrich_cloud_ip_metadata() {
	local ip="$1"
	[[ -z "$ip" ]] && return
	if [[ -n "${CLOUD_IP_ASN_CACHE[$ip]:-}" ]]; then
		return
	fi
	local ptr=""
	ptr=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | paste -sd ', ' -)
	CLOUD_IP_PTR_CACHE[$ip]="${ptr:-}"

	local cymru_line
	cymru_line=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | awk -F'|' '
		NR>1 && $1 ~ /[0-9]/ {
			for(i=1;i<=NF;i++) gsub(/^[ \t]+|[ \t]+$/, "", $i);
			printf "%s|%s|%s\n",$1,$3,$7;
			exit
		}')

	local asn="" provider="" network=""
	if [[ -n "$cymru_line" ]]; then
		asn=$(echo "$cymru_line" | cut -d'|' -f1)
		network=$(echo "$cymru_line" | cut -d'|' -f2)
		provider=$(echo "$cymru_line" | cut -d'|' -f3)
	fi

	local whois_tmp
	whois_tmp=$(mktemp)
	whois "$ip" >"$whois_tmp" 2>/dev/null || true

	if [[ -z "$network" ]]; then
		network=$(awk -F: '/^[Cc][Ii][Dd][Rr]/ {print $2; exit}' "$whois_tmp" | xargs)
		if [[ -z "$network" ]]; then
			network=$(awk -F: '/^NetRange/ {print $2; exit}' "$whois_tmp" | xargs)
		fi
	fi
	if [[ -z "$asn" ]]; then
		asn=$(awk -F: '/^origin/ {print $2; exit}' "$whois_tmp" | xargs)
	fi
	if [[ -z "$provider" ]]; then
		provider=$(awk -F: '/^(OrgName|Org-name|descr|owner)/ {print $2; exit}' "$whois_tmp" | xargs)
	fi
	rm -f "$whois_tmp"

	if [[ -n "$asn" && "$asn" != AS* ]]; then
		asn="AS${asn}"
	fi

	CLOUD_IP_ASN_CACHE[$ip]="${asn:-}"
	CLOUD_IP_PROVIDER_CACHE[$ip]="${provider:-}"
	CLOUD_IP_NETWORK_CACHE[$ip]="${network:-}"
	if [[ -z "${CLOUD_IP_PTR_CACHE[$ip]:-}" ]]; then
		CLOUD_IP_PTR_CACHE[$ip]=""
	fi
}

get_cloud_cname_chain() {
	local host="$1"
	[[ -z "$host" ]] && return
	local key
	key=$(normalize_hostname "$host")
	local cached="${CLOUD_CNAME_CACHE[$key]:-__missing__}"
	if [[ "$cached" != "__missing__" ]]; then
		if [[ -z "$cached" ]]; then
			return
		fi
		IFS='|' read -r -a cached_parts <<<"$cached"
		printf '%s\n' "${cached_parts[@]}"
		return
	fi
	local current="$host"
	local -a chain=()
	local depth=0
	while (( depth < 10 )); do
		local next
		next=$(dig +short CNAME "$current" 2>/dev/null | head -n 1 | tr -d '\r')
		next=$(echo "$next" | tr -d '[:space:]')
		next=${next%.}
		if [[ -z "$next" ]]; then
			break
		fi
		chain+=("$next")
		if [[ "$(normalize_hostname "$next")" == "$(normalize_hostname "$current")" ]]; then
			break
		fi
		current="$next"
		depth=$((depth + 1))
	done
	if (( ${#chain[@]} )); then
		local joined
		joined=$(printf '%s|' "${chain[@]}")
		joined=${joined%|}
		CLOUD_CNAME_CACHE[$key]="$joined"
	else
		CLOUD_CNAME_CACHE[$key]=""
	fi
	printf '%s\n' "${chain[@]}"
}

classify_cloud_asset() {
	local host="$1"
	local target="$2"
	local tech_blob="$3"
	local cdn_blob="$4"
	local asn_blob="$5"
	local rdns_blob="$6"
	local tls_blob="$7"

	local resource_type="Other"
	local cloud_provider="Unknown"
	local service_family="Unknown"
	local load_balancer="N/A"
	local waf="Unknown"
	local storage="N/A"

	local lower_target lower_tech lower_cdn lower_asn lower_rdns lower_tls
	lower_target=$(normalize_hostname "$target")
	lower_tech=$(echo "$tech_blob" | tr '[:upper:]' '[:lower:]')
	lower_cdn=$(echo "$cdn_blob" | tr '[:upper:]' '[:lower:]')
	lower_asn=$(echo "$asn_blob" | tr '[:upper:]' '[:lower:]')
	lower_rdns=$(echo "$rdns_blob" | tr '[:upper:]' '[:lower:]')
	lower_tls=$(echo "$tls_blob" | tr '[:upper:]' '[:lower:]')

	if [[ -n "$lower_target" ]]; then
		case "$lower_target" in
			*.cloudfront.net)
				resource_type="CDN"
				cloud_provider="AWS"
				service_family="CloudFront"
				waf="CloudFront Edge"
				;;
			*.s3.amazonaws.com|*.s3-website-*.amazonaws.com|*s3.*.amazonaws.com*)
				resource_type="Object Storage"
				cloud_provider="AWS"
				service_family="S3"
				storage="AWS S3"
				;;
			*.elb.amazonaws.com)
				resource_type="Load Balancer"
				cloud_provider="AWS"
				service_family="Elastic Load Balancing"
				load_balancer="AWS ELB | ${target:-Unknown}"
				;;
			*.execute-api.*.amazonaws.com)
				resource_type="API Gateway/Serverless Edge"
				cloud_provider="AWS"
				service_family="API Gateway"
				;;
			*.blob.core.windows.net)
				resource_type="Object Storage"
				cloud_provider="Azure"
				service_family="Blob Storage"
				storage="Azure Blob Storage"
				;;
			*.azureedge.net|*.azurefd.net)
				resource_type="CDN"
				cloud_provider="Azure"
				service_family="Azure Front Door"
				waf="Azure Front Door"
				;;
			*.trafficmanager.net)
				resource_type="Load Balancer"
				cloud_provider="Azure"
				service_family="Traffic Manager"
				load_balancer="Azure Traffic Manager | ${target:-Unknown}"
				;;
			*.azurewebsites.net)
				resource_type="PaaS Web App"
				cloud_provider="Azure"
				service_family="App Service"
				;;
			*.appspot.com|*.r.appspot.com)
				resource_type="PaaS Web App"
				cloud_provider="GCP"
				service_family="App Engine"
				;;
			*.run.app|*.cloudfunctions.net)
				resource_type="API Gateway/Serverless Edge"
				cloud_provider="GCP"
				service_family="Cloud Run"
				;;
			*.storage.googleapis.com)
				resource_type="Object Storage"
				cloud_provider="GCP"
				service_family="Cloud Storage"
				storage="GCP Cloud Storage"
				;;
			*.vercel.app)
				resource_type="PaaS Web App"
				cloud_provider="Vercel"
				service_family="Vercel Hosting"
				;;
			*.netlify.app)
				resource_type="PaaS Web App"
				cloud_provider="Netlify"
				service_family="Netlify Hosting"
				;;
			*.herokuapp.com)
				resource_type="PaaS Web App"
				cloud_provider="Heroku"
				service_family="Heroku"
				;;
			*.fly.dev)
				resource_type="PaaS Web App"
				cloud_provider="Fly.io"
				service_family="Fly.io Apps"
				;;
		*.fastly.net|*.fastlylb.net)
			resource_type="CDN"
			cloud_provider="Fastly"
			service_family="Fastly CDN"
			waf="Fastly"
			;;
		*akamaihd.net|*.edgekey.net|*.edgesuite.net|*.akamai.net)
			resource_type="CDN"
			cloud_provider="Akamai"
			service_family="Akamai CDN"
			waf="Akamai"
			;;
		*.cdn.cloudflare.net|*.cloudflare.net|*.cloudflare.com)
			resource_type="CDN"
			cloud_provider="Cloudflare"
			service_family="Cloudflare CDN"
			waf="Cloudflare"
			;;
		*.oraclecloud.com)
				if [[ "$lower_target" == *"objectstorage"* ]]; then
					resource_type="Object Storage"
					cloud_provider="Oracle"
					service_family="Oracle Object Storage"
					storage="Oracle Object Storage"
				else
					resource_type="Other"
					cloud_provider="Oracle"
					service_family="Oracle Cloud"
				fi
				;;
		esac
	fi

	if [[ "$resource_type" == "Other" ]]; then
		if echo "$lower_tls" | grep -q "cloudfront.net"; then
			resource_type="CDN"
			cloud_provider="AWS"
			service_family="CloudFront"
			waf="CloudFront Edge"
		elif echo "$lower_tls" | grep -q "azureedge.net"; then
			resource_type="CDN"
			cloud_provider="Azure"
			service_family="Azure CDN"
			waf="Azure Front Door"
		elif echo "$lower_tls" | grep -q "fastly.net"; then
			resource_type="CDN"
			cloud_provider="Fastly"
			service_family="Fastly CDN"
			waf="Fastly"
		elif echo "$lower_tls" | grep -q "cdn.cloudflare.net"; then
			resource_type="CDN"
			cloud_provider="Cloudflare"
			service_family="Cloudflare CDN"
			waf="Cloudflare"
		fi
	fi
	if [[ "$resource_type" == "Other" ]]; then
		if echo "$lower_rdns" | grep -q "cloudfront.net"; then
			resource_type="CDN"
			cloud_provider="AWS"
			service_family="CloudFront"
			waf="CloudFront Edge"
		elif echo "$lower_rdns" | grep -q "akamai"; then
			resource_type="CDN"
			cloud_provider="Akamai"
			service_family="Akamai CDN"
			waf="Akamai"
		elif echo "$lower_rdns" | grep -q "fastly"; then
			resource_type="CDN"
			cloud_provider="Fastly"
			service_family="Fastly CDN"
			waf="Fastly"
		elif echo "$lower_rdns" | grep -q "cloudflare"; then
			resource_type="CDN"
			cloud_provider="Cloudflare"
			service_family="Cloudflare CDN"
			waf="Cloudflare"
		fi
	fi

	if echo "$lower_cdn" | grep -q "cloudflare"; then
		waf="Cloudflare"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Cloudflare"
			service_family="Cloudflare CDN"
		fi
	elif echo "$lower_cdn" | grep -q "akamai"; then
		waf="Akamai"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Akamai"
			service_family="Akamai CDN"
		fi
	elif echo "$lower_cdn" | grep -q "fastly"; then
		waf="Fastly"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Fastly"
			service_family="Fastly CDN"
		fi
	elif echo "$lower_cdn" | grep -q "cloudfront"; then
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="AWS"
			service_family="CloudFront"
		fi
		waf="CloudFront Edge"
	elif echo "$lower_cdn" | grep -q "azure"; then
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Azure"
			service_family="Azure CDN"
		fi
	fi

	if echo "$lower_tech" | grep -q "cloudflare"; then
		waf="Cloudflare"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Cloudflare"
			service_family="Cloudflare CDN"
		fi
	fi
	if echo "$lower_tech" | grep -q "front door"; then
		waf="Azure Front Door"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Azure"
			service_family="Azure Front Door"
		fi
	fi
	if echo "$lower_tech" | grep -q "cloudfront"; then
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="AWS"
			service_family="CloudFront"
		fi
		waf="CloudFront Edge"
	fi
	if echo "$lower_tech" | grep -q "akamai"; then
		waf="Akamai"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Akamai"
			service_family="Akamai CDN"
		fi
	fi
	if echo "$lower_tech" | grep -q "fastly"; then
		waf="Fastly"
		if [[ "$resource_type" == "Other" ]]; then
			resource_type="CDN"
			cloud_provider="Fastly"
			service_family="Fastly CDN"
		fi
	fi

	if [[ "$cloud_provider" == "Unknown" ]]; then
		if echo "$lower_asn" | grep -qE "amazon|aws"; then
			cloud_provider="AWS"
		elif echo "$lower_asn" | grep -q "microsoft"; then
			cloud_provider="Azure"
		elif echo "$lower_asn" | grep -q "google"; then
			cloud_provider="GCP"
		elif echo "$lower_asn" | grep -q "cloudflare"; then
			cloud_provider="Cloudflare"
		elif echo "$lower_asn" | grep -q "fastly"; then
			cloud_provider="Fastly"
		elif echo "$lower_asn" | grep -q "akamai"; then
			cloud_provider="Akamai"
		elif echo "$lower_asn" | grep -q "digitalocean"; then
			cloud_provider="DigitalOcean"
		elif echo "$lower_asn" | grep -q "oracle"; then
			cloud_provider="Oracle"
		elif echo "$lower_asn" | grep -q "ibm"; then
			cloud_provider="IBM"
		elif echo "$lower_asn" | grep -q "hetzner"; then
			cloud_provider="Hetzner"
		fi
	fi

	if [[ "$resource_type" == "Other" && "$cloud_provider" != "Unknown" ]]; then
		resource_type="Other"
		service_family="${cloud_provider} Cloud"
	fi

	if [[ "$resource_type" == "CDN" && "$waf" == "Unknown" && "$cloud_provider" != "Unknown" ]]; then
		waf="$cloud_provider"
	fi

	if [[ "$resource_type" == "Object Storage" && "$waf" == "Unknown" ]]; then
		waf="Direct Origin"
	fi

	if [[ "$storage" == "N/A" && "$resource_type" == "Object Storage" ]]; then
		storage="${cloud_provider} Object Storage"
	fi

	printf '%s|%s|%s|%s|%s|%s' "$resource_type" "$cloud_provider" "$service_family" "$load_balancer" "$waf" "$storage"
}

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
		info "[1/17] Running Subfinder..."
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
info "[2/17] Running Assetfinder..."
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
info "[3/17] Running crt.sh..."
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
info "[4/17] Running GAU…"

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
		info "[6/17] Running dnsx..."
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

# Function: run_naabu
# Purpose: Run naabu port scanner against discovered subdomains.
##############################################
run_naabu() {
	if [[ "$USE_NAABU" == "true" ]]; then
		info "[7/17] Running naabu..."
		if [ ! -s "$MASTER_SUBS" ]; then
			warning "Master subdomains file is empty. Skipping naabu."
			return
		fi
		local port_file="$RUN_DIR/naabu_ports.txt"
		generate_port_list "$port_file"
        local port_list
        port_list=$(paste -sd, "$port_file")
		if [[ -z "$port_list" ]]; then
			warning "Port list generation returned empty set; falling back to default top 100 set."
			port_list="7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,548,554,587,631,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1521,1723,1900,2000,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
		fi
		local -a naabu_base_args=(
			-silent
			-l "$MASTER_SUBS"
			-p "$port_list"
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
	generate_portscan_summary
}

##############################################
# Function: generate_portscan_summary
# Purpose: Consolidate raw naabu output into per-IP structures consumed by the report.
##############################################
generate_portscan_summary() {
	local naabu_raw="$RUN_DIR/naabu.json"
	local portscan_file="$RUN_DIR/portscan.json"
	if [[ -s "$naabu_raw" ]]; then
		if ! jq -s '
			map(select((.ip // "") != "" and (.port // "") != "")) |
			group_by(.ip) |
			map({
				ip: .[0].ip,
				sources: (map(.host) | map(select(. != null and . != "")) | unique | sort),
				services: (
					group_by(.port) |
					map({
						port: (.[0].port | tonumber? // .[0].port),
						protocol: (.[0].protocol // "tcp"),
						hosts: (map(.host) | map(select(. != null and . != "")) | unique | sort)
					}) | sort_by(.port)
				)
			}) | sort_by(.ip)
		' "$naabu_raw" >"$portscan_file"; then
			warning "Failed to consolidate naabu output; writing empty portscan dataset."
			echo "[]" >"$portscan_file"
		fi
	else
		echo "[]" >"$portscan_file"
	fi
}

##############################################
# Function: generate_ip_intel
# Purpose: Build PTR, ASN, and network metadata for discovered IPs.
##############################################
generate_ip_intel() {
	local intel_file="$RUN_DIR/ip_enrichment.json"
	local ip_candidates="$RUN_DIR/ip_candidates.txt"
	>"$ip_candidates"

	if [[ -s "$RUN_DIR/dnsx.json" ]]; then
		jq -r '.a[]?, .aaaa[]?' "$RUN_DIR/dnsx.json" 2>/dev/null >>"$ip_candidates"
	fi
	if [[ -s "$RUN_DIR/portscan.json" ]]; then
		jq -r '.[].ip' "$RUN_DIR/portscan.json" 2>/dev/null >>"$ip_candidates"
	fi
	if [[ -s "$MASTER_SUBS" ]]; then
		awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || /:/' "$MASTER_SUBS" >>"$ip_candidates"
	fi

	if [[ ! -s "$ip_candidates" ]]; then
		echo "[]" >"$intel_file"
		return
	fi

	sort -u "$ip_candidates" | sed '/^$/d' >"$ip_candidates.sorted"
	mv "$ip_candidates.sorted" "$ip_candidates"

	echo "[" >"$intel_file"
	local first_entry=true
	while IFS= read -r ip; do
		[[ -z "$ip" ]] && continue
		local ptr_records
		local ptr_raw
		ptr_raw=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' || true)
		if [[ -n "$ptr_raw" ]]; then
			ptr_records=$(printf '%s\n' "$ptr_raw" | paste -sd ', ' -)
		else
			ptr_records=""
		fi

		local cymru_line=""
		local cymru_output
		cymru_output=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null || true)
		if [[ -n "$cymru_output" ]]; then
			cymru_line=$(printf '%s\n' "$cymru_output" | awk -F'|' '
				NR>1 && $1 ~ /[0-9]/ {
					for(i=1;i<=NF;i++) gsub(/^[ \t]+|[ \t]+$/, "", $i);
					printf "%s|%s|%s\n",$1,$3,$7;
					exit
				}' || true)
		fi

		local asn="" network="" provider=""
		if [[ -n "$cymru_line" ]]; then
			asn=$(echo "$cymru_line" | cut -d'|' -f1)
			network=$(echo "$cymru_line" | cut -d'|' -f2)
			provider=$(echo "$cymru_line" | cut -d'|' -f3)
		fi

		local whois_file
		whois_file=$(mktemp)
		whois "$ip" >"$whois_file" 2>/dev/null || true

		if [[ -z "$network" ]]; then
			network=$(awk -F: '/^[Cc][Ii][Dd][Rr]/ {print $2; exit}' "$whois_file" | xargs)
			if [[ -z "$network" ]]; then
				network=$(awk -F: '/^NetRange/ {print $2; exit}' "$whois_file" | xargs)
			fi
		fi
		if [[ -z "$asn" ]]; then
			asn=$(awk -F: '/^origin/ {print $2; exit}' "$whois_file" | xargs)
		fi
		if [[ -z "$provider" ]]; then
			provider=$(awk -F: '/^(OrgName|Org-name|descr|owner)/ {print $2; exit}' "$whois_file" | xargs)
		fi
		rm -f "$whois_file"

		if [[ -n "$asn" && "$asn" != AS* ]]; then
			asn="AS${asn}"
		fi

		local json_entry
		json_entry=$(jq -n \
			--arg ip "$ip" \
			--arg ptr "${ptr_records:-}" \
			--arg asn "${asn:-}" \
			--arg provider "${provider:-}" \
			--arg network "${network:-}" \
			'{
				ip: $ip,
				ptr: ($ptr | select(length>0)),
				asn: ($asn | select(length>0)),
				provider: ($provider | select(length>0)),
				network: ($network | select(length>0))
			}')

		if [[ "$first_entry" == true ]]; then
			first_entry=false
		else
			echo "," >>"$intel_file"
		fi
		echo "  $json_entry" >>"$intel_file"
	done <"$ip_candidates"
	echo "]" >>"$intel_file"
	rm -f "$ip_candidates"
}

##############################################
# Function: run_httpx
# Purpose: Run httpx to probe live web endpoints using the ports identified.
##############################################
run_httpx() {
	if [[ "$USE_HTTPX" == "true" ]]; then
		info "[8/17] Running httpx..."
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
info "[9/17] Crawling links with Katana..."
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
info "[10/17] Detecting Login panels..."
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

run_tls_inventory() {
	info "[11/17] Building TLS certificate inventory..."
	local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
	local tls_json="$RUN_DIR/tls_inventory.json"
	local tlsx_raw="$RUN_DIR/tls_inventory_raw.jsonl"
	local tlsx_log="$RUN_DIR/logs/tlsx.log"

	if [[ ! -s "$final_urls_ports" ]]; then
		info "No open ports detected; TLS inventory will be empty."
		echo "[]" >"$tls_json"
		return
	fi

	if ! tlsx -l "$final_urls_ports" -j >"$tlsx_raw" 2>>"$tlsx_log"; then
		warning "tlsx scan failed; TLS inventory will be empty. Check $tlsx_log for details."
		echo "[]" >"$tls_json"
		rm -f "$tlsx_raw"
		return
	fi

	if ! jq -cs '
		def normalize_port($raw):
			($raw // "" | tostring) as $p
			| if ($p | length) == 0 then "443" else $p end;
		def bracket_host($h):
			($h // "") as $host
			| if ($host | length) == 0 then ""
			  elif (($host | contains(":")) and (($host | startswith("[")) | not) and (($host | endswith("]")) | not))
			  then "[" + $host + "]"
			  else $host
			  end;
		def format_tls_version($v):
			if $v == null or $v == "" then ""
			elif $v == "tls13" then "TLS 1.3"
			elif $v == "tls12" then "TLS 1.2"
			elif $v == "tls11" then "TLS 1.1"
			elif $v == "tls10" then "TLS 1.0"
			elif $v == "ssl30" then "SSL 3.0"
			else $v
			end;
		map(
			{
				Host: (.host // ""),
				IP: (.ip // ""),
				Port: normalize_port(.port),
				Timestamp: (.timestamp // ""),
				ProbeStatus: (.probe_status // false),
				TLSVersion: format_tls_version(.tls_version // ""),
				Cipher: (.cipher // ""),
				NotBefore: (.not_before // ""),
				NotAfter: (.not_after // ""),
				SubjectDN: (.subject_dn // ""),
				SubjectCN: (.subject_cn // ""),
				SubjectAN: (.subject_an // [] | map(select(. != null and . != ""))),
				Serial: (.serial // ""),
				IssuerDN: (.issuer_dn // ""),
				IssuerCN: (.issuer_cn // ""),
				IssuerOrg: (.issuer_org // [] | map(select(. != null and . != ""))),
				TLSConnection: (.tls_connection // ""),
				SNI: (.sni // "")
			}
			| .EndpointURL = (
				if .Host == "" then ""
				else "https://" + bracket_host(.Host) + (if .Port == "443" then "" else ":" + .Port end)
				end
			)
			| .DaysUntilExpiry = (
				(.NotAfter // "") as $na
				| if ($na | length) == 0 then null
				  else
					($na | fromdateiso8601? // null) as $exp
					| if $exp then ((($exp - now) / 86400) | floor)
					  else null
					  end
				  end
			)
			| .HighestVersion = (.TLSVersion // "")
			| .VersionSummary = (.TLSVersion // "")
			| .CertificateIssuer = (.IssuerDN // .IssuerCN // "")
			| .ValidFrom = (.NotBefore // "")
			| .ValidTo = (.NotAfter // "")
			| .Domain = (.Host // "")
			| .DeprecatedVersions = []
			| .CertificateSubjectSummary = (.SubjectCN // "")
			| .CertificateSubjectDN = (.SubjectDN // "")
			| .CertificateCommonName = (.SubjectCN // "")
			| .CertificateSANs = .SubjectAN
			| .PerfectForwardSecrecy = ""
			| .CipherStrength = ""
			| .CertificateTransparency = ""
			| .WeakCiphers = []
			| .Notes = ""
			| .HandshakeError = (if .ProbeStatus then "N/A" else "Handshake failed" end)
			| .HostnameValidationSupported = ""
			| .SANSummary = (if (.SubjectAN | length) > 0 then (.SubjectAN | join(", ")) else "" end)
		)
	' "$tlsx_raw" >"$tls_json"; then
		warning "Failed to process tlsx output; TLS inventory will be empty."
		echo "[]" >"$tls_json"
	fi

	rm -f "$tlsx_raw"
}

##############################################
# Security Compliance and Hygine Checks
##############################################
run_security_compliance() {
	info "[12/17] Analyzing security hygiene using..."
	local compliance_output="$RUN_DIR/securitycompliance.json"
	local headers_output="$RUN_DIR/sec_headers.json"
	local compliance_jsonl="$RUN_DIR/securitycompliance.jsonl"
	local headers_jsonl="$RUN_DIR/sec_headers.jsonl"
	: >"$compliance_jsonl"
	: >"$headers_jsonl"

	local dig_opts=("+time=3" "+tries=1")

	if [ ! -f "$MASTER_SUBS" ]; then
		echo "Error: MASTER_SUBS file not found!" >&2
		return 1
	fi

	local dns_map_file
	dns_map_file=$(mktemp)
	if [[ -s "$RUN_DIR/dnsx.json" ]]; then
		jq -cs '
			[ .[] | if type=="array" then .[] else . end | select(type=="object") ]
			| group_by(((.host // "") | ascii_downcase)) |
			map({
				key: (.[0].host // "" | ascii_downcase),
				value: {
					host: (.[0].host // ""),
					status: (.[0].status_code // ""),
					a: (reduce .[] as $d ([]; . + ($d.a // []) + (($d.raw_resp.Answer // []) | map(select(.Hdr.Rrtype == 1) | .A)))) | unique | map(select(. != null and . != "")),
					cname: (reduce .[] as $d ([]; . + ($d.cname // []) + (($d.raw_resp.Answer // []) | map(select(.Hdr.Rrtype == 5) | .Target)))) | unique | map(select(. != null and . != "")),
					resolver: (reduce .[] as $d ([]; . + ($d.resolver // []))) | unique | map(select(. != null and . != ""))
				}
			}) |
			map(select(.key != "")) |
			from_entries
		' "$RUN_DIR/dnsx.json" >"$dns_map_file" || echo "{}" >"$dns_map_file"
	else
		echo "{}" >"$dns_map_file"
	fi

	local tls_host_map_file
	local tls_endpoint_map_file
	tls_host_map_file=$(mktemp)
	tls_endpoint_map_file=$(mktemp)
	if [[ -s "$RUN_DIR/tls_inventory.json" ]]; then
		jq -c '
			group_by(((.Host // .host // "") | ascii_downcase)) |
			map({ key: (.[0].Host // .[0].host // "" | ascii_downcase), value: . }) |
			map(select(.key != "")) |
			from_entries
		' "$RUN_DIR/tls_inventory.json" >"$tls_host_map_file" || echo "{}" >"$tls_host_map_file"
		jq -c '
			map(select(((.Host // .host // "") | length) > 0 and ((.Port // .port // "") | tostring | length) > 0)) |
			map({
				key: (((.Host // .host // "") | ascii_downcase) + "|" + ((.Port // .port // "") | tostring)),
				value: .
			}) |
			map(select(.key | length > 1)) |
			from_entries
		' "$RUN_DIR/tls_inventory.json" >"$tls_endpoint_map_file" || echo "{}" >"$tls_endpoint_map_file"
	else
		echo "{}" >"$tls_host_map_file"
		echo "{}" >"$tls_endpoint_map_file"
	fi

	local httpx_split_dir
	httpx_split_dir=$(mktemp -d)
	if [ -s "$RUN_DIR/httpx.json" ]; then
		while IFS=$'\t' read -r dom record; do
			dom=$(echo "$dom" | tr -d '\r' | xargs)
			[[ -z "$dom" || -z "$record" ]] && continue
			printf '%s\n' "$record" >>"$httpx_split_dir/${dom}.jsonl"
		done < <(jq -rc '(if type=="array" then .[] else . end) | [((.input // .url // .host // "") | sub("^https?://"; "") | split("/")[0] | split(":")[0]), tostring] | @tsv' "$RUN_DIR/httpx.json")
	fi

	while IFS= read -r domain || [[ -n "$domain" ]]; do
		domain=$(echo "$domain" | tr -d '\r' | xargs)
		[[ -z "$domain" ]] && continue
		local domain_key
		domain_key=$(echo "$domain" | tr '[:upper:]' '[:lower:]')

		local dns_entry
		dns_entry=$(jq -c --arg key "$domain_key" '.[$key] // null' "$dns_map_file")
		local dns_status dns_resolvers dns_a dns_cname
		if [[ "$dns_entry" != "null" ]]; then
			dns_status=$(echo "$dns_entry" | jq -r '.status // ""')
			dns_resolvers=$(echo "$dns_entry" | jq -r '(.resolver // []) | join("\n")')
			dns_a=$(echo "$dns_entry" | jq -r '(.a // []) | join("\n")')
			dns_cname=$(echo "$dns_entry" | jq -r '(.cname // []) | join("\n")')
		else
			dns_status=""
			dns_resolvers=""
			dns_a=""
			dns_cname=""
		fi

		local spf dkim dmarc dnskey dnssec ns txt srv ptr mx soa caa
		local a_records aaaa_records cname_records zone_transfer whois_summary

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
		[ -z "$txt" ] && txt=""

		srv=$(dig "${dig_opts[@]}" +short SRV "$domain" 2>/dev/null || true)
		[ -z "$srv" ] && srv=""

		a_records="$dns_a"
		if [ -z "$a_records" ]; then
			a_records=$(dig "${dig_opts[@]}" +short A "$domain" 2>/dev/null | sed '/^$/d' || true)
		fi

		local a_record=""
		ptr=""
		if [ -n "$a_records" ]; then
			a_record=$(printf '%s\n' "$a_records" | head -n 1)
		fi
		if [ -n "$a_record" ]; then
			ptr=$(dig "${dig_opts[@]}" +short -x "$a_record" 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true)
		fi
		[ -z "$ptr" ] && ptr=""

		aaaa_records=$(dig "${dig_opts[@]}" +short AAAA "$domain" 2>/dev/null | sed '/^$/d' || true)

		cname_records="$dns_cname"
		if [ -z "$cname_records" ]; then
			cname_records=$(dig "${dig_opts[@]}" +short CNAME "$domain" 2>/dev/null | sed '/^$/d' || true)
		fi

		mx=$(dig "${dig_opts[@]}" +short MX "$domain" 2>/dev/null || true)
		[ -z "$mx" ] && mx=""

		soa=$(dig "${dig_opts[@]}" +short SOA "$domain" 2>/dev/null || true)
		[ -z "$soa" ] && soa=""

		caa=$(dig "${dig_opts[@]}" +short CAA "$domain" 2>/dev/null || true)
		[ -z "$caa" ] && caa=""

		zone_transfer="AXFR Not Permitted"
		if [ -z "$ns" ] || [ "$ns" = "No NS records found" ]; then
			zone_transfer="NS data unavailable"
		else
			while IFS= read -r ns_host || [ -n "$ns_host" ]; do
				ns_host=$(echo "$ns_host" | tr -d '\r' | xargs)
				[[ -z "$ns_host" ]] && continue
				ns_host=${ns_host%.}
				local axfr_output
				axfr_output=$(timeout 6 dig +time=5 +tries=1 @"$ns_host" "$domain" AXFR 2>/dev/null | head -n 20 || true)
				if [ -z "$axfr_output" ]; then
					continue
				fi
				if echo "$axfr_output" | grep -qiE 'transfer failed|timed out|refused|denied|not implemented|connection refused|communications error|SERVFAIL'; then
					continue
				fi
				if echo "$axfr_output" | grep -q $'\tIN\t'; then
					zone_transfer="AXFR Permitted via $ns_host"
					break
				fi
			done <<<"$ns"
		fi

		if ! command -v whois >/dev/null 2>&1; then
			whois_summary="WHOIS client unavailable"
		else
			local whois_raw
			whois_raw=$(whois "$domain" 2>/dev/null || true)
			if echo "$whois_raw" | grep -qiE 'limit exceeded|quota exceeded|rate limit|exceeded the maximum number|WHOIS LIMIT'; then
				whois_summary="WHOIS query cap reached"
			elif [ -z "$whois_raw" ]; then
				whois_summary="WHOIS data unavailable"
			else
				local registrar created updated expires registrant_org registrant_country
				for pattern in "Registrar:" "Sponsoring Registrar:" "Registrar Name:"; do
					registrar=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$registrar" ] && break
				done

				for pattern in "Creation Date:" "Created On:" "Domain Registration Date:" "Domain Create Date:" "Registered On:"; do
					created=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$created" ] && break
				done

				for pattern in "Updated Date:" "Last Updated On:" "Domain Last Updated Date:" "Modified:"; do
					updated=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$updated" ] && break
				done

				for pattern in "Expiration Date:" "Expiry Date:" "Registry Expiry Date:" "Registrar Registration Expiration Date:" "Domain Expiration Date:"; do
					expires=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$expires" ] && break
				done

				for pattern in "Registrant Organization:" "OrgName:" "Organisation Name:"; do
					registrant_org=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$registrant_org" ] && break
				done

				for pattern in "Registrant Country:" "Country:"; do
					registrant_country=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
					[ -n "$registrant_country" ] && break
				done

				whois_summary=$(printf "Registrar: %s\nCreated: %s\nUpdated: %s\nExpires: %s\nOrg: %s\nCountry: %s" \
					"${registrar:-Unknown}" "${created:-Unknown}" "${updated:-Unknown}" "${expires:-Unknown}" \
					"${registrant_org:-Unknown}" "${registrant_country:-Unknown}")
			fi
		fi

		local tls_entry ssl_version ssl_issuer cert_expiry
		tls_entry=$(jq -c --arg key "$domain_key" '.[$key] // []' "$tls_host_map_file")
		if [[ "$tls_entry" != "[]" ]]; then
			ssl_version=$(echo "$tls_entry" | jq -r '[.[]? | (.TLSVersion // .HighestVersion // .VersionSummary) | select(. != null and . != "")] | first? // "N/A"')
			ssl_issuer=$(echo "$tls_entry" | jq -r '[.[]? | (.IssuerDN // .CertificateIssuer // .IssuerCN) | select(. != null and . != "")] | first? // "N/A"')
			cert_expiry=$(echo "$tls_entry" | jq -r '[.[]? | (.NotAfter // .ValidTo) | select(. != null and . != "")] | first? // "N/A"')
		else
			ssl_version="N/A"
			ssl_issuer="N/A"
			cert_expiry="N/A"
		fi

		jq -n \
			--arg domain "$domain" \
			--arg url "N/A" \
			--arg spf "$spf" \
			--arg dkim "$dkim" \
			--arg dmarc "$dmarc" \
			--arg dnssec "$dnssec" \
			--arg ns "$ns" \
			--arg txt "$txt" \
			--arg srv "$srv" \
			--arg ptr "$ptr" \
			--arg mx "$mx" \
			--arg soa "$soa" \
			--arg caa "$caa" \
			--arg arecords "$a_records" \
			--arg aaaarecords "$aaaa_records" \
			--arg cname "$cname_records" \
			--arg zonetransfer "$zone_transfer" \
			--arg whois "$whois_summary" \
			--arg ssl_version "$ssl_version" \
			--arg ssl_issuer "$ssl_issuer" \
			--arg cert_expiry "$cert_expiry" \
			--arg dns_status "${dns_status:-}" \
			--arg resolvers "${dns_resolvers:-}" \
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
        "A Records": $arecords,
        "AAAA Records": $aaaarecords,
        "CNAME Records": $cname,
        "Zone Transfer": $zonetransfer,
        "WHOIS Summary": $whois,
        "SSL/TLS Version": $ssl_version,
        "SSL/TLS Issuer": $ssl_issuer,
        "Cert Expiry Date": $cert_expiry,
        "DNS Resolver": $resolvers,
        "DNS Status": $dns_status
      }' >>"$compliance_jsonl"

		local domain_http_file="$httpx_split_dir/${domain}.jsonl"
		if [[ -f "$domain_http_file" ]]; then
			while IFS= read -r record_line || [[ -n "$record_line" ]]; do
				[[ -z "$record_line" ]] && continue
				local url host port
				url=$(jq -r '.url // ""' <<<"$record_line")
				[[ -z "$url" ]] && continue
				if [[ "$url" =~ ^https?://([^/:]+)(:([0-9]+))? ]]; then
					host=${BASH_REMATCH[1]}
					port=${BASH_REMATCH[3]}
				else
					host=""
					port=""
				fi
				if [ -z "$port" ]; then
					if [[ "$url" =~ ^https:// ]]; then
						port="443"
					elif [[ "$url" =~ ^http:// ]]; then
						port="80"
					else
						port="443"
					fi
				fi

				local ssl_version_ep ssl_issuer_ep cert_expiry_ep
				local lookup_host
				lookup_host=$(echo "$host" | tr '[:upper:]' '[:lower:]')
				[[ -z "$lookup_host" ]] && lookup_host="$domain_key"
				local endpoint_lookup="${lookup_host}|${port}"
				local tls_endpoint
				tls_endpoint=$(jq -c --arg key "$endpoint_lookup" '.[$key] // null' "$tls_endpoint_map_file")
				if [[ "$tls_endpoint" != "null" ]]; then
					ssl_version_ep=$(echo "$tls_endpoint" | jq -r '.TLSVersion // .HighestVersion // "Unknown"')
					ssl_issuer_ep=$(echo "$tls_endpoint" | jq -r '.IssuerDN // .CertificateIssuer // .IssuerCN // "N/A"')
					cert_expiry_ep=$(echo "$tls_endpoint" | jq -r '.NotAfter // .ValidTo // "N/A"')
				else
					ssl_version_ep="No SSL/TLS"
					ssl_issuer_ep="N/A"
					cert_expiry_ep="N/A"
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

				jq -n \
					--arg domain "$domain" \
					--arg url "$url" \
					--arg ssl_version "$ssl_version_ep" \
					--arg ssl_issuer "$ssl_issuer_ep" \
					--arg cert_expiry "$cert_expiry_ep" \
					--arg sts "$sts" \
					--arg xfo "$xfo" \
					--arg csp "$csp" \
					--arg xss "$xss" \
					--arg rp "$rp" \
					--arg pp "$pp" \
					--arg acao "$acao" \
					'{
        Domain: $domain,
        URL: $url,
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
      }' >>"$headers_jsonl"
		done <"$domain_http_file"
	fi
	done <"$MASTER_SUBS"

	rm -rf "$httpx_split_dir"
	rm -f "$dns_map_file" "$tls_host_map_file" "$tls_endpoint_map_file"

	combine_json "$compliance_jsonl" "$compliance_output"
	combine_json "$headers_jsonl" "$headers_output"
	rm -f "$compliance_jsonl" "$headers_jsonl"
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
info "[13/17] Identifying API endpoints..."
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
info "[14/17] Identifying colleague-facing endpoints..."
	local colleague_file="$RUN_DIR/colleague_identification.json"
	local keywords_file="colleague_keywords.txt"

	if [ ! -f "$keywords_file" ]; then
		warning "Keywords file '$keywords_file' not found. Skipping."
		echo "[]" >"$colleague_file"
		return
	fi
	# Read all keywords from the file into the 'tokens' array, trimming whitespace.
	mapfile -t raw_tokens <"$keywords_file"
	local -a tokens=()
	for token in "${raw_tokens[@]}"; do
		token=$(echo "$token" | tr -d '\r' | xargs)
		[[ -z "$token" ]] && continue
		tokens+=("$token")
	done
	echo "[" >"$colleague_file"
	local first_entry=true
	while read -r domain; do
		# Convert domain to lowercase for consistent matching.
		local lc_domain
		lc_domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
		local found="No"
		declare -A match_seen=()
		local -a matches=()
		local t
		for t in "${tokens[@]}"; do
			local lt
			lt=$(echo "$t" | tr '[:upper:]' '[:lower:]')
			[[ -z "$lt" ]] && continue
			if [[ "$lc_domain" == *"$lt"* ]]; then
				found="Yes"
				if [[ -z "${match_seen[$lt]:-}" ]]; then
					match_seen[$lt]=1
					matches+=("$t")
				fi
			fi
		done
		unset match_seen
		local matches_json='[]'
		if ((${#matches[@]})); then
			matches_json=$(printf '%s\n' "${matches[@]}" | jq -Rc '[inputs | select(length>0)]')
		fi
		local entry
		entry=$(jq -n --arg domain "$domain" --arg status "$found" --argjson matches "$matches_json" \
			'{ domain: $domain, colleague_endpoint: $status, colleague_matches: $matches }')
		if [ "$first_entry" = true ]; then
			first_entry=false
		else
			echo "," >>"$colleague_file"
		fi
		echo "  ${entry}" >>"$colleague_file"
	done <"$MASTER_SUBS"
	echo "]" >>"$colleague_file"
}

run_cloud_infrastructure_inventory() {
	info "[15/17] Building cloud infrastructure inventory..."
	local output_file="$RUN_DIR/cloud_infrastructure.json"
	local dns_map_file httpx_map_file tls_map_file
	dns_map_file=$(mktemp)
	httpx_map_file=$(mktemp)
	tls_map_file=$(mktemp)

	if [[ -s "$RUN_DIR/dnsx.json" ]]; then
		jq -cs '
			[ .[] | if type=="array" then .[] else . end | select(type=="object") ]
			| map({
				raw: (.host // ""),
				key: ((.host // "") | ascii_downcase),
				value: {
					host: (.host // ""),
					a: (.a // []),
					aaaa: (.aaaa // []),
					cname: (.cname // []),
					status: (.status_code // ""),
					resolver: (.resolver // [])
				}
			})
			| map(select(.key != ""))
			| map({key: .key, value: .value})
			| from_entries
		' "$RUN_DIR/dnsx.json" >"$dns_map_file" || echo "{}" >"$dns_map_file"
	else
		echo "{}" >"$dns_map_file"
	fi

	if [[ -s "$RUN_DIR/httpx.json" ]]; then
		jq -cs '
			[ .[] | if type=="array" then .[] else . end | select(type=="object") ]
			| group_by(((.input // .host // "") | split(":")[0] | ascii_downcase)) |
			map({
				raw: ((.[0].input // .[0].host // "") | split(":")[0]),
				key: ((.[0].input // .[0].host // "") | split(":")[0] | ascii_downcase),
				value: {
					display: ((.[0].input // .[0].host // "") | split(":")[0]),
					urls: (map(.url) | map(select(. != null and . != "")) | unique),
					ports: (map(.port) | map(select(. != null and . != "")) | unique),
					tech: (reduce .[] as $item ([]; . + ($item.tech // [])) | map(select(. != null and . != "")) | unique),
					webservers: (map(.webserver) | map(select(. != null and . != "")) | unique),
					cdn_names: (map(.cdn_name) | map(select(. != null and . != "")) | unique),
					cdn_types: (map(.cdn_type) | map(select(. != null and . != "")) | unique),
					ips: (reduce .[] as $item ([]; . + ($item.a // [])) | map(select(. != null and . != "")) | unique)
				}
			})
			| map(select(.key != ""))
			| map({key: .key, value: .value})
			| from_entries
		' "$RUN_DIR/httpx.json" >"$httpx_map_file" || echo "{}" >"$httpx_map_file"
	else
		echo "{}" >"$httpx_map_file"
	fi

	if [[ -s "$RUN_DIR/tls_inventory.json" ]]; then
		jq -c '
			group_by(((.Domain // .domain // "") | ascii_downcase)) |
			map({
				raw: (.[0].Domain // .[0].domain // ""),
				key: ((.[0].Domain // .[0].domain // "") | ascii_downcase),
				value: {
					san: (reduce .[] as $item ([]; . + ($item.CertificateSANs // [])) | map(select(. != null and . != "")) | unique),
					summary: (map(.SANSummary) | map(select(. != null and . != "")) | unique),
					cn: (map(.CertificateCommonName) | map(select(. != null and . != "")) | unique)
				}
			})
			| map(select(.key != ""))
			| map({key: .key, value: .value})
			| from_entries
		' "$RUN_DIR/tls_inventory.json" >"$tls_map_file" || echo "{}" >"$tls_map_file"
	else
		echo "{}" >"$tls_map_file"
	fi

	mapfile -t assets < <(
		{
			jq -r 'keys[]' "$dns_map_file"
			jq -r 'keys[]' "$httpx_map_file"
			jq -r 'keys[]' "$tls_map_file"
		} 2>/dev/null | tr -d '\r' | sed 's/^\s*//;s/\s*$//' | awk 'NF' | sort -u
	)

	echo "[" >"$output_file"
	local first_entry=true
	local asset
	for asset in "${assets[@]}"; do
		[[ -z "$asset" ]] && continue
		local dns_info http_info tls_info
		dns_info=$(jq -c --arg host "$asset" '.[$host] // {}' "$dns_map_file")
		http_info=$(jq -c --arg host "$asset" '.[$host] // {}' "$httpx_map_file")
		tls_info=$(jq -c --arg host "$asset" '.[$host] // {}' "$tls_map_file")

		local display_asset
		display_asset=$(jq -r '.display // ""' <<<"$http_info")
		if [[ -z "$display_asset" || "$display_asset" == "null" ]]; then
			display_asset=$(jq -r '.host // ""' <<<"$dns_info")
		fi
		if [[ -z "$display_asset" || "$display_asset" == "null" ]]; then
			display_asset="$asset"
		fi

		local -a tech_array=()
		local -a cdn_array=()
		local -a cdn_type_array=()
		local -a url_array=()
		local -a http_ip_array=()
		local -a dns_a_array=()
		local -a dns_aaaa_array=()
		local -a cname_chain=()

		if [[ "$http_info" != "{}" ]]; then
			mapfile -t tech_array < <(jq -r '.tech[]? | select(. != null and . != "")' <<<"$http_info")
			mapfile -t cdn_array < <(jq -r '.cdn_names[]? | select(. != null and . != "")' <<<"$http_info")
			mapfile -t cdn_type_array < <(jq -r '.cdn_types[]? | select(. != null and . != "")' <<<"$http_info")
			mapfile -t url_array < <(jq -r '.urls[]? | select(. != null and . != "")' <<<"$http_info")
			mapfile -t http_ip_array < <(jq -r '.ips[]? | select(. != null and . != "")' <<<"$http_info")
		fi

		if [[ "$dns_info" != "{}" ]]; then
			mapfile -t dns_a_array < <(jq -r '.a[]? | select(. != null and . != "")' <<<"$dns_info")
			mapfile -t dns_aaaa_array < <(jq -r '.aaaa[]? | select(. != null and . != "")' <<<"$dns_info")
			mapfile -t cname_chain < <(jq -r '.cname[]? | select(. != null and . != "")' <<<"$dns_info")
		fi

		local host_for_lookup="$display_asset"
		[[ -z "$host_for_lookup" ]] && host_for_lookup="$asset"
		local -a cname_follow=()
		mapfile -t cname_follow < <(get_cloud_cname_chain "$host_for_lookup")
		if (( ${#cname_follow[@]} )); then
			local cf
			for cf in "${cname_follow[@]}"; do
				local trimmed_cf="${cf%.}"
				local match_found="false"
				local existing
				for existing in "${cname_chain[@]}"; do
					if [[ "$(normalize_hostname "$existing")" == "$(normalize_hostname "$trimmed_cf")" ]]; then
						match_found="true"
						break
					fi
				done
				if [[ "$match_found" == "false" ]]; then
					cname_chain+=("$trimmed_cf")
				fi
			done
		fi

		local -a ip_list=()
		declare -A seen_ips=()
		local ip
		for ip in "${http_ip_array[@]}" "${dns_a_array[@]}" "${dns_aaaa_array[@]}"; do
			ip=$(echo "$ip" | tr -d '\r' | xargs)
			[[ -z "$ip" ]] && continue
			if [[ -z "${seen_ips[$ip]:-}" ]]; then
				seen_ips[$ip]=1
				ip_list+=("$ip")
			fi
		done
		unset seen_ips

		local -a rdns_list=()
		local asn_display="" provider_display="" network_display=""
		for ip in "${ip_list[@]}"; do
			enrich_cloud_ip_metadata "$ip"
			local asn="${CLOUD_IP_ASN_CACHE[$ip]:-}"
			local provider="${CLOUD_IP_PROVIDER_CACHE[$ip]:-}"
			local network="${CLOUD_IP_NETWORK_CACHE[$ip]:-}"
			local ptrs="${CLOUD_IP_PTR_CACHE[$ip]:-}"
			if [[ -z "$asn_display" && -n "$asn" ]]; then
				asn_display="$asn"
			fi
			if [[ -z "$provider_display" && -n "$provider" ]]; then
				provider_display="$provider"
			fi
			if [[ -z "$network_display" && -n "$network" ]]; then
				network_display="$network"
			fi
			if [[ -n "$ptrs" ]]; then
				IFS=', ' read -r -a ptr_array <<<"$ptrs"
				local ptr_entry
				for ptr_entry in "${ptr_array[@]}"; do
					ptr_entry=$(echo "$ptr_entry" | xargs)
					[[ -z "$ptr_entry" ]] && continue
					rdns_list+=("$ptr_entry")
				done
			fi
		done

		local -a tls_name_array=()
		local -a tls_summary_array=()
		local -a tls_cn_array=()
		if [[ "$tls_info" != "{}" ]]; then
			mapfile -t tls_name_array < <(jq -r '.san[]? | select(. != null and . != "")' <<<"$tls_info")
			mapfile -t tls_summary_array < <(jq -r '.summary[]? | select(. != null and . != "")' <<<"$tls_info")
			mapfile -t tls_cn_array < <(jq -r '.cn[]? | select(. != null and . != "")' <<<"$tls_info")
		fi

		local primary_url=""
		if (( ${#url_array[@]} )); then
			primary_url="${url_array[0]}"
		fi

		local canonical_target=""
		if (( ${#cname_chain[@]} )); then
			canonical_target="${cname_chain[-1]}"
		fi

		local tech_blob=""
		if (( ${#tech_array[@]} )); then
			tech_blob=$(printf '%s\n' "${tech_array[@]}")
		fi
		local cdn_blob=""
		local combined_cdn_array=("${cdn_array[@]}" "${cdn_type_array[@]}")
		if (( ${#combined_cdn_array[@]} )); then
			cdn_blob=$(printf '%s\n' "${combined_cdn_array[@]}")
		fi
		local asn_blob=""
		if [[ -n "$asn_display" || -n "$provider_display" ]]; then
			if [[ -n "$asn_display" && -n "$provider_display" ]]; then
				asn_blob="$asn_display $provider_display"
			else
				asn_blob="${asn_display:-$provider_display}"
			fi
		fi
		local rdns_blob=""
		if (( ${#rdns_list[@]} )); then
			rdns_blob=$(printf '%s\n' "${rdns_list[@]}")
		fi
		local tls_blob=""
		local combined_tls_array=("${tls_name_array[@]}" "${tls_summary_array[@]}" "${tls_cn_array[@]}")
		if (( ${#combined_tls_array[@]} )); then
			tls_blob=$(printf '%s\n' "${combined_tls_array[@]}")
		fi

		local classification
		classification=$(classify_cloud_asset "$display_asset" "$canonical_target" "$tech_blob" "$cdn_blob" "$asn_blob" "$rdns_blob" "$tls_blob")
		local resource_type cloud_provider service_family load_balancer waf_shielding storage_value
		IFS='|' read -r resource_type cloud_provider service_family load_balancer waf_shielding storage_value <<<"$classification"

		local resource_identifier="$canonical_target"
		if [[ -z "$resource_identifier" ]]; then
			if (( ${#ip_list[@]} )); then
				resource_identifier="${ip_list[0]}"
			fi
		fi
		if [[ -z "$resource_identifier" ]]; then
			resource_identifier="$display_asset"
		fi

		local cname_display=""
		if (( ${#cname_chain[@]} )); then
			cname_display=$(join_unique " → " "${cname_chain[@]}")
		fi
		local ip_display=""
		if (( ${#ip_list[@]} )); then
			ip_display=$(join_unique ", " "${ip_list[@]}")
		fi
		local rdns_display=""
		if (( ${#rdns_list[@]} )); then
			rdns_display=$(join_unique ", " "${rdns_list[@]}")
		fi
		local tech_display=""
		if (( ${#tech_array[@]} )); then
			tech_display=$(join_unique ", " "${tech_array[@]}")
		fi
		local cdn_display=""
		if (( ${#combined_cdn_array[@]} )); then
			cdn_display=$(join_unique ", " "${combined_cdn_array[@]}")
		fi
		local tls_display=""
		if (( ${#combined_tls_array[@]} )); then
			tls_display=$(join_unique ", " "${combined_tls_array[@]}")
		fi
		local asn_summary=""
		if [[ -n "$asn_display" || -n "$provider_display" ]]; then
			if [[ -n "$asn_display" && -n "$provider_display" ]]; then
				asn_summary="$asn_display – $provider_display"
			else
				asn_summary="${asn_display:-$provider_display}"
			fi
		fi
		local network_summary=""
		if [[ -n "$network_display" ]]; then
			network_summary="$network_display"
		fi

		local -a evidence=()
		if [[ -n "$primary_url" ]]; then
			evidence+=("Primary URL: $primary_url")
		fi
		if [[ -n "$cname_display" ]]; then
			evidence+=("DNS CNAME Chain: $cname_display")
		fi
		if [[ -n "$ip_display" ]]; then
			evidence+=("Resolved IPs: $ip_display")
		fi
		if [[ -n "$asn_summary" ]]; then
			evidence+=("ASN / Provider: $asn_summary")
		fi
		if [[ -n "$network_summary" ]]; then
			evidence+=("Network: $network_summary")
		fi
		if [[ -n "$rdns_display" ]]; then
			evidence+=("rDNS: $rdns_display")
		fi
		if [[ -n "$tech_display" ]]; then
			evidence+=("HTTP Technologies: $tech_display")
		fi
		if [[ -n "$cdn_display" ]]; then
			evidence+=("HTTP CDN/WAF Signals: $cdn_display")
		fi
		if [[ -n "$tls_display" ]]; then
			evidence+=("TLS SAN/CN: $tls_display")
		fi

		if [[ -z "$primary_url" && -z "$resource_identifier" && ${#evidence[@]} -eq 0 ]]; then
			continue
		fi

		local evidence_json='[]'
		if (( ${#evidence[@]} )); then
			local evidence_tmp
			evidence_tmp=$(printf '%s\n' "${evidence[@]}" | jq -Rs 'split("\n") | map(select(length>0))' 2>/dev/null || true)
			if [[ -n "$evidence_tmp" ]]; then
				evidence_json="$evidence_tmp"
			fi
		fi

		local ip_json='[]'
		if (( ${#ip_list[@]} )); then
			local ip_tmp
			ip_tmp=$(printf '%s\n' "${ip_list[@]}" | jq -Rs 'split("\n") | map(select(length>0))' 2>/dev/null || true)
			if [[ -n "$ip_tmp" ]]; then
				ip_json="$ip_tmp"
			fi
		fi

		local cname_json='[]'
		if (( ${#cname_chain[@]} )); then
			local cname_tmp
			cname_tmp=$(printf '%s\n' "${cname_chain[@]}" | jq -Rs 'split("\n") | map(select(length>0))' 2>/dev/null || true)
			if [[ -n "$cname_tmp" ]]; then
				cname_json="$cname_tmp"
			fi
		fi

		local json_entry
		json_entry=$(jq -n \
			--arg asset "$display_asset" \
			--arg primaryUrl "$primary_url" \
			--arg resourceType "$resource_type" \
			--arg cloudProvider "$cloud_provider" \
			--arg serviceFamily "$service_family" \
			--arg resourceIdentifier "$resource_identifier" \
			--arg loadBalancer "$load_balancer" \
			--arg wafShielding "$waf_shielding" \
			--arg storage "$storage_value" \
			--arg asn "$asn_summary" \
			--arg network "$network_summary" \
			--argjson evidence "$evidence_json" \
			--argjson ips "$ip_json" \
			--argjson cname "$cname_json" \
			'{
				Asset: ($asset // "N/A"),
				PrimaryURL: ($primaryUrl // ""),
				ResourceType: ($resourceType // "Other"),
				CloudProvider: ($cloudProvider // "Unknown"),
				ServiceFamily: ($serviceFamily // "Unknown"),
				ResourceIdentifier: ($resourceIdentifier // "N/A"),
				LoadBalancer: ($loadBalancer // "N/A"),
				WafShielding: ($wafShielding // "Direct Origin"),
				Storage: ($storage // "N/A"),
				ASN: ($asn // ""),
				Network: ($network // ""),
				IPs: $ips,
				CnameChain: $cname,
				Evidence: $evidence
			}')

		if [[ "$first_entry" == true ]]; then
			first_entry=false
		else
			echo "," >>"$output_file"
		fi
		printf '  %s\n' "$json_entry" >>"$output_file"
	done
	echo "]" >>"$output_file"

	rm -f "$dns_map_file" "$httpx_map_file" "$tls_map_file"
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
info "[16/17] Building HTML report with analytics..."
	combine_json "$RUN_DIR/dnsx.json" "$RUN_DIR/dnsx_merged.json"
	combine_json "$RUN_DIR/naabu.json" "$RUN_DIR/naabu_merged.json"
	combine_json "$RUN_DIR/httpx.json" "$RUN_DIR/httpx_merged.json"
	mv "$RUN_DIR/dnsx_merged.json" "$RUN_DIR/dnsx.json"
	mv "$RUN_DIR/naabu_merged.json" "$RUN_DIR/naabu.json"
	mv "$RUN_DIR/httpx_merged.json" "$RUN_DIR/httpx.json"

	cat header.html >report.html
	echo -n "const rawDnsxData = " >>report.html
	cat $RUN_DIR/dnsx.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawNaabuData = " >>report.html
	cat $RUN_DIR/naabu.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const portscanData = " >>report.html
	cat $RUN_DIR/portscan.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawHttpxData = " >>report.html
	cat $RUN_DIR/httpx.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawLoginData = " >>report.html
	cat $RUN_DIR/login.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const secData = " >>report.html
	echo "" >>report.html
	cat $RUN_DIR/securitycompliance.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawSecHeadersData = " >>report.html
	cat $RUN_DIR/sec_headers.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawTlsInventoryData = " >>report.html
	cat $RUN_DIR/tls_inventory.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawApiData = " >>report.html
	cat $RUN_DIR/api_identification.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawColleagueData = " >>report.html
	cat $RUN_DIR/colleague_identification.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawCloudInfraData = " >>report.html
	cat $RUN_DIR/cloud_infrastructure.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const ipIntelData = " >>report.html
	cat $RUN_DIR/ip_enrichment.json | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const rawKatanaData = " >>report.html
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

	info "[17/17] Report generated at $RUN_DIR/report.html"
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
info "[5/17] Merging subdomains..."
	# Append each primary domain and its www subdomain to ALL_TEMP.
	while read -r domain; do
		echo "$domain" >>"$ALL_TEMP"
		echo "www.$domain" >>"$ALL_TEMP"
	done <"$PRIMARY_DOMAINS_FILE"
	sort -u "$ALL_TEMP" >"$MASTER_SUBS"
	rm -f "$ALL_TEMP"
	run_dnsx
	run_naabu
	generate_ip_intel
	run_httpx
	run_katana
	[[ -d output/response ]] && mv output/response "$RUN_DIR/"
	[[ -d output/screenshot ]] && mv output/screenshot "$RUN_DIR/"
	gather_screenshots
	run_login_detection
	run_tls_inventory
	run_security_compliance
	run_api_identification
	run_colleague_identification
	run_cloud_infrastructure_inventory
	build_html_report
	show_summary
}
# Entry point
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
