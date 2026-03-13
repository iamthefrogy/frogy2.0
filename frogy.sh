#!/usr/bin/env bash
set -euo pipefail
# running tight so we bail fast and know why
set -o errtrace

# Resolve the directory this script lives in so all assets/lists/* paths work
# regardless of where frogy.sh is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# colour palette and logging helpers need to be available before traps fire
RED='\033[0;31m'
YELLOW='\033[0;33m'
CLEAR='\033[0m'
NC='\033[0m'
# jotting these down so the logs feel a little more alive
info() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [+] $*"; }
warning() { echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] ${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [-] $*${NC}"; }
log_warn() { warning "$*"; }  # alias used by new expansion modules

# background heartbeat — logs a still-alive pulse every 2 minutes for long-running steps
_HEARTBEAT_PID=""
heartbeat_start() {
	local label="${1:-running}"
	( while true; do sleep 120; info "  → still ${label}... ($(date +'%H:%M:%S'))"; done ) &
	_HEARTBEAT_PID=$!
	disown "$_HEARTBEAT_PID" 2>/dev/null || true
}
heartbeat_stop() {
	if [[ -n "${_HEARTBEAT_PID:-}" ]]; then
		kill "$_HEARTBEAT_PID" 2>/dev/null || true
		_HEARTBEAT_PID=""
	fi
}

# Load API keys from the config file written by the web UI.
# Env vars always win; file values only fill gaps.
load_api_config() {
	local cfg="${FROGY_CONFIG_FILE:-}"
	[[ -z "$cfg" || ! -f "$cfg" ]] && return
	GITHUB_TOKEN="${GITHUB_TOKEN:-$(jq -r '.api_keys.github_token // empty' "$cfg" 2>/dev/null || true)}"
	SHODAN_API_KEY="${SHODAN_API_KEY:-$(jq -r '.api_keys.shodan_api_key // empty' "$cfg" 2>/dev/null || true)}"
	CENSYS_API_KEY="${CENSYS_API_KEY:-$(jq -r '.api_keys.censys_api_key // empty' "$cfg" 2>/dev/null || true)}"
	OTX_API_KEY="${OTX_API_KEY:-$(jq -r '.api_keys.otx_api_key // empty' "$cfg" 2>/dev/null || true)}"
	VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-$(jq -r '.api_keys.virustotal_api_key // empty' "$cfg" 2>/dev/null || true)}"
	WHOISXML_API_KEY="${WHOISXML_API_KEY:-$(jq -r '.api_keys.whoisxml_api_key // empty' "$cfg" 2>/dev/null || true)}"
	CHAOS_KEY="${CHAOS_KEY:-$(jq -r '.api_keys.chaos_api_key // empty' "$cfg" 2>/dev/null || true)}"
}

# if anything crashes mid-run, this little buddy shouts where it blew up
log_err() {
	local ec=$?
	local cmd=${BASH_COMMAND}
	echo "ERR: exit ${ec} at ${BASH_SOURCE[0]}:${BASH_LINENO[0]} while running: ${cmd}" >&2
}
trap log_err ERR

# keeping track of when we kicked things off
SCRIPT_START_TIME=$(date +%s)

# tidy up nicely whether we win or crash
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

# giving the cleanup hook a chance to say goodbye on exit
trap script_cleanup EXIT

# keeping score as we go so the wrap-up feels useful
CHAOS_COUNT=0
SUBFINDER_COUNT=0
ASSETFINDER_COUNT=0
CRT_COUNT=0
DNSX_LIVE_COUNT=0
HTTPX_LIVE_COUNT=0
LOGIN_FOUND_COUNT=0
GAU_COUNT=0
# nudge this if the web scanners seem blocked or throttled
BLOCK_DETECTION_THRESHOLD="20"

# ─── Fixed scan parameters ────────────────────────────────────────────────
SCALE_TIER="fixed"
HTTPX_THREADS=20
HTTPX_RATE=80
HTTPX_TIMEOUT_SECS=8
HTTPX_RETRIES_COUNT=1
KATANA_DEPTH_ADAPTIVE=3
KATANA_TIMEOUT_ADAPTIVE=60
EFFECTIVE_WEB_PORTS=""       # fixed web port list for httpx expansion

# caching a few lookups so we don't hammer the same data over and over
declare -A CLOUD_IP_ASN_CACHE=()
declare -A CLOUD_IP_PROVIDER_CACHE=()
declare -A CLOUD_IP_NETWORK_CACHE=()
declare -A CLOUD_IP_PTR_CACHE=()
declare -A CLOUD_CNAME_CACHE=()

# before we spin up tools, double-check the toolbox is stocked
check_dependencies() {
	info "Verifying required tools..."
	local missing_tools=()
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
		# no point continuing without the basics, so we bail here
		exit 1
	fi
	info "All required tools are present."

	# /dev/tcp is used for Team Cymru batch ASN lookup; warn early if unavailable
	# (expected on Docker Desktop for macOS/Windows — ASN classification is non-critical)
	if ! (exec 3<>/dev/tcp/whois.cymru.com/43) 2>/dev/null; then
		warning "/dev/tcp unavailable — ASN classification via Team Cymru will be skipped (expected on Docker Desktop for macOS/Windows, non-critical)."
	fi
}

# ─── Health-check mode ────────────────────────────────────────────────────────
# Usage: bash frogy.sh --check
# Validates tools, network reachability, /dev/tcp, write permissions, and CAP_NET_RAW.
run_health_check() {
	local pass=0 warn=0 fail=0
	_hc_pass() { echo "  [PASS] $*"; (( pass++ )) || true; }
	_hc_warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; (( warn++ )) || true; }
	_hc_fail() { echo -e "  ${RED}[FAIL]${NC} $*"; (( fail++ )) || true; }

	echo ""
	echo "═══════════════════════════════════════════════"
	echo "  Frogy 2.0 — Health Check"
	echo "═══════════════════════════════════════════════"
	echo ""

	echo "── Tool versions ──────────────────────────────"
	local required_tools=("subfinder" "assetfinder" "dnsx" "naabu" "httpx" "katana" "jq" "curl" "whois" "dig" "openssl" "tlsx" "xargs" "unzip" "grep" "sed" "awk")
	for tool in "${required_tools[@]}"; do
		if command -v "$tool" &>/dev/null; then
			local ver
			ver=$("$tool" --version 2>&1 | head -1 || echo "(version unknown)")
			_hc_pass "$tool — $ver"
		else
			_hc_fail "$tool — NOT FOUND"
		fi
	done

	echo ""
	echo "── Network reachability ───────────────────────"
	for url in "https://crt.sh" "https://api.github.com" "https://web.archive.org"; do
		if curl -s --max-time 8 "$url" >/dev/null 2>&1; then
			_hc_pass "$url reachable"
		else
			_hc_warn "$url unreachable (transient or blocked by network)"
		fi
	done

	echo ""
	echo "── /dev/tcp (Team Cymru ASN lookup) ──────────"
	if (exec 3<>/dev/tcp/whois.cymru.com/43) 2>/dev/null; then
		_hc_pass "/dev/tcp available — ASN classification will work"
	else
		_hc_warn "/dev/tcp unavailable — ASN classification skipped (expected on Docker Desktop macOS/Windows, non-critical)"
	fi

	echo ""
	echo "── Write permissions ──────────────────────────"
	local out_dir="${FROGY_OUTPUT_DIR:-output}"
	mkdir -p "$out_dir" 2>/dev/null || true
	if [[ -w "$out_dir" ]]; then
		_hc_pass "output dir '$out_dir' is writable"
	else
		_hc_fail "output dir '$out_dir' is NOT writable — scans will fail to write results"
	fi

	echo ""
	echo "── CAP_NET_RAW (naabu SYN scan) ───────────────"
	if naabu -version >/dev/null 2>&1; then
		_hc_pass "naabu responds — raw socket support likely available"
	else
		_hc_warn "naabu did not respond to --version; add --cap-add=NET_RAW --privileged to docker run"
	fi

	echo ""
	echo "═══════════════════════════════════════════════"
	printf "  Results: %d passed, %d warnings, %d failed\n" "$pass" "$warn" "$fail"
	echo "═══════════════════════════════════════════════"
	echo ""
	if [[ "$fail" -gt 0 ]]; then
		exit 1
	fi
	exit 0
}

if [[ "${1:-}" == "--check" ]]; then
	run_health_check
fi

# I expect a plain list of domains as the first argument
if [ "$#" -lt 1 ]; then
	echo -e "\033[91m[-] Usage: $0 <primary_domains_file>\033[0m"
	echo -e "\033[91m       or: $0 --check   (run health check)\033[0m"
	exit 1
fi

PRIMARY_DOMAINS_FILE="$1"
if [[ ! -f "$PRIMARY_DOMAINS_FILE" || ! -r "$PRIMARY_DOMAINS_FILE" ]]; then
	echo -e "\033[91m[-] File '$PRIMARY_DOMAINS_FILE' not found or not readable!\033[0m" >&2
	exit 1
fi
if ! awk '!/^\s*$/ { if ($0 !~ /^[A-Za-z0-9.-]+$/) { exit 1 } }' "$PRIMARY_DOMAINS_FILE"; then
	error "Input file contains invalid domain lines."
	exit 1
fi

RUN_DIR="output/run-$(date +%Y%m%d%H%M%S)"
mkdir -p "$RUN_DIR/raw_output/raw_http_responses"
mkdir -p "$RUN_DIR/logs"

# make sure we can actually write under the new run folder
if [[ ! -w "$RUN_DIR" || ! -w "$RUN_DIR/logs" ]]; then
	error "Output directory '$RUN_DIR' or its 'logs' subdir is not writable."
	exit 1
fi

# tucking stderr into the run log so the console isn't noisy
exec 2>"$RUN_DIR/logs/logs.log"
# turning on shell tracing for easier debugging later
set -x

ALL_TEMP="$RUN_DIR/all_temp_subdomains.txt"
MASTER_SUBS="$RUN_DIR/master_subdomains.txt"
MASTER_HOST_INDEX="$RUN_DIR/master_hosts_lower.txt"
>"$ALL_TEMP"
>"$MASTER_SUBS"
> "$MASTER_HOST_INDEX"

USE_CHAOS="false"
USE_SUBFINDER="true"
USE_ASSETFINDER="true"
USE_DNSX="true"
USE_NAABU="true"
USE_HTTPX="true"
USE_GAU="true"

NAABU_SCAN_MODE="${NAABU_SCAN_MODE:-connect}"
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-100}"

# Fixed top-20 web ports (Shodan facet-derived, web-focused) used for httpx expansion.
WEB_PORTS_TOP20=$(grep -v '^[[:space:]]*$' "$SCRIPT_DIR/assets/lists/web-ports-top20.txt" | paste -sd',')

# CDN alternate web ports — edge nodes listen on these in addition to 80/443.
WEB_PORTS_CDN=$(grep -v '^[[:space:]]*$' "$SCRIPT_DIR/assets/lists/web-ports-cdn.txt" | paste -sd',')

# Naabu rate/concurrency defaults.
NAABU_RATE="${NAABU_RATE:-300}"
NAABU_CONCURRENCY="${NAABU_CONCURRENCY:-25}"

# ─── CDN ASN list — worldwide top-10+ providers ────────────────────────────
# Hosts resolving to these ASNs are proxy/CDN-fronted; SYN scans are blocked.
# They receive httpx web-port probing only (no naabu).
# Edit assets/lists/cdn-asns.txt to add/remove providers — no code change needed.
mapfile -t CDN_ASNS < "$SCRIPT_DIR/assets/lists/cdn-asns.txt"

# ─── CDN CNAME suffix list — CNAME-based CDN detection (complements ASN lookup) ─
# If any CNAME in a host's chain ends with one of these suffixes, the host is
# treated as CDN-fronted regardless of ASN. Cloud tier still wins over CNAME CDN.
# Edit assets/lists/cdn-cnames.txt to add/remove suffixes — no code change needed.
mapfile -t CDN_CNAME_SUFFIXES < "$SCRIPT_DIR/assets/lists/cdn-cnames.txt"

# ─── Cloud ASN list — worldwide top-10+ providers ──────────────────────────
# Hosts in these ASNs are actual compute; full port scan is valid and useful.
# Cloud takes precedence over CDN if a host maps to both.
# Edit assets/lists/cloud-asns.txt to add/remove providers — no code change needed.
mapfile -t CLOUD_ASNS < "$SCRIPT_DIR/assets/lists/cloud-asns.txt"

# ─── Classify DNS-resolved hosts into CDN-fronted vs direct/cloud tiers ─────
# Runs after dnsx; uses Team Cymru batch ASN lookup. Writes:
#   cdn_hosts.txt       — hosts behind CDN proxies (no naabu; web ports only)
#   direct_hosts.txt    — hosts on cloud/own IPs (full naabu scan)
#   host_classification.json — per-host ASN/tier details for the report
classify_hosts_by_tier() {
	local dnsx_file="$RUN_DIR/dnsx.json"
	local cdn_hosts="$RUN_DIR/cdn_hosts.txt"
	local direct_hosts="$RUN_DIR/direct_hosts.txt"
	local host_classification="$RUN_DIR/host_classification.json"

	>"$cdn_hosts"
	>"$direct_hosts"

	if [[ ! -s "$dnsx_file" ]]; then
		warning "  ⚠ No dnsx data; treating all master subdomains as direct hosts."
		[[ -s "$MASTER_SUBS" ]] && cp "$MASTER_SUBS" "$direct_hosts"
		echo "[]" >"$host_classification"
		return
	fi

	# Collect all resolved hostnames
	local all_hosts_tmp
	all_hosts_tmp=$(mktemp)
	jq -r 'select(type=="object") | select(.status_code=="NOERROR") | .host' \
		"$dnsx_file" 2>/dev/null | sort -u >"$all_hosts_tmp" || true

	# Build ip|host mapping from A records
	local ip_host_map
	ip_host_map=$(mktemp)
	jq -r 'select(type=="object") | select(.status_code=="NOERROR") |
	        select(.a != null and (.a | length) > 0) |
	        .host as $h | .a[] | "\(.)|\($h)"' \
		"$dnsx_file" 2>/dev/null | sort -u >"$ip_host_map" || true

	if [[ ! -s "$ip_host_map" ]]; then
		warning "  ⚠ No A records found; treating all resolved hosts as direct."
		cp "$all_hosts_tmp" "$direct_hosts"
		echo "[]" >"$host_classification"
		rm -f "$all_hosts_tmp" "$ip_host_map"
		return
	fi

	local ips_tmp
	ips_tmp=$(mktemp)
	cut -d'|' -f1 "$ip_host_map" | sort -u >"$ips_tmp"
	local ip_count
	ip_count=$(wc -l <"$ips_tmp" | tr -d ' ')
	info "  → Classifying ${ip_count} unique IPs via Team Cymru batch ASN lookup..."

	# Batch ASN lookup over a single TCP connection to whois.cymru.com
	local cymru_tmp
	cymru_tmp=$(mktemp)
	{
		printf 'begin\nverbose\n'
		cat "$ips_tmp"
		printf 'end\n'
	} | timeout 60 bash -c \
		'exec 3<>/dev/tcp/whois.cymru.com/43; cat >&3; sleep 3; cat <&3; exec 3>&-' \
		2>/dev/null | \
		awk -F'|' '
		NF>=2 && $1~/^[[:space:]]*[0-9]/ {
			asn=$1; ip=$2
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", asn)
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", ip)
			if (asn!="" && ip!="") print ip "|" asn
		}' >"$cymru_tmp" || true

	# Python script to classify hosts (avoids messy bash associative arrays for large sets)
	local py_tmp
	py_tmp=$(mktemp --suffix=.py)
	cat >"$py_tmp" <<'PYEOF'
import sys, json

cdn_asns   = set(sys.argv[1].split())
cloud_asns = set(sys.argv[2].split())

# Optional: CNAME-based CDN suffix list (argv[5]) and dnsx file path (argv[6])
cdn_cname_suffixes = tuple(s.lower() for s in sys.argv[5].split()) if len(sys.argv) > 5 and sys.argv[5] else ()
dnsx_file = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None

cymru_map = {}   # ip → asn
with open(sys.argv[3]) as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 2:
            cymru_map[parts[0].strip()] = parts[1].strip()

ip_host_map = {}  # ip → [hosts]
with open(sys.argv[4]) as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 2:
            ip_host_map.setdefault(parts[0].strip(), []).append(parts[1].strip())

# Build host → [cnames] map from dnsx JSON (one record per line)
host_cnames = {}  # host → [cname, ...]
if dnsx_file and cdn_cname_suffixes:
    try:
        with open(dnsx_file) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    h = rec.get('host', '')
                    cnames = rec.get('cname') or []
                    if h and cnames:
                        host_cnames[h] = [c.lower() for c in cnames]
                except Exception:
                    pass
    except Exception:
        pass

host_data = {}
for ip, hosts in ip_host_map.items():
    asn = cymru_map.get(ip, '')
    # Cloud always beats CDN (same ASN can serve both)
    if asn in cloud_asns:
        tier = 'cloud'
    elif asn in cdn_asns:
        tier = 'cdn'
    else:
        tier = 'direct'
    for host in hosts:
        if host not in host_data:
            host_data[host] = {'host': host, 'ips': [], 'asns': [], 'tier': tier}
        host_data[host]['ips'].append(ip)
        if asn and asn not in host_data[host]['asns']:
            host_data[host]['asns'].append(asn)
        # Upgrade tier: cloud > direct > cdn
        curr = host_data[host]['tier']
        if curr == 'cdn' and tier in ('cloud', 'direct'):
            host_data[host]['tier'] = tier
        elif curr == 'direct' and tier == 'cloud':
            host_data[host]['tier'] = 'cloud'

# CNAME-based CDN override: if any CNAME chain matches a known CDN suffix,
# force tier to cdn — unless the host is already classified as cloud.
if cdn_cname_suffixes:
    for host, data in host_data.items():
        if data['tier'] == 'cloud':
            continue
        cnames = host_cnames.get(host, [])
        if any(c.endswith(s) for c in cnames for s in cdn_cname_suffixes):
            data['tier'] = 'cdn'

print(json.dumps(list(host_data.values())))
PYEOF

	local cdn_asn_str="${CDN_ASNS[*]}"
	local cloud_asn_str="${CLOUD_ASNS[*]}"
	local cdn_cname_str="${CDN_CNAME_SUFFIXES[*]}"
	python3 "$py_tmp" "$cdn_asn_str" "$cloud_asn_str" "$cymru_tmp" "$ip_host_map" \
		"$cdn_cname_str" "$dnsx_file" \
		>"$host_classification" 2>/dev/null || echo "[]" >"$host_classification"

	# Write per-tier host files
	jq -r '.[] | select(.tier == "cdn") | .host' \
		"$host_classification" 2>/dev/null | sort -u >"$cdn_hosts" || true
	jq -r '.[] | select(.tier != "cdn") | .host' \
		"$host_classification" 2>/dev/null | sort -u >"$direct_hosts" || true

	# Hosts with no A record (CNAME-only, AAAA-only, TXT-only) fall back to direct
	local classified_tmp
	classified_tmp=$(mktemp)
	{ cat "$cdn_hosts" "$direct_hosts" 2>/dev/null; } | sort -u >"$classified_tmp"
	comm -23 <(sort "$all_hosts_tmp") "$classified_tmp" >>"$direct_hosts" || true
	sort -u "$direct_hosts" -o "$direct_hosts"

	local cdn_count direct_count
	cdn_count=$(wc -l <"$cdn_hosts" | tr -d ' ')
	direct_count=$(wc -l <"$direct_hosts" | tr -d ' ')
	info "  → ${cdn_count} CDN-fronted (web ports only) | ${direct_count} direct/cloud/unknown (full port scan)"

	rm -f "$all_hosts_tmp" "$ip_host_map" "$ips_tmp" "$cymru_tmp" "$py_tmp" "$classified_tmp"
}

# ─── Web port expansion — CDN vs non-CDN split ──────────────────────────────
# CDN hosts: probe CDN alternate ports (edge nodes use non-standard HTTPS ports).
# Non-CDN resolved hosts: probe standard top-20 web ports as a safety net for
# services that naabu may have missed (e.g. cloud hosts behind firewalls).
augment_final_urls_with_webports() {
	local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
	local dnsx_file="$RUN_DIR/dnsx.json"
	[[ ! -s "$dnsx_file" ]] && return

	local cdn_hosts_file="$RUN_DIR/cdn_hosts.txt"
	local cdn_ports="${WEB_PORTS_CDN:-80,443,2052,2053,2082,2083,2086,2087,2095,2096,8080,8443,4443,8888,8880,8081,2222}"
	local direct_ports="${EFFECTIVE_WEB_PORTS:-$WEB_PORTS_TOP20}"

	# All NOERROR-resolved hosts
	local resolved_hosts_tmp
	resolved_hosts_tmp=$(mktemp)
	jq -r 'select(type=="object") | select(.status_code=="NOERROR") | .host' \
		"$dnsx_file" 2>/dev/null | sort -u >"$resolved_hosts_tmp" || true

	info "  → Web port expansion (CDN/non-CDN split)..."

	# CDN hosts × CDN alternate ports
	if [[ -s "$cdn_hosts_file" ]]; then
		local cdn_count cdn_port_count
		cdn_count=$(wc -l <"$cdn_hosts_file" | tr -d ' ')
		cdn_port_count=$(echo "$cdn_ports" | tr ',' '\n' | sed '/^$/d' | wc -l | tr -d ' ')
		info "    CDN hosts: ${cdn_count} × ${cdn_port_count} CDN ports"
		awk -v ports="$cdn_ports" 'BEGIN { n=split(ports,pa,",") }
		    { for(i=1;i<=n;i++) print $0":"pa[i] }' \
			"$cdn_hosts_file" >>"$final_urls_ports"
	fi

	# Non-CDN resolved hosts × standard web ports
	local non_cdn_tmp
	non_cdn_tmp=$(mktemp)
	if [[ -s "$cdn_hosts_file" ]]; then
		comm -23 <(sort "$resolved_hosts_tmp") <(sort "$cdn_hosts_file") >"$non_cdn_tmp" || true
	else
		cp "$resolved_hosts_tmp" "$non_cdn_tmp"
	fi

	local non_cdn_count port_count
	non_cdn_count=$(wc -l <"$non_cdn_tmp" | tr -d ' ')
	port_count=$(echo "$direct_ports" | tr ',' '\n' | sed '/^$/d' | wc -l | tr -d ' ')
	info "    Non-CDN hosts: ${non_cdn_count} × ${port_count} web ports"
	if [[ -s "$non_cdn_tmp" ]]; then
		awk -v ports="$direct_ports" 'BEGIN { n=split(ports,pa,",") }
		    { for(i=1;i<=n;i++) print $0":"pa[i] }' \
			"$non_cdn_tmp" >>"$final_urls_ports"
	fi

	sort -u "$final_urls_ports" -o "$final_urls_ports"
	local total
	total=$(wc -l <"$final_urls_ports" | tr -d ' ')
	info "  → Total httpx targets after expansion: ${total}"
	rm -f "$resolved_hosts_tmp" "$non_cdn_tmp"
}

# quick helper to glue list items together without duplicates
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

# making sure hostnames look consistent when we compare them
normalize_hostname() {
	local value="$1"
	value=$(echo "$value" | tr -d '\r' | tr '[:upper:]' '[:lower:]')
	value=${value%.}
	echo "$value"
}

# caching WHOIS-style bits to avoid hammering upstream services
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

# chasing down CNAME chains so we can spot cloud providers from redirects
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

# best guess labels for the cloud bits we discover
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

declare -a QUALITY_ALERTS=()

# keeping data checks handy so we notice weird runs right away
quality_ping() {
	local message="$1"
	QUALITY_ALERTS+=("$message")
	warning "$message"
}

quality_check_json_array() {
	local label="$1"
	local file="$2"
	local min=${3:-0}
	if [[ ! -s "$file" ]]; then
		quality_ping "$label came back empty at $file. Moving on but keep an eye on coverage."
		echo "[]" >"$file"
		return 0
	fi
	if ! jq -e 'type=="array"' "$file" >/dev/null 2>&1; then
		quality_ping "$label looked malformed, so I reset $file to []. Continuing the run."
		echo "[]" >"$file"
		return 0
	fi
	local count
	count=$(jq 'length' "$file")
	if (( count < min )); then
		quality_ping "$label only has $count record(s); expected at least $min. Carrying on regardless."
	else
		info "[✔] Quality check for $label: $count record(s) in place."
	fi
	return 0
}

quality_check_hosts_against_master() {
	local label="$1"
	local file="$2"
	local jq_expr="$3"
	local master_index="$RUN_DIR/master_hosts_lower.txt"
	[[ -s "$file" && -s "$master_index" ]] || return 0
	local tmp
	tmp=$(mktemp)
	if ! jq -r "$jq_expr" "$file" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/^\s*//;s/\s*$//' | sed '/^$/d' | sort -u >"$tmp"; then
		quality_ping "$label host extraction failed for $file. Continuing without cross-check."
		rm -f "$tmp"
		return 0
	fi
	if [[ ! -s "$tmp" ]]; then
		rm -f "$tmp"
		return 0
	fi
	local misses
	misses=$(comm -23 "$tmp" "$master_index")
	if [[ -n "$misses" ]]; then
		local slice
		slice=$(echo "$misses" | paste -sd',' -)
		quality_ping "$label spotted hosts missing from master list: $slice (still exporting data)."
	fi
	rm -f "$tmp"
}

# gives us a quick record count no matter how the JSON is shaped
json_count() {
	local file="$1"
	[[ -s "$file" ]] || { echo 0; return; }
	jq -s 'if length == 0 then 0 elif length == 1 and (.[0]|type=="array") then (.[0]|length) else length end' "$file" 2>/dev/null || wc -l <"$file"
}

# pouring each tool's findings into the shared bucket and tallying counts
merge_and_count() {
	local file="$1"        # stash of subdomains from a single tool
	local source_name="$2" # tag so we know which counter to bump
	local count=0
	if [[ -s "$file" ]]; then
		count=$(wc -l <"$file")
		cat "$file" >>"$ALL_TEMP"
	fi
	# keep the little scoreboard up to date per source
	case "$source_name" in
	"Chaos") CHAOS_COUNT=$((CHAOS_COUNT + count)) ;;
	"Subfinder") SUBFINDER_COUNT=$((SUBFINDER_COUNT + count)) ;;
	"Assetfinder") ASSETFINDER_COUNT=$((ASSETFINDER_COUNT + count)) ;;
	"Certificate") CRT_COUNT=$((CRT_COUNT + count)) ;;
	"GAU") GAU_COUNT=$((GAU_COUNT + count)) ;;
	esac

}

# filter a host-list file in-place using FROGY_EXCLUSIONS_FILE
# each exclusion entry removes exact matches + all subdomains (*.entry)
apply_exclusions() {
	local target_file="$1"
	local label="${2:-MASTER_SUBS}"
	[[ -z "${FROGY_EXCLUSIONS_FILE:-}" || ! -f "$FROGY_EXCLUSIONS_FILE" ]] && return
	local before after
	before=$(wc -l <"$target_file" 2>/dev/null || echo 0)
	cp "$target_file" "${target_file}.pre_excl"
	while IFS= read -r excl; do
		[[ -z "$excl" || "$excl" =~ ^# ]] && continue
		local esc
		esc=$(printf '%s' "$excl" | sed 's/\./\\./g')
		grep -v -E "(^${esc}$|\\.${esc}$)" "${target_file}.pre_excl" >"${target_file}.excl_tmp" 2>/dev/null || true
		mv "${target_file}.excl_tmp" "${target_file}.pre_excl"
	done <"$FROGY_EXCLUSIONS_FILE"
	mv "${target_file}.pre_excl" "$target_file"
	after=$(wc -l <"$target_file" 2>/dev/null || echo 0)
	info "Exclusions applied to ${label}: $((before - after)) entries removed"
}

# optional Chaos dataset pull for folks with API access
run_chaos() {
	if [[ "$USE_CHAOS" == "true" ]]; then
		info "Running Chaos..."
		local cdir
		cdir="$(basename "$RUN_DIR")"
		local chaos_index="output/$cdir/logs/chaos_index.json"
		# grab the chaos index so we know where to pull data from
		curl -s https://chaos-data.projectdiscovery.io/index.json -o "$chaos_index"
		# match the index entry to this run's folder name
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

	# If a PDCP/Chaos API key is set, also query via chaos CLI for live per-domain results
	if [[ -n "${CHAOS_KEY:-}" ]] && command -v chaos >/dev/null 2>&1; then
		local chaos_cli_out="$RUN_DIR/chaos_cli.txt"
		: >"$chaos_cli_out"
		while IFS= read -r domain; do
			[[ -z "$domain" ]] && continue
			chaos -d "$domain" -key "$CHAOS_KEY" -silent 2>/dev/null >>"$chaos_cli_out" || true
		done <"$PRIMARY_DOMAINS_FILE"
		merge_and_count "$chaos_cli_out" "Chaos-CLI"
	fi
}

# bread-and-butter subdomain discovery via subfinder
run_subfinder() {
	if [[ "$USE_SUBFINDER" == "true" ]]; then
		info "[4/31] Running Subfinder..."
		timeout 300 subfinder -dL "$PRIMARY_DOMAINS_FILE" -silent -all -o "$RUN_DIR/subfinder.txt" >/dev/null 2>&1 || { warning "subfinder timed out after 5 min — continuing with partial results."; true; }
		merge_and_count "$RUN_DIR/subfinder.txt" "Subfinder"
	fi
}

# catching whatever assetfinder can scrape from public sources
run_assetfinder() {
	if [[ "$USE_ASSETFINDER" != "true" ]]; then
		return 0
	fi
info "[5/31] Running Assetfinder..."
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

# leaning on crt.sh to shake out certificate-disclosed hosts
run_crtsh() {
info "[6/31] Running crt.sh..."
	local crt_file="$RUN_DIR/whois.txt"
	>"$crt_file"
	local crt_status=0
	if ! while read -r domain; do
		{
			# pausing strict mode so we can tolerate flaky whois replies
			set +e
			local registrant
			# try to yank the registrant org from whois
			registrant=$(whois "$domain" 2>/dev/null |
				grep -i "Registrant Organization" |
				cut -d ":" -f2 |
				xargs |
				sed 's/,/%2C/g; s/ /+/g' |
				egrep -v '(Whois|whois|WHOIS|domains|DOMAINS|Domains|domain|DOMAIN|Domain|proxy|Proxy|PROXY|PRIVACY|privacy|Privacy|REDACTED|redacted|Redacted|DNStination|WhoisGuard|Protected|protected|PROTECTED|Registration Private|REGISTRATION PRIVATE|registration private)' ||
				true)
			if [[ -n "$registrant" ]]; then
				# ask crt.sh about that org as well
				curl -s "https://crt.sh/?q=$registrant" |
					grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' |
					sed -e 's/^<TD>//;s/<\/TD>$//' \
						>>"$crt_file"
			fi
			# fall back to straight domain lookups too
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

# GAU gives us historical URLs that still hint at old assets
run_gau() {
	if [[ "$USE_GAU" != "true" ]]; then
		return 0
	fi
info "[7/31] Running GAU…"

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

# quick DNS sweep to see what actually resolves
run_dnsx() {
	if [[ "$USE_DNSX" == "true" ]]; then
		info "[10/31] Running dnsx..."
		heartbeat_start "resolving subdomains with dnsx"
		timeout 900 dnsx -silent \
			-rl 50 \
			-t 25 \
			-l "$MASTER_SUBS" \
			-o "$RUN_DIR/dnsx.json" \
			-j \
			>/dev/null 2>&1 || { warning "dnsx timed out after 15 min — continuing with partial results."; true; }
		heartbeat_stop
		if [[ -s "$RUN_DIR/dnsx.json" ]]; then
			# tally how many hosts actually resolved cleanly
			DNSX_LIVE_COUNT=$(jq -r 'select(.status_code=="NOERROR") | .host' "$RUN_DIR/dnsx.json" | sort -u | wc -l)
		else
			DNSX_LIVE_COUNT=0
		fi
	fi
}

# port scan time; naabu checks which services even bother replying
# Only scans direct/cloud/unknown hosts; CDN-fronted hosts are handled by
# augment_final_urls_with_webports (httpx-only probe on the web port list).
run_naabu() {
	if [[ "$USE_NAABU" == "true" ]]; then
		info "[12/31] Running naabu..."

		# Scan only direct/cloud hosts; CDN-fronted hosts are handled separately
		# by augment_final_urls_with_webports (web-port probing only, no SYN scan).
		local naabu_target="$RUN_DIR/naabu_targets.txt"
		if [[ -s "$RUN_DIR/direct_hosts.txt" ]]; then
			cp "$RUN_DIR/direct_hosts.txt" "$naabu_target"
		elif [[ -s "$RUN_DIR/dnsx.json" ]]; then
			# Fallback: no classification output — scan all NOERROR hosts
			jq -r 'select(type=="object") | select(.status_code=="NOERROR") | .host' \
				"$RUN_DIR/dnsx.json" 2>/dev/null | sort -u >"$naabu_target" || true
		fi
		if [[ ! -s "$naabu_target" ]]; then
			naabu_target="$MASTER_SUBS"
		fi
		local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
		if [[ ! -s "$naabu_target" ]]; then
			info "  → No hosts available for naabu scan."
			> "$RUN_DIR/naabu.json"
			> "$final_urls_ports"
			# Always include root input domains on 80/443 so web checks still run
			while IFS= read -r domain; do
				domain=$(echo "$domain" | tr -d '\r' | xargs)
				[[ -z "$domain" ]] && continue
				printf '%s:80\n%s:443\nwww.%s:80\nwww.%s:443\n' "$domain" "$domain" "$domain" "$domain"
			done <"$PRIMARY_DOMAINS_FILE" >>"$final_urls_ports"
			sort -u "$final_urls_ports" -o "$final_urls_ports"
			generate_portscan_summary
			return
		fi
		local target_count
		target_count=$(wc -l <"$naabu_target" | tr -d ' ')

		# Build port argument from port-spec.txt; fallback to top-N if file missing.
		local naabu_port_arg
		local port_spec_file="$SCRIPT_DIR/assets/lists/port-spec.txt"
		if [[ -s "$port_spec_file" ]]; then
			naabu_port_arg=$(grep -v '^\s*#' "$port_spec_file" | grep -v '^\s*$' | tr '\n' ',' | sed 's/,$//')
			info "  → Scanning ${target_count} direct/cloud hosts with naabu (port-spec.txt, $(echo "$naabu_port_arg" | tr ',' '\n' | wc -l | tr -d ' ') ports, rate=${NAABU_RATE:-300})."
		else
			local top_ports="${NAABU_TOP_PORTS:-100}"
			if [[ ! "$top_ports" =~ ^[0-9]+$ ]] || (( top_ports <= 0 )); then
				warning "Invalid NAABU_TOP_PORTS='${NAABU_TOP_PORTS}'. Falling back to 100."
				top_ports=100
			fi
			naabu_port_arg=""
			info "  → Scanning ${target_count} direct/cloud hosts with naabu top-${top_ports} (port-spec.txt not found)."
		fi

		local -a naabu_base_args=(
			-silent
			-l "$naabu_target"
			-rate "${NAABU_RATE:-300}"
			-c "${NAABU_CONCURRENCY:-25}"
			-retries 1
			-o "$RUN_DIR/naabu.json"
			-json
		)
		if [[ -n "$naabu_port_arg" ]]; then
			naabu_base_args+=(-p "$naabu_port_arg")
		else
			naabu_base_args+=(-top-ports "${top_ports:-100}")
		fi

		run_naabu_pass() {
			rm -f "$RUN_DIR/naabu.json"
			heartbeat_start "port scanning with naabu"
			timeout 5400 naabu "${naabu_base_args[@]}" "$@" >/dev/null || { warning "naabu timed out after 90 min — continuing with partial results."; true; }
			heartbeat_stop
		}

		local scan_mode="${NAABU_SCAN_MODE,,}"
		case "$scan_mode" in
		connect)
			info "Running naabu in TCP connect mode (-s c -Pn)."
			run_naabu_pass -s c -Pn
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

		# build a simple host:port list for later HTTP checks
		if [[ -s "$RUN_DIR/naabu.json" ]]; then
			jq -r '"\(.host):\(.port)"' "$RUN_DIR/naabu.json" | sort -u >"$final_urls_ports"
		else
			> "$final_urls_ports"
		fi
		# Always include root input domains on 80/443 so CDN-fronted sites never get skipped
		while IFS= read -r domain; do
			domain=$(echo "$domain" | tr -d '\r' | xargs)
			[[ -z "$domain" ]] && continue
			printf '%s:80\n%s:443\nwww.%s:80\nwww.%s:443\n' "$domain" "$domain" "$domain" "$domain"
		done <"$PRIMARY_DOMAINS_FILE" >>"$final_urls_ports"
		sort -u "$final_urls_ports" -o "$final_urls_ports"
	fi
	generate_portscan_summary
}

# summarizing naabu hits per IP so later steps have clean data
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
	quality_check_json_array "Port summary" "$portscan_file"
}

# pulling rDNS and ASN notes so the report has context on each IP
# parallelised: 8 concurrent workers via xargs
_ip_intel_worker() {
	local ip="$1"
	[[ -z "$ip" ]] && return
	local safe_ip
	safe_ip=$(printf '%s' "$ip" | tr '/: ' '___')

	local ptr_records=""
	local ptr_raw
	ptr_raw=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' || true)
	[[ -n "$ptr_raw" ]] && ptr_records=$(printf '%s\n' "$ptr_raw" | paste -sd ', ' -)

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
	if [[ -n "${WHOIS_LOCK:-}" ]]; then
		(flock -x 200; whois "$ip" 2>/dev/null || true) 200>"$WHOIS_LOCK" >"$whois_file" || whois "$ip" >"$whois_file" 2>/dev/null || true
	else
		whois "$ip" >"$whois_file" 2>/dev/null || true
	fi

	if [[ -z "$network" ]]; then
		network=$(awk -F: '/^[Cc][Ii][Dd][Rr]/ {print $2; exit}' "$whois_file" | xargs 2>/dev/null || true)
		[[ -z "$network" ]] && network=$(awk -F: '/^NetRange/ {print $2; exit}' "$whois_file" | xargs 2>/dev/null || true)
	fi
	[[ -z "$asn" ]] && asn=$(awk -F: '/^origin/ {print $2; exit}' "$whois_file" | xargs 2>/dev/null || true)
	[[ -z "$provider" ]] && provider=$(awk -F: '/^(OrgName|Org-name|descr|owner)/ {print $2; exit}' "$whois_file" | xargs 2>/dev/null || true)
	rm -f "$whois_file"

	[[ -n "$asn" && "$asn" != AS* ]] && asn="AS${asn}"

	jq -n \
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
		}' >"${IP_INTEL_TMP_DIR}/${safe_ip}.json" 2>/dev/null || true
}
export -f _ip_intel_worker

generate_ip_intel() {
	info "[13/31] Enriching IP intelligence (parallel workers)..."
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
		quality_check_json_array "IP enrichment" "$intel_file"
		rm -f "$ip_candidates"
		return
	fi

	sort -u "$ip_candidates" | sed '/^$/d' >"$ip_candidates.sorted"
	mv "$ip_candidates.sorted" "$ip_candidates"

	export IP_INTEL_TMP_DIR="$RUN_DIR/ip_intel_tmp"
	mkdir -p "$IP_INTEL_TMP_DIR"
	# export a global WHOIS lock file for rate-limiting
	export WHOIS_LOCK="$RUN_DIR/.whois_ip.lock"
	touch "$WHOIS_LOCK"
	export RUN_DIR

	# run 8 workers in parallel
	cat "$ip_candidates" | xargs -P 8 -I {} bash -c '_ip_intel_worker "$@"' _ {}

	# merge per-IP JSON files into the final array
	if ls "$IP_INTEL_TMP_DIR"/*.json >/dev/null 2>&1; then
		jq -cs '.' "$IP_INTEL_TMP_DIR"/*.json >"$intel_file" 2>/dev/null || echo "[]" >"$intel_file"
	else
		echo "[]" >"$intel_file"
	fi

	rm -rf "$IP_INTEL_TMP_DIR"
	rm -f "$ip_candidates" "$WHOIS_LOCK"
	quality_check_json_array "IP enrichment" "$intel_file"
}

# Filter non-CDN host:port entries using naabu confirmed-open ports.
# Hosts WITH naabu results  → keep only naabu-confirmed ports + {80,443}
# Hosts WITH NO naabu data  → keep only 80,443 (safety net — may block naabu but serve HTTP)
# CDN entries               → caller passes only the direct/non-CDN subset here
# Edits $1 (direct targets file) in-place.
_filter_direct_targets_via_naabu() {
	local targets_file="$1"
	local naabu_json="$RUN_DIR/naabu.json"
	local direct_hosts_file="$RUN_DIR/direct_hosts.txt"
	[[ ! -s "$naabu_json" ]] && return

	local naabu_confirmed naabu_hosts direct_hosts keep_file before after
	naabu_confirmed=$(mktemp)
	naabu_hosts=$(mktemp)
	direct_hosts=$(mktemp)
	keep_file=$(mktemp)

	jq -r 'select(type=="object") | "\(.host):\(.port)"' \
		"$naabu_json" 2>/dev/null | sort -u >"$naabu_confirmed" || true

	if [[ ! -s "$naabu_confirmed" ]]; then
		rm -f "$naabu_confirmed" "$naabu_hosts" "$direct_hosts" "$keep_file"
		return
	fi

	cut -d: -f1 "$naabu_confirmed" | sort -u >"$naabu_hosts"
	# Load the known direct (non-cloud) hosts so cloud-tier entries pass through unchanged
	[[ -s "$direct_hosts_file" ]] && sort -u "$direct_hosts_file" >"$direct_hosts" || true
	before=$(wc -l <"$targets_file" | tr -d ' ')

	awk -F: -v confirmed="$naabu_confirmed" -v has_naabu_file="$naabu_hosts" -v direct_file="$direct_hosts" '
	BEGIN {
		while ((getline line < confirmed) > 0)       cset[line]=1
		while ((getline h    < has_naabu_file) > 0)  has_naabu[h]=1
		while ((getline h    < direct_file) > 0)     is_direct[h]=1
	}
	{
		host=$1; port=$2; entry=host":"port
		# Cloud-tier hosts (not in direct_hosts.txt) bypass naabu filter entirely
		if (!(host in is_direct)) {
			print $0
		} else if (host in has_naabu) {
			if ((entry in cset) || port=="80" || port=="443") print $0
		} else {
			if (port=="80" || port=="443") print $0
		}
	}' "$targets_file" >"$keep_file" || true

	mv "$keep_file" "$targets_file"
	after=$(wc -l <"$targets_file" | tr -d ' ')
	info "  → Naabu pre-filter: direct ${before} → ${after} targets (removed $(( before - after )) speculative combos)"
	rm -f "$naabu_confirmed" "$naabu_hosts" "$direct_hosts"
}

# Split a host:port file into CDN and direct subsets using cdn_hosts.txt.
# Returns 1 if cdn_hosts.txt is missing/empty so caller can fall back to monolithic pass.
_split_httpx_targets() {
	local src="$1" cdn_out="$2" direct_out="$3"
	local cdn_hosts="$RUN_DIR/cdn_hosts.txt"
	[[ ! -s "$cdn_hosts" ]] && return 1
	awk -F: 'NR==FNR{h[$1]=1;next}  ($1 in h)' "$cdn_hosts" "$src" >"$cdn_out"  || true
	awk -F: 'NR==FNR{h[$1]=1;next} !($1 in h)' "$cdn_hosts" "$src" >"$direct_out" || true
	return 0
}

# httpx tells us which services are actually talking over HTTP/S
run_httpx() {
	if [[ "$USE_HTTPX" == "true" ]]; then
		info "[15/31] Running httpx..."
		local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
		local httpx_json_file="$RUN_DIR/httpx.json"

		# skip the run if naabu came back empty-handed
		if [ ! -s "$final_urls_ports" ]; then
			warning "Input file for httpx is empty. Skipping."
			>"$httpx_json_file"
			HTTPX_LIVE_COUNT=0
			return
		fi

		# Emit a quick launch estimate so profile impact is visible in logs.
		local total_targets unique_hosts unique_ports cdn_targets direct_targets
		total_targets=$(wc -l <"$final_urls_ports" | tr -d ' ')
		unique_hosts=$(cut -d: -f1 "$final_urls_ports" | sort -u | wc -l | tr -d ' ')
		unique_ports=$(cut -d: -f2 "$final_urls_ports" | sort -u | wc -l | tr -d ' ')
		cdn_targets=0
		direct_targets=0
		if [[ -s "$RUN_DIR/cdn_hosts.txt" ]]; then
			cdn_targets=$(awk -F: 'NR==FNR{h[$1]=1; next} (($1 in h)){c++} END{print c+0}' "$RUN_DIR/cdn_hosts.txt" "$final_urls_ports")
		fi
		if [[ -s "$RUN_DIR/direct_hosts.txt" ]]; then
			direct_targets=$(awk -F: 'NR==FNR{h[$1]=1; next} (($1 in h)){c++} END{print c+0}' "$RUN_DIR/direct_hosts.txt" "$final_urls_ports")
		fi
		local rl est_seconds est_minutes
		rl="${HTTPX_RATE:-15}"
		if [[ "$rl" =~ ^[0-9]+$ ]] && (( rl > 0 )); then
			est_seconds=$(( (total_targets + rl - 1) / rl ))
		else
			est_seconds=0
		fi
		est_minutes=$(( (est_seconds + 59) / 60 ))
		info "  → httpx launch plan: targets=${total_targets} hosts=${unique_hosts} ports=${unique_ports} (cdn=${cdn_targets}, direct=${direct_targets}) est>=${est_minutes}m @rl=${rl}/s"

		local -a httpx_base_args=(
			-silent
			-t "${HTTPX_THREADS:-5}"
			-rl "${HTTPX_RATE:-15}"
			-timeout "${HTTPX_TIMEOUT_SECS:-15}"
			-retries "${HTTPX_RETRIES_COUNT:-2}"
			-follow-redirects
			-l "$final_urls_ports"
		)

		# ── Parallel CDN / Direct split ──────────────────────────────────────
		local cdn_tmp direct_tmp cdn_jsonl direct_jsonl
		cdn_tmp=$(mktemp); direct_tmp=$(mktemp)
		cdn_jsonl=$(mktemp); direct_jsonl=$(mktemp)

		local split_ok=0
		_split_httpx_targets "$final_urls_ports" "$cdn_tmp" "$direct_tmp" && split_ok=1

		if [[ "$split_ok" -eq 1 && ( -s "$cdn_tmp" || -s "$direct_tmp" ) ]]; then
			# Apply naabu filter to direct targets only (CDN bypasses naabu by design)
			[[ -s "$direct_tmp" ]] && _filter_direct_targets_via_naabu "$direct_tmp"

			# CDN timeout: cap at 4s (fast) / 5s (balanced|deep); retries always 0
			local cdn_timeout=5

			info "  → httpx CDN pass   : $(wc -l <"$cdn_tmp"    | tr -d ' ') targets  timeout=${cdn_timeout}s retries=0"
			info "  → httpx Direct pass: $(wc -l <"$direct_tmp"  | tr -d ' ') targets  timeout=${HTTPX_TIMEOUT_SECS}s retries=${HTTPX_RETRIES_COUNT}"

			# Launch both passes in parallel
			local cdn_pid="" direct_pid=""
			if [[ -s "$cdn_tmp" ]]; then
				timeout 3600 httpx -silent \
					-t "${HTTPX_THREADS:-20}" -rl "${HTTPX_RATE:-80}" \
					-timeout "$cdn_timeout" -retries 0 \
					-follow-redirects -l "$cdn_tmp" \
					-json -o "$cdn_jsonl" >/dev/null 2>&1 &
				cdn_pid=$!
			fi

			if [[ -s "$direct_tmp" ]]; then
				timeout 3600 httpx -silent \
					-t "${HTTPX_THREADS:-20}" -rl "${HTTPX_RATE:-80}" \
					-timeout "${HTTPX_TIMEOUT_SECS:-8}" -retries "${HTTPX_RETRIES_COUNT:-1}" \
					-follow-redirects -l "$direct_tmp" \
					-json -o "$direct_jsonl" >/dev/null 2>&1 &
				direct_pid=$!
			fi

			heartbeat_start "probing web endpoints with httpx"
			[[ -n "$cdn_pid"    ]] && wait "$cdn_pid"    2>/dev/null || true
			[[ -n "$direct_pid" ]] && wait "$direct_pid" 2>/dev/null || true
			heartbeat_stop

			# Merge both JSONL outputs, dedup by input+url+status_code
			{
				[[ -s "$cdn_jsonl"    ]] && cat "$cdn_jsonl"
				[[ -s "$direct_jsonl" ]] && cat "$direct_jsonl"
			} | jq -sc '
				map(select(type=="object"))
				| unique_by((.input//"") + "|" + (.url//"") + "|" + ((.status_code//0)|tostring))
				| .[]
			' >"$httpx_json_file" 2>/dev/null || true

		else
			# Fallback: cdn_hosts.txt missing or both subsets empty → monolithic pass
			info "  → httpx monolithic pass: $(wc -l <"$final_urls_ports" | tr -d ' ') targets"
			heartbeat_start "probing web endpoints with httpx"
			timeout 3600 httpx "${httpx_base_args[@]}" \
				-json \
				-o "$httpx_json_file" \
				>/dev/null || { warning "httpx timed out after 60 min — continuing with partial results."; true; }
			heartbeat_stop
		fi

		rm -f "$cdn_tmp" "$direct_tmp" "$cdn_jsonl" "$direct_jsonl"
		# ── end parallel split ────────────────────────────────────────────────

		# make sure the json file exists even if httpx stayed quiet
		if [[ ! -f "$httpx_json_file" ]]; then
			>"$httpx_json_file"
		fi

		# keep track of how many URLs actually responded
		HTTPX_LIVE_COUNT=$(wc -l <"$httpx_json_file" || echo 0)

		# quick pulse check to catch rate limits or blocking
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

		# Recovery pass: if success rate is extremely low, probe canonical 80/443
		# endpoints per host with gentler settings to avoid false negatives.
		if [[ "$naabu_target_count" -gt 10 && "$success_rate" -lt "$BLOCK_DETECTION_THRESHOLD" ]]; then
			local hosts_tmp fallback_jsonl merged_json
			hosts_tmp=$(mktemp)
			fallback_jsonl=$(mktemp)
			merged_json=$(mktemp)
			cut -d: -f1 "$final_urls_ports" | sed '/^$/d' | sort -u >"$hosts_tmp"
			if [[ -s "$hosts_tmp" ]]; then
				info "  → Low hit-rate fallback: retrying canonical web ports (80/443) on $(wc -l <"$hosts_tmp" | tr -d ' ') hosts..."
				httpx -silent -l "$hosts_tmp" -ports 80,443 -json -follow-redirects -t 10 -rl 25 -timeout 12 -retries 1 \
					-o "$fallback_jsonl" >/dev/null 2>&1 || true
				if [[ -s "$fallback_jsonl" ]]; then
					jq -sc '
						[
						  (input // []),
						  (input // [])
						] | add
						  | map(select(type=="object"))
						  | unique_by((.input // "") + "|" + (.url // "") + "|" + ((.status_code // 0)|tostring))
					' "$httpx_json_file" "$fallback_jsonl" >"$merged_json" 2>/dev/null || true
					if [[ -s "$merged_json" ]]; then
						jq -c '.[]' "$merged_json" >"$httpx_json_file" 2>/dev/null || true
					fi
				fi
			fi
			rm -f "$hosts_tmp" "$fallback_jsonl" "$merged_json"
			HTTPX_LIVE_COUNT=$(wc -l <"$httpx_json_file" || echo 0)
			success_rate=0
			if [[ "$naabu_target_count" -gt 0 ]]; then
				success_rate=$((HTTPX_LIVE_COUNT * 100 / naabu_target_count))
			fi
		fi

		# shout if we dropped below the comfort threshold
		if [[ "$BLOCK_DETECTION_THRESHOLD" -gt 0 && "$naabu_target_count" -gt 10 && "$success_rate" -lt "$BLOCK_DETECTION_THRESHOLD" ]]; then
			warning "httpx success rate ${success_rate}% fell below ${BLOCK_DETECTION_THRESHOLD}%. Results may be incomplete."
		fi

		# only talk about success rate if the sample size is worth it
		if [[ "$naabu_target_count" -gt 10 && "$BLOCK_DETECTION_THRESHOLD" -gt 0 ]]; then
			info "Web Scan Success Rate: ${success_rate}% (${HTTPX_LIVE_COUNT} live websites found / ${naabu_target_count} total live targets)"

			if [[ "$success_rate" -lt "$BLOCK_DETECTION_THRESHOLD" ]]; then
				warning "Success rate remains below the ${BLOCK_DETECTION_THRESHOLD}% threshold. Results may be incomplete (consider lowering BLOCK_DETECTION_THRESHOLD or changing IP)."
			fi
		fi
fi
}

# ─── CSP Subdomain Discovery ─────────────────────────────────────────────────
# Extracts hostnames from Content-Security-Policy headers in httpx results.
# Newly discovered and resolving hosts are probed and merged into the inventory.
run_csp_discovery() {
	local httpx_file="$RUN_DIR/httpx.json"
	local output_file="$RUN_DIR/csp_subdomains.json"
	[[ ! -s "$httpx_file" ]] && echo "[]" >"$output_file" && return

	info "  → Extracting subdomains from Content-Security-Policy headers..."
	local csp_tmp new_tmp resolved_tmp live_tmp
	csp_tmp=$(mktemp); new_tmp=$(mktemp); resolved_tmp=$(mktemp); live_tmp=$(mktemp)

	# Parse CSP header values from httpx JSONL; try multiple field names
	jq -r '
		select(type=="object") |
		(.csp // .header["content-security-policy"] // .headers["content-security-policy"] // "") |
		split(";") | .[] | split(" ") | .[] |
		ltrimstr("https://") | ltrimstr("http://") | ltrimstr("//") |
		gsub("\\*\\."; "") |
		select(test("^[a-zA-Z0-9][a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"))
	' "$httpx_file" 2>/dev/null | grep -vE "^(none|self|unsafe|data|blob)" | sort -u >"$csp_tmp" || true

	# Only keep hosts not already known
	comm -23 <(sort "$csp_tmp") <(tr '[:upper:]' '[:lower:]' <"$MASTER_SUBS" | sort) >"$new_tmp" 2>/dev/null || cp "$csp_tmp" "$new_tmp"

	if [[ -s "$new_tmp" ]]; then
		dnsx -silent -l "$new_tmp" 2>/dev/null >"$resolved_tmp" || true
		if [[ -s "$resolved_tmp" ]]; then
			local n_new
			n_new=$(wc -l <"$resolved_tmp")
			info "  → CSP discovery: ${n_new} new hosts — probing with httpx..."
			cat "$resolved_tmp" >>"$MASTER_SUBS"
			sort -u "$MASTER_SUBS" -o "$MASTER_SUBS"
			apply_exclusions "$MASTER_SUBS" "MASTER_SUBS (post-CSP)"
			while IFS= read -r host; do
				printf '%s:80\n%s:443\n' "$host" "$host"
			done <"$resolved_tmp" >"$live_tmp"
			httpx -silent -l "$live_tmp" -json -follow-redirects -timeout 10 -retries 1 2>/dev/null \
				| grep '^{' >>"$httpx_file" || true
		fi
	fi

	jq -Rc '[inputs | select(length>0)]' "$resolved_tmp" >"$output_file" 2>/dev/null || echo "[]" >"$output_file"
	rm -f "$csp_tmp" "$new_tmp" "$resolved_tmp" "$live_tmp"
}

# quick crawl with katana to widen the URL funnel
run_katana() {
info "[18/31] Crawling links with Katana..."
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

	local depth="${KATANA_DEPTH:-${KATANA_DEPTH_ADAPTIVE:-3}}"
	local timeout="${KATANA_TIMEOUT:-${KATANA_TIMEOUT_ADAPTIVE:-60}}"

	heartbeat_start "crawling with katana"
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
	heartbeat_stop

	echo "}" >>"$output_file"
}

# sniffing out login flows - parallelised with 10 workers, 2+ signal FP reduction
_login_check_worker() {
	local url="$1"
	[[ -z "$url" ]] && return
	local url_hash
	url_hash=$(printf '%s' "$url" | cksum | cut -d' ' -f1)
	local out_file="${LOGIN_TMP_DIR}/${url_hash}.json"

	local headers_file body_file curl_err
	headers_file=$(mktemp)
	body_file=$(mktemp)
	curl_err=$(mktemp)

	if ! curl -s -S -L \
		--connect-timeout "${CURL_CONNECT_TIMEOUT:-10}" \
		--max-time "${CURL_MAX_TIME:-25}" \
		-D "$headers_file" \
		-o "$body_file" \
		"$url" \
		2>"$curl_err"; then
		local curl_exit=$?
		rm -f "$headers_file" "$body_file" "$curl_err"
		if [[ $curl_exit -ne 35 ]]; then
			jq -n --arg url "$url" '{ url: $url, final_url: "", login_detection: { login_found: "No", login_details: [] } }' >"$out_file" 2>/dev/null || true
		fi
		return
	fi
	rm -f "$curl_err"

	set +e
	local final_url
	final_url=$(curl -s -S -L \
		--connect-timeout "${CURL_CONNECT_TIMEOUT:-10}" \
		--max-time "${CURL_MAX_TIME:-25}" \
		-o /dev/null -w "%{url_effective}" "$url" 2>/dev/null)
	set -e
	[[ -z "$final_url" ]] && final_url="$url"

	local -a reasons=()
	local -a strong_reasons=()

	# --- STRONG signals (each alone sufficient) ---
	if grep -qi -E '<input[^>]*type=["'"'"']password["'"'"']' "$body_file" 2>/dev/null; then
		strong_reasons+=("Found password field")
	fi
	if grep -qi -E '^HTTP/.*[[:space:]]+(401|407)' "$headers_file" 2>/dev/null; then
		strong_reasons+=("HTTP 401/407 authentication required")
	fi
	if grep -qi 'WWW-Authenticate' "$headers_file" 2>/dev/null; then
		strong_reasons+=("Found WWW-Authenticate header")
	fi

	# --- WEAK signals (need 2+ to fire) ---
	if grep -qi -E '<input[^>]*(name|id)=["'"'"']?(username|user|email|userid|loginid)' "$body_file" 2>/dev/null; then
		reasons+=("Found username/email field")
	fi
	if grep -qi -E '<form[^>]*(action|id|name)[[:space:]]*=[[:space:]]*["'"'"'][^"'"'"'>]*(login|log[-]?in|signin|auth|session|passwd|pwd|credential|oauth|token|sso)' "$body_file" 2>/dev/null; then
		reasons+=("Found form with login-related attributes")
	fi
	if grep -qi -E '(<input[^>]*type=["'"'"']submit["'"'"'][^>]*value=["'"'"']?(login|sign[[:space:]]*in|authenticate)|<button[^>]*>([[:space:]]*)?(login|sign[[:space:]]*in|authenticate))' "$body_file" 2>/dev/null; then
		reasons+=("Found submit button with login text")
	fi
	if grep -qi -E 'Forgot[[:space:]]*Password|Reset[[:space:]]*Password' "$body_file" 2>/dev/null; then
		reasons+=("Found password reset text")
	fi
	if grep -qi -E '<input[^>]*type=["'"'"']hidden["'"'"'][^>]*(csrf|token|authenticity|nonce|xsrf)' "$body_file" 2>/dev/null; then
		reasons+=("Found hidden CSRF/token field")
	fi
	if grep -qi -E '(recaptcha|g-recaptcha|hcaptcha)' "$body_file" 2>/dev/null; then
		reasons+=("Found CAPTCHA widget")
	fi
	if grep -qi -E '(loginModal|modal[-_]?login|popup[-_]?login)' "$body_file" 2>/dev/null; then
		reasons+=("Found modal/popup login hint")
	fi
	if grep -qi -E '(firebase\.auth|Auth0\.WebAuth|passport\.authenticate)' "$body_file" 2>/dev/null; then
		reasons+=("Found JavaScript auth library reference")
	fi
	if grep -qi -E 'Set-Cookie:[[:space:]]*(sessionid|PHPSESSID|JSESSIONID|auth_token|jwt)' "$headers_file" 2>/dev/null; then
		reasons+=("Found session cookie in response")
	fi
	if grep -qi -E 'Location:.*(login|signin|auth)' "$headers_file" 2>/dev/null; then
		reasons+=("Found redirect to login URL")
	fi
	if echo "$final_url" | grep -qiE '/(login|signin|auth|wp-login\.php|wp-admin|users/sign_in|member/login|login\.aspx|signin\.aspx)' 2>/dev/null; then
		reasons+=("Final URL path suggests login endpoint")
	fi
	if grep -qi -E '(iniciar[[:space:]]+sesi|connexion|anmelden|accedi|entrar|inloggen)' "$body_file" 2>/dev/null; then
		reasons+=("Found multi-language login keyword")
	fi

	rm -f "$headers_file" "$body_file"

	# --- decision: strong single OR 2+ weak signals ---
	local login_found="No"
	local -a all_reasons=("${strong_reasons[@]}")
	if [[ "${#strong_reasons[@]}" -gt 0 ]]; then
		login_found="Yes"
	elif [[ "${#reasons[@]}" -ge 2 ]]; then
		login_found="Yes"
		all_reasons+=("${reasons[@]}")
	fi

	local json_details
	json_details=$(printf '%s\n' "${all_reasons[@]:-none}" | grep -v '^none$' | jq -R . 2>/dev/null | jq -s . 2>/dev/null || echo '[]')

	jq -n \
		--arg url "$url" \
		--arg final_url "$final_url" \
		--arg login_found "$login_found" \
		--argjson details "$json_details" \
		'{ url: $url, final_url: $final_url, login_detection: { login_found: $login_found, login_details: $details } }' \
		>"$out_file" 2>/dev/null || true
}
export -f _login_check_worker

run_login_detection() {
	info "[21/31] Detecting Login panels (parallel workers)..."
	local input_file="$RUN_DIR/httpx.json"
	local output_file="$RUN_DIR/login.json"

	: "${CURL_CONNECT_TIMEOUT:=10}"
	: "${CURL_MAX_TIME:=25}"

	if [[ ! -f "$input_file" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "Login detection" "$output_file"
		return
	fi
	if ! command -v jq >/dev/null 2>&1; then
		echo "[]" >"$output_file"
		quality_check_json_array "Login detection" "$output_file"
		return
	fi

	export LOGIN_TMP_DIR="$RUN_DIR/login_tmp"
	mkdir -p "$LOGIN_TMP_DIR"
	export CURL_CONNECT_TIMEOUT CURL_MAX_TIME RUN_DIR

	local urls_file="$RUN_DIR/login_urls.txt"
	jq -r 'if type=="array" then .[].url else .url end' "$input_file" 2>/dev/null | grep -v '^null$' | sort -u >"$urls_file" || true

	if [[ -s "$urls_file" ]]; then
		cat "$urls_file" | xargs -P 10 -I {} bash -c '_login_check_worker "$@"' _ {}
	fi
	rm -f "$urls_file"

	# merge per-URL results
	if ls "$LOGIN_TMP_DIR"/*.json >/dev/null 2>&1; then
		local count
		count=$(ls "$LOGIN_TMP_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ')
		LOGIN_FOUND_COUNT=$(grep -l '"login_found": "Yes"' "$LOGIN_TMP_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ' || echo 0)
		jq -cs '.' "$LOGIN_TMP_DIR"/*.json >"$output_file" 2>/dev/null || echo "[]" >"$output_file"
	else
		echo "[]" >"$output_file"
	fi

	rm -rf "$LOGIN_TMP_DIR"
	quality_check_json_array "Login detection" "$output_file"
}

# using tlsx to grab cert metadata and expiry windows
run_tls_inventory() {
	info "[22/31] Building TLS certificate inventory..."
	local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
	local tls_json="$RUN_DIR/tls_inventory.json"
	local tlsx_raw="$RUN_DIR/tls_inventory_raw.jsonl"
	local tlsx_log="$RUN_DIR/logs/tlsx.log"

	if [[ ! -s "$final_urls_ports" ]]; then
		info "No open ports detected; TLS inventory will be empty."
		echo "[]" >"$tls_json"
		quality_check_json_array "TLS inventory" "$tls_json"
		return
	fi

	heartbeat_start "scanning TLS certificates with tlsx"
	if ! timeout 1200 tlsx -l "$final_urls_ports" -j >"$tlsx_raw" 2>>"$tlsx_log"; then
		heartbeat_stop
		warning "tlsx scan failed or timed out after 20 min; TLS inventory will be empty. Check $tlsx_log for details."
		echo "[]" >"$tls_json"
		rm -f "$tlsx_raw"
		quality_check_json_array "TLS inventory" "$tls_json"
		return
	fi
	heartbeat_stop

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
				SNI: (.sni // ""),
				PublicKeyBits: (.public_key_bits // null),
				PublicKeyAlgo: (.public_key_algo // "")
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

	# add SSL/TLS letter grade (A+ A B C D F) based on version + cipher + expiry
	if [[ -s "$tls_json" ]]; then
		local now_ts
		now_ts=$(date +%s)
		local tmp_graded
		tmp_graded=$(mktemp)
		jq --argjson now "$now_ts" '
			map(
				. as $rec |
				($rec.TLSVersion // "") as $ver |
				($rec.DaysUntilExpiry // 9999) as $days |
				($rec.ProbeStatus // false) as $ok |
				($rec.Cipher // "" | ascii_downcase) as $cipher |
				(
					if ($ok | not) then "F"
					elif ($days < 0) then "F"
					elif ($ver == "SSL 3.0") then "F"
					elif ($ver == "TLS 1.0") then "D"
					elif ($ver == "TLS 1.1") then "C"
					elif ($ver == "TLS 1.2") then
						(if ($days <= 30) then "B"
						 elif ($cipher | test("rc4|des|null|export|anon"; "i")) then "B"
						 else "A"
						 end)
					elif ($ver == "TLS 1.3") then
						(if ($days >= 30) then "A+"
						 else "A"
						 end)
					else "B"
					end
				) as $grade |
				$rec + { TLSGrade: $grade }
			)
		' "$tls_json" >"$tmp_graded" 2>/dev/null && mv "$tmp_graded" "$tls_json" || rm -f "$tmp_graded"
	fi

	quality_check_json_array "TLS inventory" "$tls_json"
	rm -f "$tlsx_raw"
}

# per-domain compliance worker (called in parallel via xargs)
_compliance_domain_worker() {
	local domain="$1"
	[[ -z "$domain" ]] && return
	local domain_key
	domain_key=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
	local dig_opts=("+time=3" "+tries=1")

	local dns_entry
	dns_entry=$(jq -c --arg key "$domain_key" '.[$key] // null' "$COMP_DNS_MAP" 2>/dev/null || echo null)
	local dns_status="" dns_resolvers="" dns_a="" dns_cname=""
	if [[ "$dns_entry" != "null" ]]; then
		dns_status=$(echo "$dns_entry" | jq -r '.status // ""' 2>/dev/null || true)
		dns_resolvers=$(echo "$dns_entry" | jq -r '(.resolver // []) | join("\n")' 2>/dev/null || true)
		dns_a=$(echo "$dns_entry" | jq -r '(.a // []) | join("\n")' 2>/dev/null || true)
		dns_cname=$(echo "$dns_entry" | jq -r '(.cname // []) | join("\n")' 2>/dev/null || true)
	fi

	local spf dkim dmarc dnskey dnssec ns txt srv ptr mx soa caa
	local a_records aaaa_records cname_records zone_transfer whois_summary
	local bimi_record mta_sts_dns mta_sts_mode dane_tlsa_443 dane_tlsa_25 dane_tlsa

	spf=$(dig "${dig_opts[@]}" +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" | head -n 1 || true)
	[ -z "$spf" ] && spf="No SPF Record"
	dkim=$(dig "${dig_opts[@]}" +short TXT "default._domainkey.$domain" 2>/dev/null | grep -i "v=DKIM1" | head -n 1 || true)
	[ -z "$dkim" ] && dkim="No DKIM Record"
	dmarc=$(dig "${dig_opts[@]}" +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC1" | head -n 1 || true)
	[ -z "$dmarc" ] && dmarc="No DMARC Record"
	dnskey=$(dig "${dig_opts[@]}" +short DNSKEY "$domain" 2>/dev/null || true)
	[[ -z "$dnskey" ]] && dnssec="DNSSEC Not Enabled" || dnssec="DNSSEC Enabled"
	ns=$(dig "${dig_opts[@]}" +short NS "$domain" 2>/dev/null || true)
	[ -z "$ns" ] && ns="No NS records found"
	txt=$(dig "${dig_opts[@]}" +short TXT "$domain" 2>/dev/null || true)
	srv=$(dig "${dig_opts[@]}" +short SRV "$domain" 2>/dev/null || true)
	a_records="$dns_a"
	[ -z "$a_records" ] && a_records=$(dig "${dig_opts[@]}" +short A "$domain" 2>/dev/null | sed '/^$/d' || true)
	local a_record=""
	ptr=""
	[ -n "$a_records" ] && a_record=$(printf '%s\n' "$a_records" | head -n 1)
	[ -n "$a_record" ] && ptr=$(dig "${dig_opts[@]}" +short -x "$a_record" 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true)
	aaaa_records=$(dig "${dig_opts[@]}" +short AAAA "$domain" 2>/dev/null | sed '/^$/d' || true)
	cname_records="$dns_cname"
	[ -z "$cname_records" ] && cname_records=$(dig "${dig_opts[@]}" +short CNAME "$domain" 2>/dev/null | sed '/^$/d' || true)
	mx=$(dig "${dig_opts[@]}" +short MX "$domain" 2>/dev/null || true)
	soa=$(dig "${dig_opts[@]}" +short SOA "$domain" 2>/dev/null || true)
	caa=$(dig "${dig_opts[@]}" +short CAA "$domain" 2>/dev/null || true)

	# BIMI
	bimi_record=$(dig "${dig_opts[@]}" +short TXT "default._bimi.$domain" 2>/dev/null | tr -d '"' | head -1 || true)
	[ -z "$bimi_record" ] && bimi_record="Not Found"

	# MTA-STS DNS signal
	mta_sts_dns=$(dig "${dig_opts[@]}" +short TXT "_mta-sts.$domain" 2>/dev/null | tr -d '"' | head -1 || true)
	mta_sts_mode="not-found"
	[[ -n "$mta_sts_dns" ]] && mta_sts_mode=$(echo "$mta_sts_dns" | grep -oP 'mode=\K\w+' | head -1 || echo "found")

	# DANE/TLSA — check port 443 + 25
	dane_tlsa_443=$(dig "${dig_opts[@]}" +short TLSA "_443._tcp.$domain" 2>/dev/null | head -1 || true)
	dane_tlsa_25=$(dig "${dig_opts[@]}" +short TLSA "_25._tcp.$domain" 2>/dev/null | head -1 || true)
	dane_tlsa="Not Found"
	[[ -n "$dane_tlsa_443" ]] && dane_tlsa="port443: $dane_tlsa_443"
	[[ -n "$dane_tlsa_25"  ]] && dane_tlsa="${dane_tlsa/#Not Found/}${dane_tlsa:+$([[ "$dane_tlsa" != "Not Found" ]] && echo " | ")}port25: $dane_tlsa_25"
	# simplify dane_tlsa if only port25
	[[ -z "$dane_tlsa_443" && -n "$dane_tlsa_25" ]] && dane_tlsa="port25: $dane_tlsa_25"

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
			[ -z "$axfr_output" ] && continue
			echo "$axfr_output" | grep -qiE 'transfer failed|timed out|refused|denied|not implemented|connection refused|SERVFAIL' && continue
			if echo "$axfr_output" | grep -q $'\tIN\t'; then
				zone_transfer="AXFR Permitted via $ns_host"
				break
			fi
		done <<<"$ns"
	fi

	# rate-limited WHOIS
	if ! command -v whois >/dev/null 2>&1; then
		whois_summary="WHOIS client unavailable"
	else
		local whois_raw
		(flock -x 200; whois "$domain" 2>/dev/null || true) 200>"${COMP_WHOIS_LOCK}" >"${RUN_DIR}/.whois_tmp_${domain_key//[^a-z0-9]/_}" 2>/dev/null || true
		whois_raw=$(cat "${RUN_DIR}/.whois_tmp_${domain_key//[^a-z0-9]/_}" 2>/dev/null || true)
		rm -f "${RUN_DIR}/.whois_tmp_${domain_key//[^a-z0-9]/_}"
		if echo "$whois_raw" | grep -qiE 'limit exceeded|quota exceeded|rate limit|exceeded the maximum number|WHOIS LIMIT'; then
			whois_summary="WHOIS query cap reached"
		elif [ -z "$whois_raw" ]; then
			whois_summary="WHOIS data unavailable"
		else
			local registrar created updated expires registrant_org registrant_country
		registrar=""; created=""; updated=""; expires=""; registrant_org=""; registrant_country=""
			for pattern in "Registrar:" "Sponsoring Registrar:" "Registrar Name:"; do
				registrar=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
				[ -n "$registrar" ] && break
			done
			for pattern in "Creation Date:" "Created On:" "Registered On:"; do
				created=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
				[ -n "$created" ] && break
			done
			for pattern in "Updated Date:" "Last Updated On:" "Modified:"; do
				updated=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
				[ -n "$updated" ] && break
			done
			for pattern in "Expiration Date:" "Expiry Date:" "Registry Expiry Date:"; do
				expires=$(echo "$whois_raw" | grep -i "$pattern" | head -n 1 | cut -d':' -f2- | xargs || true)
				[ -n "$expires" ] && break
			done
			for pattern in "Registrant Organization:" "OrgName:"; do
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
	tls_entry=$(jq -c --arg key "$domain_key" '.[$key] // []' "$COMP_TLS_HOST_MAP" 2>/dev/null || echo '[]')
	if [[ "$tls_entry" != "[]" ]]; then
		ssl_version=$(echo "$tls_entry" | jq -r '[.[]? | (.TLSVersion // .HighestVersion // .VersionSummary) | select(. != null and . != "")] | first? // "N/A"' 2>/dev/null || echo "N/A")
		ssl_issuer=$(echo "$tls_entry" | jq -r '[.[]? | (.IssuerDN // .CertificateIssuer // .IssuerCN) | select(. != null and . != "")] | first? // "N/A"' 2>/dev/null || echo "N/A")
		cert_expiry=$(echo "$tls_entry" | jq -r '[.[]? | (.NotAfter // .ValidTo) | select(. != null and . != "")] | first? // "N/A"' 2>/dev/null || echo "N/A")
	else
		ssl_version="N/A"; ssl_issuer="N/A"; cert_expiry="N/A"
	fi

	local safe_key="${domain_key//[^a-z0-9._-]/_}"
	# pull structured whois fields from whois_summary context (set during whois block)
	local _reg _created _expires _reg_org _reg_country
	_reg="${registrar:-}"; _created="${created:-}"; _expires="${expires:-}"
	_reg_org="${registrant_org:-}"; _reg_country="${registrant_country:-}"
	jq -n \
		--arg domain "$domain" \
		--arg url "N/A" \
		--arg spf "$spf" \
		--arg dkim "$dkim" \
		--arg dmarc "$dmarc" \
		--arg dnssec "$dnssec" \
		--arg ns "$ns" \
		--arg txt "${txt:-}" \
		--arg srv "${srv:-}" \
		--arg ptr "${ptr:-}" \
		--arg mx "${mx:-}" \
		--arg soa "${soa:-}" \
		--arg caa "${caa:-}" \
		--arg arecords "${a_records:-}" \
		--arg aaaarecords "${aaaa_records:-}" \
		--arg cname "${cname_records:-}" \
		--arg zonetransfer "$zone_transfer" \
		--arg whois "$whois_summary" \
		--arg ssl_version "$ssl_version" \
		--arg ssl_issuer "$ssl_issuer" \
		--arg cert_expiry "$cert_expiry" \
		--arg dns_status "${dns_status:-}" \
		--arg resolvers "${dns_resolvers:-}" \
		--arg bimi "$bimi_record" \
		--arg mta_sts "$mta_sts_mode" \
		--arg dane "$dane_tlsa" \
		--arg registrar "$_reg" \
		--arg domain_created "$_created" \
		--arg domain_expires "$_expires" \
		--arg registrant_org "$_reg_org" \
		--arg registrant_country "$_reg_country" \
		'{
			Domain: $domain, URL: $url,
			"SPF Record": $spf, "DKIM Record": $dkim, "DMARC Record": $dmarc,
			"DNSSEC Status": $dnssec, "NS Records": $ns, "TXT Records": $txt,
			"SRV Records": $srv, "PTR Record": $ptr, "MX Records": $mx,
			"SOA Record": $soa, "CAA Records": $caa,
			"A Records": $arecords, "AAAA Records": $aaaarecords,
			"CNAME Records": $cname, "Zone Transfer": $zonetransfer,
			"WHOIS Summary": $whois,
			"Registrar": $registrar,
			"DomainCreated": $domain_created,
			"DomainExpires": $domain_expires,
			"RegistrantOrg": $registrant_org,
			"RegistrantCountry": $registrant_country,
			"BIMI Record": $bimi,
			"MTA-STS": $mta_sts,
			"DANE/TLSA": $dane,
			"SSL/TLS Version": $ssl_version, "SSL/TLS Issuer": $ssl_issuer,
			"Cert Expiry Date": $cert_expiry,
			"DNS Resolver": $resolvers, "DNS Status": $dns_status
		}' >"${COMP_COMPLIANCE_TMP}/${safe_key}.jsonl" 2>/dev/null || true

	# HTTP header check per endpoint
	local domain_http_file="${COMP_HTTPX_SPLIT}/${domain}.jsonl"
	if [[ -f "$domain_http_file" ]]; then
		while IFS= read -r record_line || [[ -n "$record_line" ]]; do
			[[ -z "$record_line" ]] && continue
			local url host port
			url=$(jq -r '.url // ""' <<<"$record_line" 2>/dev/null || true)
			[[ -z "$url" ]] && continue
			if [[ "$url" =~ ^https?://([^/:]+)(:([0-9]+))? ]]; then
				host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[3]}
			else
				host=""; port=""
			fi
			if [ -z "$port" ]; then
				[[ "$url" =~ ^https:// ]] && port="443" || port="80"
			fi

			local lookup_host
			lookup_host=$(echo "$host" | tr '[:upper:]' '[:lower:]')
			[[ -z "$lookup_host" ]] && lookup_host="$domain_key"
			local endpoint_lookup="${lookup_host}|${port}"
			local tls_endpoint
			tls_endpoint=$(jq -c --arg key "$endpoint_lookup" '.[$key] // null' "$COMP_TLS_ENDPOINT_MAP" 2>/dev/null || echo null)
			local ssl_version_ep ssl_issuer_ep cert_expiry_ep
			if [[ "$tls_endpoint" != "null" ]]; then
				ssl_version_ep=$(echo "$tls_endpoint" | jq -r '.TLSVersion // .HighestVersion // "Unknown"' 2>/dev/null || echo "Unknown")
				ssl_issuer_ep=$(echo "$tls_endpoint" | jq -r '.IssuerDN // .CertificateIssuer // .IssuerCN // "N/A"' 2>/dev/null || echo "N/A")
				cert_expiry_ep=$(echo "$tls_endpoint" | jq -r '.NotAfter // .ValidTo // "N/A"' 2>/dev/null || echo "N/A")
			else
				ssl_version_ep="No SSL/TLS"; ssl_issuer_ep="N/A"; cert_expiry_ep="N/A"
			fi

			local headers
			headers=$(curl -s --max-time 15 --connect-timeout 5 -D - "$url" -o /dev/null 2>/dev/null || true)
			local sts xfo csp xss rp pp acao
			sts=$(echo "$headers" | grep -i "Strict-Transport-Security:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			xfo=$(echo "$headers" | grep -i "X-Frame-Options:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			csp=$(echo "$headers" | grep -i "Content-Security-Policy:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			xss=$(echo "$headers" | grep -i "X-XSS-Protection:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			rp=$(echo "$headers" | grep -i "Referrer-Policy:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			pp=$(echo "$headers" | grep -i "Permissions-Policy:" | cut -d':' -f2- | xargs 2>/dev/null || true)
			acao=$(echo "$headers" | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs 2>/dev/null || true)

			# cookie security analysis
			local cookie_secure="N/A" cookie_httponly="N/A" cookie_samesite="N/A"
			local set_cookie_line
			set_cookie_line=$(echo "$headers" | grep -i "^Set-Cookie:" | head -n 1 || true)
			if [[ -n "$set_cookie_line" ]]; then
				echo "$set_cookie_line" | grep -qi ";\s*Secure" && cookie_secure="Yes" || cookie_secure="No"
				echo "$set_cookie_line" | grep -qi ";\s*HttpOnly" && cookie_httponly="Yes" || cookie_httponly="No"
				local ss_val
				ss_val=$(echo "$set_cookie_line" | grep -oi "SameSite=[A-Za-z]*" | cut -d'=' -f2 || true)
				[[ -n "$ss_val" ]] && cookie_samesite="$ss_val" || cookie_samesite="Not Set"
			fi

			# CORS status
			local cors_status="Unconfigured"
			if [[ -n "$acao" ]]; then
				if [[ "$acao" == "*" ]]; then
					cors_status="Open"
				elif echo "$acao" | grep -qi "null"; then
					cors_status="Null-Origin"
				else
					# check for reflective CORS
					local cors_probe
					cors_probe=$(curl -s --max-time 8 --connect-timeout 4 \
						-H "Origin: https://evil-cors-test.com" \
						-I "$url" 2>/dev/null | grep -i "Access-Control-Allow-Origin:" | cut -d':' -f2- | xargs 2>/dev/null || true)
					if echo "$cors_probe" | grep -qi "evil-cors-test.com"; then
						cors_status="Reflective"
					else
						cors_status="Restrictive"
					fi
				fi
			fi

			local url_hash
			url_hash=$(printf '%s' "${domain_key}${url}" | cksum | cut -d' ' -f1)
			jq -n \
				--arg domain "$domain" \
				--arg url "$url" \
				--arg ssl_version "$ssl_version_ep" \
				--arg ssl_issuer "$ssl_issuer_ep" \
				--arg cert_expiry "$cert_expiry_ep" \
				--arg sts "${sts:-}" \
				--arg xfo "${xfo:-}" \
				--arg csp "${csp:-}" \
				--arg xss "${xss:-}" \
				--arg rp "${rp:-}" \
				--arg pp "${pp:-}" \
				--arg acao "${acao:-}" \
				--arg cookie_secure "$cookie_secure" \
				--arg cookie_httponly "$cookie_httponly" \
				--arg cookie_samesite "$cookie_samesite" \
				--arg cors_status "$cors_status" \
				'{
					Domain: $domain, URL: $url,
					"SSL/TLS Version": $ssl_version, "SSL/TLS Issuer": $ssl_issuer,
					"Cert Expiry Date": $cert_expiry,
					"Strict-Transport-Security": $sts, "X-Frame-Options": $xfo,
					"Content-Security-Policy": $csp, "X-XSS-Protection": $xss,
					"Referrer-Policy": $rp, "Permissions-Policy": $pp,
					"Access-Control-Allow-Origin": $acao,
					"Cookie-Secure": $cookie_secure,
					"Cookie-HttpOnly": $cookie_httponly,
					"Cookie-SameSite": $cookie_samesite,
					"CORS-Status": $cors_status
				}' >"${COMP_HEADERS_TMP}/${url_hash}.jsonl" 2>/dev/null || true
		done <"$domain_http_file"
	fi
}
export -f _compliance_domain_worker

# checking DNS hygiene, email auth, and handy headers in one pass (parallelised)
run_security_compliance() {
	info "[23/31] Analyzing security hygiene (parallel workers)..."
	local compliance_output="$RUN_DIR/securitycompliance.json"
	local headers_output="$RUN_DIR/sec_headers.json"

	if [ ! -f "$MASTER_SUBS" ]; then
		echo "Error: MASTER_SUBS file not found!" >&2
		return 1
	fi

	# build shared read-only map files for workers
	export COMP_DNS_MAP
	COMP_DNS_MAP=$(mktemp)
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
		' "$RUN_DIR/dnsx.json" >"$COMP_DNS_MAP" 2>/dev/null || echo "{}" >"$COMP_DNS_MAP"
	else
		echo "{}" >"$COMP_DNS_MAP"
	fi

	export COMP_TLS_HOST_MAP COMP_TLS_ENDPOINT_MAP
	COMP_TLS_HOST_MAP=$(mktemp)
	COMP_TLS_ENDPOINT_MAP=$(mktemp)
	if [[ -s "$RUN_DIR/tls_inventory.json" ]]; then
		jq -c '
			group_by(((.Host // .host // "") | ascii_downcase)) |
			map({ key: (.[0].Host // .[0].host // "" | ascii_downcase), value: . }) |
			map(select(.key != "")) |
			from_entries
		' "$RUN_DIR/tls_inventory.json" >"$COMP_TLS_HOST_MAP" 2>/dev/null || echo "{}" >"$COMP_TLS_HOST_MAP"
		jq -c '
			map(select(((.Host // .host // "") | length) > 0 and ((.Port // .port // "") | tostring | length) > 0)) |
			map({
				key: (((.Host // .host // "") | ascii_downcase) + "|" + ((.Port // .port // "") | tostring)),
				value: .
			}) |
			map(select(.key | length > 1)) |
			from_entries
		' "$RUN_DIR/tls_inventory.json" >"$COMP_TLS_ENDPOINT_MAP" 2>/dev/null || echo "{}" >"$COMP_TLS_ENDPOINT_MAP"
	else
		echo "{}" >"$COMP_TLS_HOST_MAP"
		echo "{}" >"$COMP_TLS_ENDPOINT_MAP"
	fi

	export COMP_HTTPX_SPLIT
	COMP_HTTPX_SPLIT=$(mktemp -d)
	if [ -s "$RUN_DIR/httpx.json" ]; then
		while IFS=$'\t' read -r dom record; do
			dom=$(echo "$dom" | tr -d '\r' | xargs)
			[[ -z "$dom" || -z "$record" ]] && continue
			printf '%s\n' "$record" >>"$COMP_HTTPX_SPLIT/${dom}.jsonl"
		done < <(jq -rc '(if type=="array" then .[] else . end) | [((.input // .url // .host // "") | sub("^https?://"; "") | split("/")[0] | split(":")[0]), tostring] | @tsv' "$RUN_DIR/httpx.json")
	fi

	export COMP_COMPLIANCE_TMP="$RUN_DIR/comp_compliance_tmp"
	export COMP_HEADERS_TMP="$RUN_DIR/comp_headers_tmp"
	mkdir -p "$COMP_COMPLIANCE_TMP" "$COMP_HEADERS_TMP"

	export COMP_WHOIS_LOCK="$RUN_DIR/.comp_whois.lock"
	touch "$COMP_WHOIS_LOCK"
	export RUN_DIR MASTER_SUBS

	# run 20 domain workers in parallel
	cat "$MASTER_SUBS" | xargs -P 20 -I {} bash -c '_compliance_domain_worker "$@"' _ {}

	# merge compliance results
	local compliance_jsonl="$RUN_DIR/securitycompliance.jsonl"
	: >"$compliance_jsonl"
	if ls "$COMP_COMPLIANCE_TMP"/*.jsonl >/dev/null 2>&1; then
		cat "$COMP_COMPLIANCE_TMP"/*.jsonl >"$compliance_jsonl" 2>/dev/null || true
	fi
	combine_json "$compliance_jsonl" "$compliance_output"
	rm -f "$compliance_jsonl"

	# merge headers results
	local headers_jsonl="$RUN_DIR/sec_headers.jsonl"
	: >"$headers_jsonl"
	if ls "$COMP_HEADERS_TMP"/*.jsonl >/dev/null 2>&1; then
		cat "$COMP_HEADERS_TMP"/*.jsonl >"$headers_jsonl" 2>/dev/null || true
	fi
	combine_json "$headers_jsonl" "$headers_output"
	rm -f "$headers_jsonl"

	rm -rf "$COMP_COMPLIANCE_TMP" "$COMP_HEADERS_TMP" "$COMP_HTTPX_SPLIT"
	rm -f "$COMP_DNS_MAP" "$COMP_TLS_HOST_MAP" "$COMP_TLS_ENDPOINT_MAP" "$COMP_WHOIS_LOCK"
	quality_check_json_array "Security compliance" "$compliance_output"
	quality_check_json_array "Security headers" "$headers_output"
}

# turning jsonl blobs into tidy arrays for later steps
# Uses a two-pass approach: fast jq first, line-by-line fallback if malformed lines exist
combine_json() {
	local infile="$1"
	local outfile="$2"
	if [[ -f "$infile" ]]; then
		jq -cs '.' "$infile" >"$outfile" 2>/dev/null \
			|| jq -Rn '[inputs | fromjson? | select(type == "object")]' "$infile" >"$outfile" 2>/dev/null \
			|| echo "[]" >"$outfile"
	else
		echo "[]" >"$outfile"
	fi
}

# multi-signal API identification (domain keyword + content-type)
run_api_identification() {
	info "[26/31] Identifying API endpoints (multi-signal)..."
	local api_file="$RUN_DIR/api_identification.json"
	local api_jsonl="$RUN_DIR/api_identification.jsonl"
	: >"$api_jsonl"

	# pre-build a map of content-types from httpx for quick lookup
	local ct_map_file
	ct_map_file=$(mktemp)
	if [[ -s "$RUN_DIR/httpx.json" ]]; then
		jq -cs '
			[ .[] | if type=="array" then .[] else . end | select(type=="object") ]
			| group_by(((.input // .host // "") | split(":")[0] | ascii_downcase))
			| map({
				key: ((.[0].input // .[0].host // "") | split(":")[0] | ascii_downcase),
				value: {
					content_type: (map(.content_type // "") | map(select(length>0)) | first // ""),
					status: (map(.status_code // 0) | first // 0)
				}
			})
			| from_entries
		' "$RUN_DIR/httpx.json" >"$ct_map_file" 2>/dev/null || echo "{}" >"$ct_map_file"
	else
		echo "{}" >"$ct_map_file"
	fi

	while read -r domain; do
		local domain_key
		domain_key=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
		local -a signals=()
		local confidence="Low"

		# signal 1: domain name keyword (weak)
		if echo "$domain" | grep -qiE '(\.api\.|-api[-.]|^api\.)'; then
			signals+=("domain-keyword")
		fi

		# signal 2: content-type from httpx (strong)
		local ct
		ct=$(jq -r --arg key "$domain_key" '.[$key].content_type // ""' "$ct_map_file" 2>/dev/null || true)
		if echo "$ct" | grep -qiE 'application/(json|xml|graphql|hal\+json|vnd\.|problem\+json)'; then
			signals+=("json-content-type")
			confidence="High"
		fi

		# determine api_endpoint status
		local api_status="No"
		[[ "${#signals[@]}" -ge 1 ]] && api_status="Yes"

		local signals_json='[]'
		(( ${#signals[@]} )) && signals_json=$(printf '%s\n' "${signals[@]}" | jq -R . 2>/dev/null | jq -s . 2>/dev/null || echo '[]')

		jq -n \
			--arg domain "$domain" \
			--arg api_endpoint "$api_status" \
			--arg api_confidence "$confidence" \
			--argjson signals "$signals_json" \
			'{ domain: $domain, api_endpoint: $api_endpoint, api_confidence: $api_confidence, api_signals: $signals }' \
			>>"$api_jsonl" 2>/dev/null || true
	done <"$MASTER_SUBS"

	combine_json "$api_jsonl" "$api_file"
	rm -f "$api_jsonl" "$ct_map_file"
	quality_check_json_array "API detection" "$api_file"
}

# looking for intranet-ish names so the team sees potential internal portals
run_colleague_identification() {
info "[27/31] Identifying colleague-facing endpoints..."
	local colleague_file="$RUN_DIR/colleague_identification.json"
	local keywords_file="$SCRIPT_DIR/assets/lists/colleague-keywords.txt"

	if [ ! -f "$keywords_file" ]; then
		warning "Keywords file '$keywords_file' not found. Skipping."
		echo "[]" >"$colleague_file"
		return
	fi
	# pull keywords into an array and trim the junk spaces
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
		# lowercase everything so comparisons behave
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
	quality_check_json_array "Colleague detection" "$colleague_file"
}

# stitching DNS, HTTP, and TLS bits into a single cloud story
run_cloud_infrastructure_inventory() {
	info "[30/31] Building cloud infrastructure inventory..."
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

	quality_check_json_array "Cloud inventory" "$output_file"
	rm -f "$dns_map_file" "$httpx_map_file" "$tls_map_file"
}


# --- NEW MODULE: Subdomain Takeover Detection ---
run_subdomain_takeover() {
	info "[11/31] Detecting dangling DNS / subdomain takeover candidates..."
	local output_file="$RUN_DIR/takeover.json"
	local fingerprints_file="$SCRIPT_DIR/assets/lists/takeover_fingerprints.json"

	if [[ ! -s "$RUN_DIR/dnsx.json" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "Takeover detection" "$output_file"
		return
	fi
	if [[ ! -f "$fingerprints_file" ]]; then
		warning "Takeover fingerprints file not found at $fingerprints_file; skipping."
		echo "[]" >"$output_file"
		return
	fi

	local jsonl_tmp="$RUN_DIR/takeover.jsonl"
	: >"$jsonl_tmp"

	# extract domains with CNAMEs from dnsx output
	local cname_pairs
	cname_pairs=$(jq -r '
		(if type=="array" then .[] else . end)
		| select(type=="object")
		| select((.cname // []) | length > 0)
		| .host as $host
		| (.cname // [])[] as $cname
		| [$host, $cname] | @tsv
	' "$RUN_DIR/dnsx.json" 2>/dev/null || true)

	if [[ -z "$cname_pairs" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "Takeover detection" "$output_file"
		return
	fi

	local fingerprints_json
	fingerprints_json=$(cat "$fingerprints_file")

	while IFS=$'\t' read -r host cname; do
		[[ -z "$host" || -z "$cname" ]] && continue
		local cname_lower
		cname_lower=$(echo "$cname" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')

		# check if CNAME resolves (if not → dangling)
		local resolves
		resolves=$(dig +short +time=3 +tries=1 A "$cname" 2>/dev/null | head -n 1 || true)
		local nxdomain=false
		[[ -z "$resolves" ]] && nxdomain=true

		# match cname against fingerprint patterns
		local matched_provider="" matched_body_pattern="" severity="low"
		while IFS= read -r fp; do
			local provider
			provider=$(echo "$fp" | jq -r '.provider' 2>/dev/null || true)
			local cname_pats
			cname_pats=$(echo "$fp" | jq -r '.cname_patterns[]' 2>/dev/null || true)
			local matched_cname=false
			while IFS= read -r pat; do
				[[ -z "$pat" ]] && continue
				if echo "$cname_lower" | grep -qi "$pat"; then
					matched_cname=true
					matched_provider="$provider"
					severity=$(echo "$fp" | jq -r '.severity // "low"' 2>/dev/null || echo "low")
					matched_body_pattern=$(echo "$fp" | jq -r '.body_patterns | join("|")' 2>/dev/null || true)
					break
				fi
			done <<<"$cname_pats"
			[[ "$matched_cname" == true ]] && break
		done < <(echo "$fingerprints_json" | jq -c '.[]' 2>/dev/null || true)

		[[ -z "$matched_provider" ]] && continue

		local status="Potential"
		local evidence="Dangling CNAME to ${matched_provider}"

		# if dangling, try to confirm by fetching the unclaimed-app error page
		if [[ "$nxdomain" == true ]] && [[ -n "$matched_body_pattern" ]]; then
			local http_resp
			http_resp=$(curl -sL --max-time 8 --connect-timeout 4 "https://${host}" 2>/dev/null || \
				curl -sL --max-time 8 --connect-timeout 4 "http://${host}" 2>/dev/null || true)
			if echo "$http_resp" | grep -qiE "$matched_body_pattern"; then
				status="Confirmed"
				evidence="Unclaimed ${matched_provider} endpoint: body matches '${matched_body_pattern}'"
			fi
		elif [[ "$nxdomain" == false ]]; then
			status="Safe"
			evidence="CNAME resolves to ${resolves}"
		fi

		jq -n \
			--arg domain "$host" \
			--arg cname_target "$cname" \
			--arg provider "$matched_provider" \
			--arg status "$status" \
			--arg severity "$severity" \
			--arg evidence "$evidence" \
			'{ domain: $domain, cname_target: $cname_target, provider: $provider, status: $status, severity: $severity, evidence: $evidence }' \
			>>"$jsonl_tmp" 2>/dev/null || true
	done <<<"$cname_pairs"

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
	quality_check_json_array "Takeover detection" "$output_file"
}

# --- NEW MODULE: JavaScript File Analysis ---
run_js_analysis() {
	info "[19/31] Analyzing JavaScript files for endpoints and secrets..."
	local output_file="$RUN_DIR/js_analysis.json"
	local jsonl_tmp="$RUN_DIR/js_analysis.jsonl"
	: >"$jsonl_tmp"

	if [[ ! -s "$RUN_DIR/katana_links.json" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "JS analysis" "$output_file"
		return
	fi

	# extract all .js URLs from katana output
	local js_urls
	js_urls=$(jq -r 'to_entries[] | .value[]' "$RUN_DIR/katana_links.json" 2>/dev/null | grep -iE '\.js(\?|$)' | grep -v 'node_modules' | sort -u || true)

	if [[ -z "$js_urls" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "JS analysis" "$output_file"
		return
	fi

	local js_tmp_dir
	js_tmp_dir=$(mktemp -d)

	_js_worker() {
		local js_url="$1"
		local out_dir="$2"
		local url_hash
		url_hash=$(printf '%s' "$js_url" | cksum | cut -d' ' -f1)
		local host
		host=$(echo "$js_url" | sed 's|^https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

		# download JS file (max 2MB, 5s timeout)
		local js_content
		js_content=$(curl -sL --max-time 5 --connect-timeout 4 --max-filesize 2097152 "$js_url" 2>/dev/null || true)
		[[ -z "$js_content" ]] && return

		# regex patterns
		local -a findings=()

		# API endpoints
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			findings+=("$(jq -n --arg js_url "$js_url" --arg host "$host" --arg finding_type "api_endpoint" --arg match "$match" --arg context "" \
				'{ js_url: $js_url, host: $host, finding_type: $finding_type, match: $match, context: $context }' 2>/dev/null || true)")
		done < <(echo "$js_content" | grep -oE '["'"'"'`](/?(api|v[0-9]+)/[a-zA-Z0-9/_-]{3,})["'"'"'`]' | sed "s/[\"'\`]//g" | sort -u | head -20 || true)

		# AWS keys
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			findings+=("$(jq -n --arg js_url "$js_url" --arg host "$host" --arg finding_type "potential_secret" --arg match "$match" --arg context "AWS Key" \
				'{ js_url: $js_url, host: $host, finding_type: $finding_type, match: $match, context: $context }' 2>/dev/null || true)")
		done < <(echo "$js_content" | grep -oE 'AKIA[0-9A-Z]{16}' | sort -u || true)

		# Generic secrets with high entropy
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			# skip if match looks like a template string or common placeholder
			echo "$match" | grep -qiE 'your[-_]?key|example|placeholder|changeme|xxx+|your[-_]?token' && continue
			findings+=("$(jq -n --arg js_url "$js_url" --arg host "$host" --arg finding_type "potential_secret" --arg match "${match:0:40}..." --arg context "Secret pattern" \
				'{ js_url: $js_url, host: $host, finding_type: $finding_type, match: $match, context: $context }' 2>/dev/null || true)")
		done < <(echo "$js_content" | grep -oE '(secret|token|password|api_key|apikey|auth_key)[[:space:]]*[:=][[:space:]]*["'"'"'][a-zA-Z0-9+/]{20,}["'"'"']' | head -10 || true)

		# Internal URLs
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			findings+=("$(jq -n --arg js_url "$js_url" --arg host "$host" --arg finding_type "internal_url" --arg match "$match" --arg context "Internal endpoint" \
				'{ js_url: $js_url, host: $host, finding_type: $finding_type, match: $match, context: $context }' 2>/dev/null || true)")
		done < <(echo "$js_content" | grep -oE 'https?://[a-z0-9-]+\.(internal|corp|local|dev|staging|intra)\b[^"'"'"' ]*' | sort -u | head -10 || true)

		# write findings
		for f in "${findings[@]}"; do
			[[ -n "$f" ]] && echo "$f" >>"${out_dir}/${url_hash}.jsonl"
		done
	}
	export -f _js_worker

	echo "$js_urls" | xargs -P 8 -I {} bash -c '_js_worker "$@"' _ {} "$js_tmp_dir"

	# merge results
	if ls "$js_tmp_dir"/*.jsonl >/dev/null 2>&1; then
		cat "$js_tmp_dir"/*.jsonl >"$jsonl_tmp" 2>/dev/null || true
	fi
	combine_json "$jsonl_tmp" "$output_file"
	rm -rf "$js_tmp_dir"
	rm -f "$jsonl_tmp"
	quality_check_json_array "JS analysis" "$output_file"
}

# --- NEW MODULE: Cloud Storage Public Exposure Check ---
run_cloud_storage_check() {
	info "[30/31] Checking cloud storage buckets and enhanced permutations..."
	local output_file="$RUN_DIR/cloud_storage.json"
	local jsonl_tmp="$RUN_DIR/cloud_storage.jsonl"
	: >"$jsonl_tmp"

	if [[ ! -s "$RUN_DIR/cloud_infrastructure.json" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "Cloud storage" "$output_file"
		return
	fi

	# extract Object Storage entries
	local storage_entries
	storage_entries=$(jq -r '.[] | select(.ResourceType == "Object Storage") | [.Asset, .CloudProvider, .Storage] | @tsv' \
		"$RUN_DIR/cloud_infrastructure.json" 2>/dev/null || true)

	if [[ -z "$storage_entries" ]]; then
		echo "[]" >"$output_file"
		quality_check_json_array "Cloud storage" "$output_file"
		return
	fi

	while IFS=$'\t' read -r asset provider storage; do
		[[ -z "$asset" ]] && continue
		local url="" status="Unknown"

		case "$provider" in
		AWS)
			# try the asset as a bucket name
			local bucket_name
			bucket_name=$(echo "$storage" | sed 's/AWS S3//; s/ //g' || echo "$asset")
			url="https://${asset}.s3.amazonaws.com/"
			;;
		Azure)
			url=$(echo "$storage" | grep -oE 'https://[a-z0-9]+\.blob\.core\.windows\.net[^"'"'"' ]*' || true)
			[[ -z "$url" ]] && url="https://${asset}.blob.core.windows.net/"
			;;
		GCP)
			url="https://storage.googleapis.com/${asset}/"
			;;
		*)
			continue
			;;
		esac

		local http_code
		http_code=$(curl -s --max-time 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
		case "$http_code" in
		200) status="Public" ;;
		403) status="Private" ;;
		404) status="Nonexistent" ;;
		*) status="Unknown (${http_code})" ;;
		esac

		local severity="info"
		[[ "$status" == "Public" ]] && severity="critical"

		jq -n \
			--arg asset "$asset" \
			--arg provider "$provider" \
			--arg url "$url" \
			--arg status "$status" \
			--arg severity "$severity" \
			'{ asset: $asset, provider: $provider, url: $url, status: $status, finding_severity: $severity }' \
			>>"$jsonl_tmp" 2>/dev/null || true
	done <<<"$storage_entries"

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
	quality_check_json_array "Cloud storage" "$output_file"
}

# --- NEW MODULE: Change Detection vs. previous run ---
# glue the UI shell with the datasets and drop the finished HTML
build_html_report() {
info "[32/32] Building HTML report..."
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
	echo -n "const takeoverData = " >>report.html
	if [ -s "${RUN_DIR}/takeover.json" ] && jq -e . "${RUN_DIR}/takeover.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/takeover.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const exposedFilesData = " >>report.html
	echo "[]" | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const jsAnalysisData = " >>report.html
	if [ -s "${RUN_DIR}/js_analysis.json" ] && jq -e . "${RUN_DIR}/js_analysis.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/js_analysis.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const cloudStorageData = " >>report.html
	if [ -s "${RUN_DIR}/cloud_storage.json" ] && jq -e . "${RUN_DIR}/cloud_storage.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/cloud_storage.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const seedExpansionData = " >>report.html
	if [ -s "${RUN_DIR}/seed_expansion.json" ] && jq -e . "${RUN_DIR}/seed_expansion.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/seed_expansion.json"; else echo "{}"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const brandCandidates = " >>report.html
	if [ -s "${RUN_DIR}/brand_candidates.json" ] && jq -e . "${RUN_DIR}/brand_candidates.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/brand_candidates.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const githubSurfaceData = " >>report.html
	if [ -s "${RUN_DIR}/github_surface.json" ] && jq -e . "${RUN_DIR}/github_surface.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/github_surface.json"; else echo "{}"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const faviconClusters = " >>report.html
	if [ -s "${RUN_DIR}/favicon_clusters.json" ] && jq -e . "${RUN_DIR}/favicon_clusters.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/favicon_clusters.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const saasTenants = " >>report.html
	if [ -s "${RUN_DIR}/saas_tenants.json" ] && jq -e . "${RUN_DIR}/saas_tenants.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/saas_tenants.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const thirdPartyDeps = " >>report.html
	if [ -s "${RUN_DIR}/third_party_intel.json" ] && jq -e . "${RUN_DIR}/third_party_intel.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/third_party_intel.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const thirdPartyIntelData = " >>report.html
	if [ -s "${RUN_DIR}/third_party_intel.json" ] && jq -e . "${RUN_DIR}/third_party_intel.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/third_party_intel.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const shodanBanners = " >>report.html
	if [ -s "${RUN_DIR}/shodan_banners.json" ] && jq -e . "${RUN_DIR}/shodan_banners.json" >/dev/null 2>&1; then jq -c . "${RUN_DIR}/shodan_banners.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const ipv6Data = " >>report.html
	if [ -s "${RUN_DIR}/dnsx_ipv6.json" ] && jq -e . "${RUN_DIR}/dnsx_ipv6.json" >/dev/null 2>&1; then jq -sc '.' "${RUN_DIR}/dnsx_ipv6.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const cspSubdomains = " >>report.html
	if [ -s "${RUN_DIR}/csp_subdomains.json" ] && jq -e . "${RUN_DIR}/csp_subdomains.json" >/dev/null 2>&1; then jq -c '.' "${RUN_DIR}/csp_subdomains.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const hostClassificationData = " >>report.html
	if [ -s "${RUN_DIR}/host_classification.json" ] && jq -e . "${RUN_DIR}/host_classification.json" >/dev/null 2>&1; then jq -c '.' "${RUN_DIR}/host_classification.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	# ── Scoring wordlists (managed in assets/lists/) ──────────────────
	echo -n "const scoringSubdomainKeywords = " >>report.html
	if [ -s "assets/lists/scoring-subdomain-keywords.json" ]; then jq -c . "assets/lists/scoring-subdomain-keywords.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const scoringFinancialPaths = " >>report.html
	if [ -s "assets/lists/scoring-financial-paths.json" ]; then jq -c . "assets/lists/scoring-financial-paths.json"; else echo "[]"; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	echo -n "const scoringThirdPartyVendors = " >>report.html
	if [ -s "assets/lists/scoring-thirdparty-vendors.json" ]; then jq -c . "assets/lists/scoring-thirdparty-vendors.json"; else echo '{"payment_processors":[],"identity_providers":[],"high_risk_categories":[]}'; fi | tr -d "\n" >>report.html
	echo "" >>report.html
	cat footer.html >>report.html

	mkdir -p "$RUN_DIR/assets"
	cp assets/report.css "$RUN_DIR/assets/report.css"

	mv report.html $RUN_DIR/

	info "[32/32] Report generated at $RUN_DIR/report.html"
}

# final sandbox of data checks so we ship trustworthy artifacts
quality_post_run_checks() {
	quality_check_json_array "DNS inventory" "$RUN_DIR/dnsx.json"
	quality_check_json_array "Port scan inventory" "$RUN_DIR/naabu.json"
	quality_check_json_array "HTTP inventory" "$RUN_DIR/httpx.json"
	quality_check_json_array "Login detection" "$RUN_DIR/login.json"
	quality_check_json_array "Security compliance" "$RUN_DIR/securitycompliance.json"
	quality_check_json_array "Security headers" "$RUN_DIR/sec_headers.json"
	quality_check_json_array "TLS inventory" "$RUN_DIR/tls_inventory.json"
	quality_check_json_array "API detection" "$RUN_DIR/api_identification.json"
	quality_check_json_array "Colleague detection" "$RUN_DIR/colleague_identification.json"
	quality_check_json_array "Cloud inventory" "$RUN_DIR/cloud_infrastructure.json"
	quality_check_json_array "Port summary" "$RUN_DIR/portscan.json"
	quality_check_json_array "IP enrichment" "$RUN_DIR/ip_enrichment.json"
	quality_check_json_array "Takeover detection" "$RUN_DIR/takeover.json"
	quality_check_json_array "JS analysis" "$RUN_DIR/js_analysis.json"
	quality_check_json_array "Cloud storage" "$RUN_DIR/cloud_storage.json"
	quality_check_hosts_against_master "HTTP inventory" "$RUN_DIR/httpx.json" '(if type=="array" then .[] else . end) | (.input // .url // .host // "") | sub("^https?://"; "") | split("/")[0] | split(":")[0] | ascii_downcase'
	quality_check_hosts_against_master "TLS inventory" "$RUN_DIR/tls_inventory.json" '(if type=="array" then .[] else . end) | (.Host // .host // .Domain // .domain // "") | ascii_downcase'
	quality_check_hosts_against_master "Cloud inventory" "$RUN_DIR/cloud_infrastructure.json" '(if type=="array" then .[] else . end) | (.Asset // "") | ascii_downcase'
}

# ─── NEW MODULE: Seed Expansion ─────────────────────────────────────────────
# Uses free sources (crt.sh org filter, ARIN RDAP, TLD sweep) + optional WhoisXML
run_seed_expansion() {
	info "[2/31] Running seed expansion (crt.sh org · ASN CIDR · TLD sweep)..."
	local output_file="$RUN_DIR/seed_expansion.json"
	local company="${FROGY_COMPANY_NAME:-}"
	local cidr_blocks=() tld_candidates=() org_subdomains=()

	# crt.sh O= filter — extract subdomains issued to org name
	if [[ -n "$company" ]]; then
		local crt_org_url
		crt_org_url="https://crt.sh/?O=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$company" 2>/dev/null)&output=json"
		local crt_org_raw
		crt_org_raw=$(curl -sf --max-time 20 "$crt_org_url" 2>/dev/null || true)
		if [[ -n "$crt_org_raw" ]]; then
			while IFS= read -r sub; do
				[[ -z "$sub" || "$sub" == \** ]] && continue
				org_subdomains+=("$sub")
				echo "$sub" >>"$ALL_TEMP"
			done < <(echo "$crt_org_raw" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | grep -v '^$' | sort -u || true)
		fi
	fi

	# BGP: resolve seed domain IPs → ASN via Team Cymru → announced prefixes via RIPE STAT
	# RIPE STAT covers all RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC) unlike ARIN-only RDAP.
	# Known CDN ASNs are skipped since they don't represent the company's own network.
	local -a cdn_asns=("13335" "209242" "20940" "21342" "54113" "16509" "15169" "8075" "14618" "2906" "16625")
	local -A seen_asns=()
	while IFS= read -r domain; do
		local ips
		ips=$(dig +short A "$domain" 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -5 || true)
		while IFS= read -r ip; do
			[[ -z "$ip" ]] && continue
			local asn_info asn asn_name
			asn_info=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null \
				| awk -F'|' 'NR>1 && $1 ~ /[0-9]/ {
					gsub(/^[ \t]+|[ \t]+$/,"",$1);
					gsub(/^[ \t]+|[ \t]+$/,"",$3);
					print $1 "|" $3; exit }' || true)
			[[ -z "$asn_info" ]] && continue
			asn=$(echo "$asn_info" | cut -d'|' -f1 | sed 's/^AS//')
			asn_name=$(echo "$asn_info" | cut -d'|' -f2)
			# Skip CDN/hosting provider ASNs
			local skip_cdn=false
			for cdn_asn in "${cdn_asns[@]}"; do [[ "$asn" == "$cdn_asn" ]] && skip_cdn=true && break; done
			"$skip_cdn" && continue
			# Skip already-processed ASNs to avoid duplicate prefix lookups
			[[ -n "${seen_asns[$asn]+_}" ]] && continue
			seen_asns["$asn"]=1
			# RIPE STAT: global routing data (works for any RIR region)
			local stat_raw
			stat_raw=$(curl -sf --max-time 15 \
				"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}" \
				2>/dev/null || true)
			if [[ -n "$stat_raw" ]]; then
				while IFS= read -r cidr; do
					[[ -z "$cidr" ]] && continue
					local cidr_obj
					cidr_obj=$(jq -n \
						--arg asn "AS${asn}" \
						--arg asn_name "$asn_name" \
						--arg cidr "$cidr" \
						--arg source_domain "$domain" \
						'{"asn":$asn,"asn_name":$asn_name,"cidr":$cidr,"source_domain":$source_domain}' \
						2>/dev/null) || continue
					cidr_blocks+=("$cidr_obj")
				done < <(echo "$stat_raw" | jq -r '.data.prefixes[]?.prefix // empty' 2>/dev/null | head -30 || true)
			fi
		done <<<"$ips"
	done <"$PRIMARY_DOMAINS_FILE"

	# TLD variation sweep — attempt {slug}.{tld} for common TLDs
	local first_domain slug
	first_domain=$(head -1 "$PRIMARY_DOMAINS_FILE" | tr -d '\r' | xargs)
	slug=$(echo "$first_domain" | sed 's/\..*//')
	local -a tlds=("io" "co" "net" "org" "app" "dev" "ai" "cloud" "tech" "digital")
	local -a variation_targets=()
	for tld in "${tlds[@]}"; do
		variation_targets+=("${slug}.${tld}")
	done
	local var_tmp
	var_tmp=$(mktemp)
	printf '%s\n' "${variation_targets[@]}" >"$var_tmp"
	local resolved_vars
	resolved_vars=$(dnsx -silent -l "$var_tmp" 2>/dev/null | grep -v '^$' || true)
	while IFS= read -r v; do
		[[ -z "$v" ]] && continue
		tld_candidates+=("$v")
	done <<<"$resolved_vars"
	rm -f "$var_tmp"

	# WhoisXML pivot (optional)
	local whois_candidates=()
	if [[ -n "${WHOISXML_API_KEY:-}" ]]; then
		local wx_raw
		wx_raw=$(curl -sf --max-time 15 \
			"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API_KEY}&domainName=${first_domain}&outputFormat=JSON" \
			2>/dev/null || true)
		if [[ -n "$wx_raw" ]]; then
			local reg_email
			reg_email=$(echo "$wx_raw" | jq -r '.WhoisRecord.registrant.email // ""' 2>/dev/null || true)
			if [[ -n "$reg_email" && "$reg_email" != "null" ]]; then
				local wx_rev
				wx_rev=$(curl -sf --max-time 15 \
					"https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=${WHOISXML_API_KEY}&searchType=current&mode=purchase&punycode=true&basicSearchTerms.include=${reg_email}" \
					2>/dev/null || true)
				while IFS= read -r dom; do
					[[ -z "$dom" ]] && continue
					whois_candidates+=("$dom")
				done < <(echo "$wx_rev" | jq -r '.domainsList[]' 2>/dev/null | head -50 || true)
			fi
		fi
	fi

	# Write output JSON
	local cidr_json tld_json org_json whois_json
	cidr_json=$(printf '%s\n' "${cidr_blocks[@]+"${cidr_blocks[@]}"}" | jq -sc '.' 2>/dev/null || echo '[]')
	tld_json=$(printf '%s\n' "${tld_candidates[@]+"${tld_candidates[@]}"}" | jq -Rc '[inputs | select(length>0)]' 2>/dev/null || echo '[]')
	org_json=$(printf '%s\n' "${org_subdomains[@]+"${org_subdomains[@]}"}" | jq -Rc '[inputs | select(length>0)]' 2>/dev/null || echo '[]')
	whois_json=$(printf '%s\n' "${whois_candidates[@]+"${whois_candidates[@]}"}" | jq -Rc '[inputs | select(length>0)]' 2>/dev/null || echo '[]')

	jq -n \
		--argjson cidr "$cidr_json" \
		--argjson tld "$tld_json" \
		--argjson org "$org_json" \
		--argjson whois "$whois_json" \
		'{ cidr_blocks: $cidr, tld_candidates: $tld, org_subdomains: $org, whois_candidates: $whois }' \
		>"$output_file" 2>/dev/null || echo '{}' >"$output_file"
}

# ─── NEW MODULE: Brand Discovery ─────────────────────────────────────────────
run_brand_discovery() {
	info "[3/31] Running brand / subsidiary discovery (EDGAR + domain variants)..."
	local output_file="$RUN_DIR/brand_candidates.json"
	local jsonl_tmp="$RUN_DIR/brand_candidates.jsonl"
	: >"$jsonl_tmp"

	local first_domain slug company="${FROGY_COMPANY_NAME:-}"
	first_domain=$(head -1 "$PRIMARY_DOMAINS_FILE" | tr -d '\r' | xargs)
	slug=$(echo "$first_domain" | sed 's/\..*//')

	# Brand variation domains
	local -a brand_variants=()
	local -a var_tlds=("com" "io" "co" "net" "org" "app")
	local -a prefixes=("get" "try" "use" "my" "go" "" )
	local -a suffixes=("" "hq" "app" "labs" "corp" "inc")
	for pfx in "${prefixes[@]}"; do
		for sfx in "${suffixes[@]}"; do
			for tld in "${var_tlds[@]}"; do
				local candidate="${pfx}${slug}${sfx}.${tld}"
				brand_variants+=("$candidate")
			done
		done
	done

	local var_tmp
	var_tmp=$(mktemp)
	printf '%s\n' "${brand_variants[@]}" | sort -u >"$var_tmp"
	local resolved
	resolved=$(dnsx -silent -l "$var_tmp" 2>/dev/null | grep -v '^$' || true)
	while IFS= read -r host; do
		[[ -z "$host" ]] && continue
		jq -n --arg host "$host" --arg source "brand-variation" --arg confidence "candidate" \
			'{ host: $host, source: $source, confidence: $confidence }' \
			>>"$jsonl_tmp" 2>/dev/null || true
	done <<<"$resolved"
	rm -f "$var_tmp"

	# SEC EDGAR lookup (free)
	if [[ -n "$company" ]]; then
		local edgar_name
		edgar_name=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$company" 2>/dev/null || echo "$company")
		local edgar_raw
		edgar_raw=$(curl -sf --max-time 15 \
			"https://efts.sec.gov/LATEST/search-index?q=%22${edgar_name}%22&dateRange=custom&startdt=2020-01-01&forms=10-K" \
			2>/dev/null || true)
		if [[ -z "$edgar_raw" ]]; then
			edgar_raw=$(curl -sf --max-time 15 \
				"https://www.sec.gov/cgi-bin/browse-edgar?company=${edgar_name}&action=getcompany&output=atom" \
				2>/dev/null || true)
		fi
		if [[ -n "$edgar_raw" ]]; then
			local cik
			cik=$(echo "$edgar_raw" | grep -oE 'CIK=[0-9]+' | head -1 | cut -d= -f2 || true)
			if [[ -n "$cik" ]]; then
				local sub_raw
				sub_raw=$(curl -sf --max-time 15 \
					"https://data.sec.gov/submissions/CIK$(printf '%010d' "$cik").json" \
					2>/dev/null || true)
				if [[ -n "$sub_raw" ]]; then
					while IFS= read -r former; do
						[[ -z "$former" ]] && continue
						jq -n --arg host "$former" --arg source "edgar-former-name" --arg confidence "candidate" \
							'{ host: $host, source: $source, confidence: $confidence }' \
							>>"$jsonl_tmp" 2>/dev/null || true
					done < <(echo "$sub_raw" | jq -r '.formerNames[]?.name // empty' 2>/dev/null | head -20 || true)
				fi
			fi
		fi
	fi

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
}

# ─── NEW MODULE: Enhanced Passive Sources ────────────────────────────────────
run_enhanced_passive() {
	info "[8/31] Running enhanced passive recon (Wayback · RapidDNS · OTX · VT)..."
	# Wayback CDX (free)
	while IFS= read -r domain; do
		local wb_raw
		wb_raw=$(curl -sf --max-time 20 \
			"https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey&limit=5000" \
			2>/dev/null || true)
		if [[ -n "$wb_raw" ]]; then
			echo "$wb_raw" | grep -oE '[a-zA-Z0-9._-]+\.'"$domain" | sort -u >>"$ALL_TEMP" || true
		fi
		# RapidDNS (free)
		local rdns_raw
		rdns_raw=$(curl -sf --max-time 15 \
			"https://rapiddns.io/subdomain/${domain}?full=1&down=1" \
			2>/dev/null || true)
		if [[ -n "$rdns_raw" ]]; then
			echo "$rdns_raw" | grep -oE '[a-zA-Z0-9._-]+\.'"$domain" | sort -u >>"$ALL_TEMP" || true
		fi
		# OTX AlienVault (optional)
		if [[ -n "${OTX_API_KEY:-}" ]]; then
			local otx_resp
			otx_resp=$(curl -sf --max-time 15 \
				-H "X-OTX-API-KEY: ${OTX_API_KEY}" \
				"https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
				2>/dev/null || true)
			local otx_code="${otx_resp:0:3}"
			if [[ "$otx_code" == "429" ]]; then
				log_warn "⚠ OTX rate limit hit — skipping remaining OTX queries"
				break
			fi
			if [[ -n "$otx_resp" ]]; then
				echo "$otx_resp" | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null | grep -iE "\.${domain}$" | sort -u >>"$ALL_TEMP" || true
			fi
		fi
		# VirusTotal (optional)
		if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
			local vt_resp
			vt_resp=$(curl -sf --max-time 15 \
				"https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VIRUSTOTAL_API_KEY}&domain=${domain}" \
				2>/dev/null || true)
			if [[ -n "$vt_resp" ]]; then
				echo "$vt_resp" | jq -r '.subdomains[]? // empty' 2>/dev/null | sort -u >>"$ALL_TEMP" || true
			fi
		fi
	done <"$PRIMARY_DOMAINS_FILE"
}

# ─── NEW MODULE: IPv6 Discovery ──────────────────────────────────────────────
run_ipv6_discovery() {
	info "[14/31] Collecting AAAA records (IPv6 discovery)..."
	local ipv6_file="$RUN_DIR/dnsx_ipv6.json"
	if [[ ! -s "$MASTER_SUBS" ]]; then
		echo "[]" >"$ipv6_file"
		return
	fi
	dnsx -silent -l "$MASTER_SUBS" -aaaa -json -o "$ipv6_file" >/dev/null 2>/dev/null || true
	if [[ ! -f "$ipv6_file" ]]; then
		echo "[]" >"$ipv6_file"
	fi
	# Append any AAAA IPs to the naabu target list so later HTTP probing covers them
	local final_urls_ports="$RUN_DIR/final_urls_and_ports.txt"
	if [[ -s "$ipv6_file" ]]; then
		jq -r 'select(type=="object") | .aaaa[]?' "$ipv6_file" 2>/dev/null | grep -v '^$' | while IFS= read -r ipv6; do
			echo "[${ipv6}]:80" >>"$final_urls_ports"
			echo "[${ipv6}]:443" >>"$final_urls_ports"
		done || true
	fi
}

# ─── NEW MODULE: Shodan Banner Enrichment ────────────────────────────────────
run_shodan_banner_enrichment() {
	info "[16/31] Shodan banner enrichment (API-optional)..."
	local output_file="$RUN_DIR/shodan_banners.json"
	if [[ -z "${SHODAN_API_KEY:-}" ]]; then
		log_warn "⚠ Shodan API key not configured — banner enrichment skipped"
		echo "[]" >"$output_file"
		return
	fi
	local jsonl_tmp="$RUN_DIR/shodan_banners.jsonl"
	: >"$jsonl_tmp"

	# Collect unique IPs from port scan
	local -a ips=()
	if [[ -s "$RUN_DIR/portscan.json" ]]; then
		while IFS= read -r ip; do
			[[ -z "$ip" ]] && continue
			ips+=("$ip")
		done < <(jq -r '.[].ip' "$RUN_DIR/portscan.json" 2>/dev/null | sort -u | head -50 || true)
	fi

	for ip in "${ips[@]+"${ips[@]}"}"; do
		local resp
		resp=$(curl -sf --max-time 10 \
			"https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" \
			2>/dev/null || true)
		if echo "$resp" | grep -q '"error"'; then
			log_warn "⚠ Shodan error for ${ip} — skipping"
			continue
		fi
		if [[ -n "$resp" ]]; then
			echo "$resp" | jq \
				--arg ip "$ip" \
				'{
					ip: $ip,
					ports: [(.data // [])[] | { port: .port, protocol: (.transport // "tcp"), service: (.product // ""), version: (.version // ""), banner: ((.banner // "")[0:200]) }]
				}' 2>/dev/null >>"$jsonl_tmp" || true
		fi
		sleep 1  # respect free tier rate limit
	done

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
}

# ─── NEW MODULE: SaaS Tenant Detection ──────────────────────────────────────
run_saas_detection() {
	info "[24/31] Detecting SaaS tenant footprint..."
	local output_file="$RUN_DIR/saas_tenants.json"
	local jsonl_tmp="$RUN_DIR/saas_tenants.jsonl"
	: >"$jsonl_tmp"

	local first_domain slug
	first_domain=$(head -1 "$PRIMARY_DOMAINS_FILE" | tr -d '\r' | xargs)
	slug=$(echo "$first_domain" | sed 's/\..*//')

	_probe_saas() {
		local url="$1" label="$2"
		local code
		# curl always writes http_code via -w even on failure (exit!=0); don't || echo "000" or it doubles
		code=$(curl -so /dev/null --max-time 10 --connect-timeout 5 -w "%{http_code}" "$url" 2>/dev/null)
		[[ -z "$code" ]] && code="000"
		if [[ "$code" != "404" && "$code" != "410" && "$code" != "000" && "$code" != "400" ]]; then
			jq -n --arg service "$label" --arg url "$url" --arg status_code "$code" \
				'{ service: $service, url: $url, status_code: $status_code, detected: true }' \
				>>"$jsonl_tmp" 2>/dev/null || true
		fi
	}

	_probe_saas "https://${slug}.slack.com"              "Slack"
	_probe_saas "https://${slug}.atlassian.net"          "Atlassian"
	_probe_saas "https://${slug}.zendesk.com"            "Zendesk"
	_probe_saas "https://${slug}.my.salesforce.com"      "Salesforce"
	_probe_saas "https://${slug}.gitlab.io"              "GitLab Pages"
	_probe_saas "https://${slug}.github.io"              "GitHub Pages"
	_probe_saas "https://${slug}.freshdesk.com"          "Freshdesk"
	_probe_saas "https://${slug}.intercom.io"            "Intercom"
	_probe_saas "https://${slug}.hubspot.com"            "HubSpot"
	_probe_saas "https://${slug}.monday.com"             "Monday.com"
	_probe_saas "https://${slug}.notion.site"            "Notion"
	_probe_saas "https://${slug}.sharepoint.com"         "SharePoint"

	# HubSpot: detect via MX record
	if dig +short MX "$first_domain" 2>/dev/null | grep -qi "hubspot"; then
		jq -n --arg service "HubSpot (MX)" --arg url "https://www.hubspot.com" --arg status_code "mx" \
			'{ service: $service, url: $url, status_code: $status_code, detected: true }' \
			>>"$jsonl_tmp" 2>/dev/null || true
	fi

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
}

# ─── MODULE: Third-Party Intelligence (multi-source, 100+ vendor patterns) ────
# Aggregates third-party vendor signals from: CSP headers, Katana crawl links,
# JS analysis, MX records, SPF includes, CNAME chains, and HTTP response headers.
# A Python script handles classification against 100+ known vendor patterns.
run_third_party_intel() {
	info "[25/31] Analyzing third-party intelligence (multi-source, 100+ vendors)..."
	local output_file="$RUN_DIR/third_party_intel.json"
	local raw_tmp="$RUN_DIR/.tpi_raw.txt"
	: >"$raw_tmp"

	# Source 1: CSP headers from httpx.json (domain\tsource)
	if [[ -s "$RUN_DIR/httpx.json" ]]; then
		jq -r '
			select(type=="object") |
			(.headers // {}) | to_entries[] |
			select(.key | ascii_downcase | contains("content-security-policy")) |
			.value
		' "$RUN_DIR/httpx.json" 2>/dev/null \
		| grep -oE '[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
		| grep -v '^[0-9.]*$' \
		| sort -u | awk '{print $0 "\tcsp"}' >>"$raw_tmp" || true
	fi

	# Source 2: Katana crawl external links
	if [[ -s "$RUN_DIR/katana_links.json" ]]; then
		jq -r 'to_entries[] | .value[]' "$RUN_DIR/katana_links.json" 2>/dev/null \
		| grep -oE 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
		| sed 's|https\?://||' | sort -u \
		| awk '{print $0 "\tkatana"}' >>"$raw_tmp" || true
	fi

	# Source 3: JS analysis external URLs
	if [[ -s "$RUN_DIR/js_analysis.json" ]]; then
		jq -r '
			select(type=="object") |
			((.urls // []) + (.endpoints // []) + (.external_urls // [])) |
			.[] | select(startswith("http")) |
			ltrimstr("https://") | ltrimstr("http://") | split("/") | .[0]
		' "$RUN_DIR/js_analysis.json" 2>/dev/null \
		| grep -E '\.[a-zA-Z]{2,}$' | sort -u \
		| awk '{print $0 "\tjs_analysis"}' >>"$raw_tmp" || true
	fi

	# Source 4: MX records → email provider fingerprinting
	if [[ -s "$RUN_DIR/dnsx.json" ]]; then
		jq -r '
			select(type=="object") |
			(.mx // [])[] | ascii_downcase |
			split(" ") | last | rtrimstr(".")
		' "$RUN_DIR/dnsx.json" 2>/dev/null \
		| grep -E '\.[a-z]{2,}$' | sort -u \
		| awk '{print $0 "\tmx_record"}' >>"$raw_tmp" || true

		# Source 5: SPF includes → SaaS email vendors
		jq -r '
			select(type=="object") |
			(.txt // [])[] | select(test("v=spf1")) |
			split(" ") | .[] |
			select(startswith("include:")) | ltrimstr("include:")
		' "$RUN_DIR/dnsx.json" 2>/dev/null \
		| sort -u | awk '{print $0 "\tspf_include"}' >>"$raw_tmp" || true

		# Source 6: CNAME chains → service fingerprinting
		jq -r '
			select(type=="object") |
			(.cname // [])[] | ascii_downcase | rtrimstr(".")
		' "$RUN_DIR/dnsx.json" 2>/dev/null \
		| grep -E '\.[a-z]{2,}$' | sort -u \
		| awk '{print $0 "\tcname"}' >>"$raw_tmp" || true
	fi

	# Source 7: HTTP response headers (Set-Cookie domain, Via, X-Powered-By, Server)
	if [[ -s "$RUN_DIR/httpx.json" ]]; then
		jq -r '
			select(type=="object") |
			(.headers // {}) | to_entries[] |
			select(.key | ascii_downcase | test("^(set-cookie|via|server|x-powered-by|x-cache|cdn-cache)")) |
			.value
		' "$RUN_DIR/httpx.json" 2>/dev/null \
		| grep -oE '[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
		| grep -v '^[0-9.]*$' | sort -u \
		| awk '{print $0 "\tresponse_headers"}' >>"$raw_tmp" || true
	fi

	if [[ ! -s "$raw_tmp" ]]; then
		echo "[]" >"$output_file"
		rm -f "$raw_tmp"
		return
	fi

	# Python-based vendor classification — 100+ patterns across 10 categories
	local py_tmp
	py_tmp=$(mktemp --suffix=.py)
	# Write vendors file path as a Python variable so the quoted heredoc needs no changes
	printf 'VENDORS_FILE = %s\n' "\"$SCRIPT_DIR/assets/lists/third-party-vendors.json\"" >"$py_tmp"
	cat >>"$py_tmp" <<'PYEOF'
import sys, json

# Load vendor patterns from external file — edit assets/lists/third-party-vendors.json
with open(VENDORS_FILE) as _vf:
    VENDORS = [tuple(v) for v in json.load(_vf)]

# (pattern_substring, category, risk, service_name) — kept as comment for reference
# ("google-analytics.com","analytics","low","Google Analytics"),

results = {}
for line in sys.stdin:
    parts = line.rstrip('\n').split('\t', 1)
    domain = parts[0].strip().lower()
    source = parts[1].strip() if len(parts) > 1 else 'unknown'
    if not domain or '.' not in domain or len(domain) < 4 or len(domain) > 200:
        continue
    # Skip IP addresses
    if all(c.isdigit() or c == '.' for c in domain):
        continue
    if domain not in results:
        cat, risk, svc = 'other', 'low', ''
        for pattern, c, r, n in VENDORS:
            if pattern in domain:
                cat, risk, svc = c, r, n
                break
        if cat == 'other':
            continue
        results[domain] = {
            'domain': domain,
            'category': cat,
            'risk': risk,
            'service_name': svc,
            'sources': []
        }
    if source and source not in results[domain]['sources']:
        results[domain]['sources'].append(source)

output = sorted(results.values(), key=lambda x: (x['category'], x['domain']))
print(json.dumps(output))
PYEOF

	python3 "$py_tmp" <"$raw_tmp" >"$output_file" 2>/dev/null || echo "[]" >"$output_file"
	rm -f "$py_tmp" "$raw_tmp"

	local count
	count=$(jq 'length' "$output_file" 2>/dev/null || echo 0)
	info "  → Third-party intelligence: ${count} classified vendors across all sources"
}

# Keep backward-compat alias so any callers referencing the old name still work
run_third_party_deps() { run_third_party_intel "$@"; }

# ─── MODULE: GitHub Subdomain Discovery ──────────────────────────────────────
# Discovers subdomains from public GitHub org code using github-subdomains.
# Any new subdomains found are resolved and merged into the main httpx inventory.
# Secret scanning has been intentionally removed — use dedicated tools for that.
run_github_surface() {
	info "[28/31] GitHub subdomain discovery from public org code..."
	local output_file="$RUN_DIR/github_surface.json"

	if [[ -z "${GITHUB_TOKEN:-}" ]]; then
		log_warn "⚠ GitHub token not configured — GitHub subdomain discovery skipped"
		echo '{"org_found":false,"reason":"no_token","subdomains":[]}' >"$output_file"
		return
	fi

	local first_domain slug
	first_domain=$(head -1 "$PRIMARY_DOMAINS_FILE" | tr -d '\r' | xargs)
	slug=$(echo "$first_domain" | sed 's/\..*//')

	# Check if GitHub org exists
	local org_check
	org_check=$(curl -sf --max-time 10 \
		-H "Authorization: token ${GITHUB_TOKEN}" \
		-H "User-Agent: frogy/2.0" \
		"https://api.github.com/orgs/${slug}" 2>/dev/null || true)

	if echo "$org_check" | jq -e '.message == "Not Found"' >/dev/null 2>&1; then
		echo '{"org_found":false,"reason":"org_not_found","subdomains":[]}' >"$output_file"
		return
	fi

	local -a gh_subdomains=()
	if command -v github-subdomains >/dev/null 2>&1; then
		while IFS= read -r sub; do
			[[ -z "$sub" ]] && continue
			gh_subdomains+=("$sub")
		done < <(github-subdomains -t "$GITHUB_TOKEN" -d "$first_domain" 2>/dev/null | grep -v '^$' || true)
	fi

	# Merge any newly discovered subdomains into the live scan inventory
	if [[ ${#gh_subdomains[@]} -gt 0 ]]; then
		local new_subs_tmp
		new_subs_tmp=$(mktemp)
		printf '%s\n' "${gh_subdomains[@]}" | sort -u \
			| comm -23 - <(sort "$MASTER_SUBS") >"$new_subs_tmp" 2>/dev/null || true
		if [[ -s "$new_subs_tmp" ]]; then
			info "  → GitHub discovery found $(wc -l <"$new_subs_tmp") new subdomains — probing..."
			cat "$new_subs_tmp" >>"$MASTER_SUBS"
			sort -u "$MASTER_SUBS" -o "$MASTER_SUBS"
			apply_exclusions "$MASTER_SUBS" "MASTER_SUBS (post-GitHub)"
			local new_live_tmp
			new_live_tmp=$(mktemp)
			dnsx -silent -l "$new_subs_tmp" 2>/dev/null | while IFS= read -r host; do
				[[ -z "$host" ]] && continue
				printf '%s:80\n%s:443\n' "$host" "$host"
			done >"$new_live_tmp" || true
			if [[ -s "$new_live_tmp" ]]; then
				httpx -silent -l "$new_live_tmp" -json -follow-redirects -timeout 10 -retries 1 \
					>>"$RUN_DIR/httpx.json" 2>/dev/null || true
			fi
			rm -f "$new_live_tmp"
		fi
		rm -f "$new_subs_tmp"
	fi

	local sub_json
	sub_json=$(printf '%s\n' "${gh_subdomains[@]+"${gh_subdomains[@]}"}" | jq -Rc '[inputs | select(length>0)]' 2>/dev/null || echo '[]')
	jq -n \
		--argjson org_found true \
		--arg org "$slug" \
		--argjson subdomains "$sub_json" \
		'{ org_found: $org_found, org: $org, subdomains: $subdomains }' \
		>"$output_file" 2>/dev/null || echo '{"org_found":false}' >"$output_file"
}

# ─── NEW MODULE: Favicon Hash Clustering ─────────────────────────────────────
run_favicon_clustering() {
	info "[29/31] Computing favicon hashes and clustering assets..."
	local output_file="$RUN_DIR/favicon_clusters.json"
	local jsonl_tmp="$RUN_DIR/favicon_clusters.jsonl"
	: >"$jsonl_tmp"

	if [[ ! -s "$RUN_DIR/httpx.json" ]]; then
		echo "[]" >"$output_file"
		return
	fi

	# Generic hashes to skip (Apache, nginx, IIS, etc.)
	# Edit assets/lists/favicon-skip-hashes.txt to add/remove hashes — no code change needed.
	local -a skip_hashes
	mapfile -t skip_hashes < "$SCRIPT_DIR/assets/lists/favicon-skip-hashes.txt"

	local urls
	urls=$(jq -r '(if type=="array" then .[] else . end) | .url // ""' "$RUN_DIR/httpx.json" 2>/dev/null | grep -v '^$' | head -50 || true)

	if ! python3 -c "import mmh3" >/dev/null 2>&1; then
		log_warn "⚠ Python mmh3 not installed — favicon clustering skipped"
		echo "[]" >"$output_file"
		return
	fi

	while IFS= read -r base_url; do
		[[ -z "$base_url" ]] && continue
		local fav_url="${base_url%/}/favicon.ico"
		local fav_data
		fav_data=$(curl -sfL --max-time 8 --connect-timeout 4 "$fav_url" 2>/dev/null | base64 -w 0 || true)
		[[ -z "$fav_data" ]] && continue

		local mmh3_hash
		mmh3_hash=$(python3 - <<PYEOF 2>/dev/null || echo "0"
import mmh3, base64
data = base64.b64decode("${fav_data}")
print(mmh3.hash(data))
PYEOF
)
		# Skip generic/empty hashes
		local skip=false
		for h in "${skip_hashes[@]}"; do
			[[ "$mmh3_hash" == "$h" ]] && skip=true && break
		done
		"$skip" && continue

		# Shodan lookup by MMH3 hash
		if [[ -n "${SHODAN_API_KEY:-}" ]]; then
			local sh_resp
			sh_resp=$(curl -sf --max-time 15 \
				"https://api.shodan.io/shodan/host/search?query=http.favicon.hash:${mmh3_hash}&key=${SHODAN_API_KEY}&minify=true" \
				2>/dev/null || true)
			if [[ -n "$sh_resp" ]]; then
				echo "$sh_resp" | jq \
					--arg src "$base_url" \
					--arg hash "$mmh3_hash" \
					'.matches[]? | { source: $src, favicon_hash: $hash, candidate_ip: .ip_str, candidate_port: .port, confidence: "candidate" }' \
					2>/dev/null >>"$jsonl_tmp" || true
			fi
		fi

		# Censys lookup by MD5 favicon hash (independent of Shodan — runs if key is set)
		if [[ -n "${CENSYS_API_KEY:-}" ]]; then
			local md5_hash
			md5_hash=$(python3 - <<PYEOF 2>/dev/null || true
import hashlib, base64
data = base64.b64decode("${fav_data}")
print(hashlib.md5(data).hexdigest())
PYEOF
)
			if [[ -n "$md5_hash" ]]; then
				local censys_b64 censys_resp
				censys_b64=$(python3 -c "import base64; print(base64.b64encode(b'${CENSYS_API_KEY}:${CENSYS_API_KEY}').decode())" 2>/dev/null || true)
				censys_resp=$(curl -sf --max-time 15 \
					-H "Authorization: Basic ${censys_b64}" \
					-H "Content-Type: application/json" \
					--data-raw "{\"q\":\"services.http.response.favicons.md5_hash:\\\"${md5_hash}\\\"\",\"per_page\":25}" \
					"https://search.censys.io/api/v2/hosts/search" \
					2>/dev/null || true)
				if [[ -n "$censys_resp" ]]; then
					echo "$censys_resp" | jq \
						--arg src "$base_url" \
						--arg hash "$mmh3_hash" \
						'.result.hits[]? | { source: $src, favicon_hash: $hash, candidate_ip: .ip, candidate_port: (.services[0].port // null), confidence: "candidate" }' \
						2>/dev/null >>"$jsonl_tmp" || true
				fi
			fi
		fi

		# Fallback: record hash-only if neither Shodan nor Censys is configured
		if [[ -z "${SHODAN_API_KEY:-}" && -z "${CENSYS_API_KEY:-}" ]]; then
			jq -n \
				--arg src "$base_url" \
				--arg hash "$mmh3_hash" \
				'{ source: $src, favicon_hash: $hash, confidence: "hash-only" }' \
				>>"$jsonl_tmp" 2>/dev/null || true
		fi
	done <<<"$urls"

	combine_json "$jsonl_tmp" "$output_file"
	rm -f "$jsonl_tmp"
}

# ─── ENHANCED MODULE: Cloud Bucket Permutation Check ─────────────────────────
# Enhances existing run_cloud_storage_check with slug permutations
run_cloud_bucket_enhanced() {
	local first_domain slug
	first_domain=$(head -1 "$PRIMARY_DOMAINS_FILE" | tr -d '\r' | xargs)
	slug=$(echo "$first_domain" | sed 's/\..*//')

	# Base slug always included; suffixes loaded from file — edit assets/lists/bucket-permutations.txt
	local -a permutations=("${slug}")
	while IFS= read -r suffix; do
		[[ -n "$suffix" ]] && permutations+=("${slug}${suffix}")
	done < "$SCRIPT_DIR/assets/lists/bucket-permutations.txt"

	local output_file="$RUN_DIR/cloud_storage.json"
	local jsonl_tmp="$RUN_DIR/cloud_storage.jsonl"

	# Preserve any entries already written by run_cloud_storage_check
	local existing="[]"
	[[ -s "$output_file" ]] && existing=$(cat "$output_file")

	for bucket in "${permutations[@]}"; do
		for provider_url_template in \
			"AWS|https://${bucket}.s3.amazonaws.com/" \
			"Azure|https://${bucket}.blob.core.windows.net/" \
			"GCP|https://storage.googleapis.com/${bucket}/"
		do
			local provider url
			provider="${provider_url_template%%|*}"
			url="${provider_url_template#*|}"
			local code
			code=$(curl -so /dev/null --max-time 8 --connect-timeout 4 -w "%{http_code}" "$url" 2>/dev/null || echo "000")
			local status="Unknown"
			case "$code" in
				200) status="Public" ;;
				403) status="Private" ;;
				404) status="Nonexistent" ;;
				*) status="Unknown (${code})" ;;
			esac
			[[ "$status" == "Nonexistent" ]] && continue
			local severity="info"
			[[ "$status" == "Public" ]] && severity="critical"
			jq -n \
				--arg asset "$bucket" \
				--arg provider "$provider" \
				--arg url "$url" \
				--arg status "$status" \
				--arg severity "$severity" \
				'{ asset: $asset, provider: $provider, url: $url, status: $status, finding_severity: $severity }' \
				>>"$jsonl_tmp" 2>/dev/null || true
		done
	done

	# Merge permutation results into existing cloud storage file
	if [[ -s "$jsonl_tmp" ]]; then
		local perm_json
		perm_json=$(jq -cs '.' "$jsonl_tmp" 2>/dev/null || echo '[]')
		echo "$existing" | jq --argjson new "$perm_json" '. + $new | unique_by(.url)' \
			>"$output_file" 2>/dev/null || true
	fi
	rm -f "$jsonl_tmp"
}

# quick recap for the terminal once everything wraps up
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
	if (( ${#QUALITY_ALERTS[@]} > 0 )); then
		echo ""
		echo "Data quality heads-up:"
		local note
		for note in "${QUALITY_ALERTS[@]}"; do
			printf " - %s\n" "$note"
		done
	else
		echo ""
		echo "Data quality checks looked solid this round."
	fi
}
# main path: run the scanners, enrich the output, and wrap it all up
main() {
	check_dependencies
	load_api_config                    # load API keys from web UI config file
	if ! run_chaos; then               # [1/31]
		warning "Chaos step encountered an error and was skipped."
	fi
	if ! run_seed_expansion; then      # [2/31]
		warning "Seed expansion step encountered an error and was skipped."
	fi
	if ! run_brand_discovery; then     # [3/31]
		warning "Brand discovery step encountered an error and was skipped."
	fi
	run_subfinder                      # [4/31]
	if ! run_assetfinder; then         # [5/31]
		warning "Assetfinder step encountered an error and was skipped."
	fi
	if ! run_crtsh; then               # [6/31]
		warning "crt.sh lookup step encountered an error and was skipped."
	fi
	if ! run_gau; then                 # [7/31]
		warning "GAU step encountered an error and was skipped."
	fi
	if ! run_enhanced_passive; then    # [8/31]
		warning "Enhanced passive step encountered an error and was skipped."
	fi
	info "[9/31] Merging subdomains..."
	while read -r domain; do
		echo "$domain" >>"$ALL_TEMP"
		echo "www.$domain" >>"$ALL_TEMP"
	done <"$PRIMARY_DOMAINS_FILE"
	sort -u "$ALL_TEMP" >"$MASTER_SUBS"
	rm -f "$ALL_TEMP"
	apply_exclusions "$MASTER_SUBS" "MASTER_SUBS"
	tr '[:upper:]' '[:lower:]' <"$MASTER_SUBS" | sed '/^$/d' | sort -u >"$MASTER_HOST_INDEX"
	run_dnsx                                   # [10/31]
	classify_hosts_by_tier                     # CDN vs direct/cloud classification (post-dnsx)
	EFFECTIVE_WEB_PORTS="$WEB_PORTS_TOP20"     # set web port list for httpx expansion
	run_subdomain_takeover                     # [11/31] dangling CNAME / takeover detection
	run_naabu                                  # [12/31] direct/cloud hosts only
	augment_final_urls_with_webports           # tier-aware web port expansion for httpx
	generate_ip_intel                          # [13/31] IP enrichment (parallel)
	if ! run_ipv6_discovery; then              # [14/31]
		warning "IPv6 discovery step encountered an error and was skipped."
	fi
	run_httpx                                  # [15/31]
	run_csp_discovery                          # bonus: CSP-based subdomain expansion
	if ! run_shodan_banner_enrichment; then    # [16/31]
		warning "Shodan banner enrichment skipped."
	fi
	run_katana                                 # [18/31]
	run_js_analysis                            # [19/31] JS endpoint/secret extraction
	# [20/31] screenshot capture removed
	run_login_detection                        # [21/31] parallel, 2+ signal threshold
	run_tls_inventory                          # [22/31] TLS + grading
	run_security_compliance                    # [23/31] parallel, cookie + CORS analysis
	if ! run_saas_detection; then              # [24/31]
		warning "SaaS detection step encountered an error and was skipped."
	fi
	if ! run_third_party_intel; then           # [25/31]
		warning "Third-party intelligence step encountered an error and was skipped."
	fi
	run_api_identification                     # [26/31] multi-signal API detection
	run_colleague_identification               # [27/31]
	if ! run_github_surface; then              # [28/31]
		warning "GitHub surface discovery step encountered an error and was skipped."
	fi
	if ! run_favicon_clustering; then          # [29/31]
		warning "Favicon clustering step encountered an error and was skipped."
	fi
	run_cloud_infrastructure_inventory         # [30/32]
	run_cloud_storage_check                    # [30/32] storage exposure (runs after cloud infra)
	run_cloud_bucket_enhanced                  # [30/32] enhanced permutation check
	build_html_report                          # [31/31]
	quality_post_run_checks
	show_summary
	# write pipeline stats for the web UI dashboard
	# Counts are computed to exactly match the HTML report's Attack Surface section:
	#   subdomains = unique .host from dnsx.json (resolved domains)
	#   live_assets = unique .host from dnsx.json that have A/AAAA records
	#   web_hosts   = unique scheme://host:port variants from httpx.json
	local _inputs=0
	[[ -s "$PRIMARY_DOMAINS_FILE" ]] && _inputs=$(grep -cve '^\s*$' "$PRIMARY_DOMAINS_FILE" 2>/dev/null || echo 0)
	python3 - "$RUN_DIR/dnsx.json" "$RUN_DIR/httpx.json" "$_inputs" "$RUN_DIR/scan_summary.json" <<'__PYSTATS__'
import json, sys
from urllib.parse import urlparse

dnsx_file, httpx_file, inputs_str, out_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
inputs = int(inputs_str) if inputs_str.isdigit() else 0

def load_jsonl(path):
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    records.append(parsed)
                elif isinstance(parsed, list):
                    records.extend(r for r in parsed if isinstance(r, dict))
    except Exception:
        pass
    return records

dnsx  = load_jsonl(dnsx_file)
httpx = load_jsonl(httpx_file)

domain_set    = set()
live_set      = set()
for r in dnsx:
    host = (r.get("host") or "").strip().lower()
    if not host:
        continue
    domain_set.add(host)
    if r.get("a") or r.get("aaaa"):
        live_set.add(host)

def url_parts(url_str):
    """Return (scheme, host, effective_port) or None."""
    if not url_str:
        return None
    try:
        u = urlparse(url_str)
        scheme = (u.scheme or "http").lower()
        host   = (u.hostname or "").lower()
        if not host:
            return None
        explicit_port = u.port
        eff_port = explicit_port if explicit_port else (443 if scheme == "https" else 80)
        return (scheme, host, eff_port)
    except Exception:
        return None

# Build all raw variant keys first
raw_entries = []  # list of (key, record)
for r in httpx:
    url_str = r.get("url") or ""
    p = url_parts(url_str)
    if not p:
        host   = (r.get("host") or "").strip().lower()
        scheme = (r.get("scheme") or "http").strip().lower() or "http"
        port   = r.get("port")
        try:
            eff = int(port) if port else (443 if scheme == "https" else 80)
        except Exception:
            eff = 443 if scheme == "https" else 80
        if host:
            p = (scheme, host, eff)
    if p:
        raw_entries.append(p)

# Build set of https:host:443 keys that exist
https_hosts = {host for (scheme, host, port) in raw_entries if scheme == "https" and port == 443}

# Apply Rule A: suppress http:host:80 when https:host:443 already exists (mirrors report dedup)
web_variants = set()
for (scheme, host, port) in raw_entries:
    if scheme == "http" and port == 80 and host in https_hosts:
        continue  # suppressed — report doesn't count this separately
    key = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
    web_variants.add(key)

out = json.dumps({
    "inputs":      inputs,
    "subdomains":  len(domain_set),
    "live_assets": len(live_set),
    "web_hosts":   len(web_variants)
})
with open(out_file, "w") as f:
    f.write(out + "\n")
__PYSTATS__
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
