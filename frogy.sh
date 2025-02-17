#!/usr/bin/env bash
set -euo pipefail

##############################################
# 1) Helper: Print with colors
##############################################
info()    { echo -e "\033[96m[+] $*\033[0m"; }
warning() { echo -e "\033[93m[!] $*\033[0m"; }
error()   { echo -e "\033[91m[-] $*\033[0m"; }

##############################################
# 2) Helper: Merge subdomain files & show count
##############################################
merge_and_count() {
  local file="$1"
  local source_name="$2"
  if [[ -s "$file" ]]; then
    cat "$file" >> "$ALL_TEMP"
    local count
    count=$(wc -l < "$file")
    info "$count new entries from $source_name"
  else
    warning "No subdomains found from $source_name"
  fi
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

# Central temporary file & final subdomain file
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
    info "Searching CHAOS dataset..."
    local chaos_index="output/$cdir/logs/chaos_index.json"
    curl -s https://chaos-data.projectdiscovery.io/index.json -o "$chaos_index"

    local chaos_url
    chaos_url=$(grep -w "$cdir" "$chaos_index" | grep "URL" | sed 's/"URL": "//;s/",//' | xargs || true)

    if [[ -z "$chaos_url" ]]; then
      warning "Not found in CHAOS. Skipping..."
    else
      info "Found a CHAOS dataset. Downloading..."
      (
        cd "output/$cdir" || exit
        curl -sSL "$chaos_url" -O
        unzip -qq "*.zip" || true
        cat ./*.txt > chaos.txt
        rm -f ./*.zip ./*.txt
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
    info "Running subfinder..."
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
    info "Running assetfinder..."
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
  info "Querying crt.sh..."
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
# 4e) DNSX Ã¢â‚¬â€œ Live Domain Check
##############################################
run_dnsx() {
  if [[ "$USE_DNSX" == "true" ]]; then
    info "Running dnsx..."
    dnsx -silent \
         -l "output/$cdir/master_subdomains.txt" \
         -o "output/$cdir/dnsx.json" \
         -j \
         >/dev/null 2>&1 || true

    local live_hosts="output/$cdir/live_subdomains.txt"
    cat "output/$cdir/dnsx.json" \
      | jq -r 'select(.status_code=="NOERROR") | .host' \
      | sort -u \
      > "$live_hosts"

    local count_live
    count_live=$(wc -l < "$live_hosts")
    info "Found $count_live live subdomains (dnsx)."
  fi
}

##############################################
# 4f) Naabu Ã¢â‚¬â€œ Port Scanning
##############################################
run_naabu() {
  if [[ "$USE_NAABU" == "true" ]]; then
    info "Running naabu..."
    naabu -silent \
          -l "output/$cdir/master_subdomains.txt" \
          --top-ports 100 \
          -o "output/$cdir/naabu.json" \
          -j \
          >/dev/null 2>&1 || true

    local open_ports
    open_ports=$(cat "output/$cdir/naabu.json" \
      | jq -r '.port' \
      | sort -n \
      | uniq \
      | paste -sd, -)
    info "Unique open ports found: $open_ports"

    local final_urls_ports="output/$cdir/final_urls_and_ports.txt"
    cat "output/$cdir/naabu.json" \
      | jq -r '"\(.host):\(.port)"' \
      | sort -u \
      > "$final_urls_ports"

    local total_lines
    total_lines=$(wc -l < "$final_urls_ports")
    info "Created $total_lines domain:port entries in $final_urls_ports"
  fi
}

##############################################
# 4g) HTTPX Ã¢â‚¬â€œ Web Recon
##############################################
run_httpx() {
  if [[ "$USE_HTTPX" == "true" ]]; then
    info "Running httpx..."
    httpx -silent \
          -l "output/$cdir/final_urls_and_ports.txt" \
          -j \
          -o "output/$cdir/httpx.json" \
          >/dev/null 2>&1 || true

    local total_httpx
    total_httpx=$(wc -l < "output/$cdir/httpx.json")
    info "HTTPX processed $total_httpx domain:port combos"
  fi
}

##############################################
# 5) Merge line-based JSON -> single-array JSON
#    so the HTML report can parse properly.
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
# 6) Build HTML Report with Priority Scoring and Theme Toggle
##############################################
build_html_report() {
  info "Generating HTML report..."

  # Merge the line-based JSON into valid JSON arrays
  combine_json "output/$cdir/dnsx.json"   "output/$cdir/dnsx_merged.json"
  combine_json "output/$cdir/naabu.json"  "output/$cdir/naabu_merged.json"
  combine_json "output/$cdir/httpx.json"  "output/$cdir/httpx_merged.json"

  mv "output/$cdir/dnsx_merged.json"  "output/$cdir/dnsx.json"
  mv "output/$cdir/naabu_merged.json" "output/$cdir/naabu.json"
  mv "output/$cdir/httpx_merged.json" "output/$cdir/httpx.json"

  # Write the HTML template to report.html.
  # The table displays:
  # - Priority (computed), Domain, Resolvers, A records, DNS Status (from dnsx.json)
  # - Then one row per HTTP record (from httpx.json) with:
  #   CDN Name, CDN Type, Port, URL, Redirect Location, Homepage Title,
  #   Web Server, Technology Stack, Status Code, Content Length, CDN.
  local report_html="output/$cdir/report.html"
  cat << 'EOF' > "$report_html"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Domain Analysis Report</title>
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
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
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
    }
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
  </style>
</head>
<body>
  <div class="header">
    <h1>Domain Analysis Report</h1>
    <button id="themeToggle" class="toggle-btn">Toggle Dark/Light</button>
  </div>
  <div class="container">
    <table id="report-table">
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
        <th>Technology Stack</th>
        <th>Status Code</th>
        <th>Content Length</th>
        <th>CDN</th>
      </tr>
    </table>
  </div>
  <script>
    // Toggle theme functionality
    const toggleButton = document.getElementById('themeToggle');
    toggleButton.addEventListener('click', () => {
      document.body.classList.toggle('dark');
    });

    // Utility functions
    const unique = arr => [...new Set(arr)];
    const formatCell = arr => arr.length ? arr.join("<br>") : "N/A";

    // Compute priority score and bucket based on HTTP record and DNS record
    function computePriority(httpRecord, dnsRecord) {
      let score = 0;
      // Status code factor
      if (httpRecord.status_code === 200) {
        score += 5;
      } else if (httpRecord.status_code === 301 || httpRecord.status_code === 302) {
        score += 3;
      } else if (httpRecord.status_code >= 400) {
        score += 1;
      } else {
        score += 1;
      }
      // Content length factor
      if (httpRecord.content_length !== undefined) {
        if (httpRecord.content_length > 100000) score += 3;
        else if (httpRecord.content_length > 50000) score += 2;
        else if (httpRecord.content_length > 10000) score += 1;
      }
      // Technology stack factor
      if (httpRecord.tech && httpRecord.tech.length > 0) {
        score += 2;
      }
      // DNS factor (if available)
      if (dnsRecord && dnsRecord.status_code === "NOERROR") {
        score += 1;
      }
      // Map score to priority bucket
      if (score >= 10) return "P0";
      else if (score >= 8) return "P1";
      else if (score >= 6) return "P2";
      else if (score >= 4) return "P3";
      else return "P4";
    }

    // Return color based on priority; colors are chosen for sufficient contrast in both themes.
    function getPriorityColor(priority) {
      switch(priority) {
        case "P0": return "#e74c3c"; // red
        case "P1": return "#e67e22"; // amber
        case "P2": return "#2ecc71"; // green
        case "P3": return "#3498db"; // blue
        case "P4": return "#85c1e9"; // light blue
        default: return "inherit";
      }
    }

    async function loadData() {
      try {
        const dnsxData = await fetch("dnsx.json").then(res => res.json()).catch(() => []);
        const httpxData = await fetch("httpx.json").then(res => res.json()).catch(() => []);
        const combinedData = {};

        // Process DNSX data (keyed by record.host)
        dnsxData.forEach(record => {
          const domain = record.host;
          if (!combinedData[domain]) {
            combinedData[domain] = { dns: record, http: [] };
          } else {
            combinedData[domain].dns = record;
          }
        });

        // Process HTTPX data (keyed by hostname from record.input)
        httpxData.forEach(record => {
          const domain = record.input.split(":")[0];
          if (!combinedData[domain]) {
            combinedData[domain] = { dns: null, http: [record] };
          } else {
            combinedData[domain].http.push(record);
          }
        });

        const table = document.getElementById("report-table");

        Object.keys(combinedData).forEach(domain => {
          const data = combinedData[domain];

          // DNS fields
          const dnsResolvers = data.dns && data.dns.resolver ? data.dns.resolver : [];
          const dnsA = data.dns && data.dns.a ? data.dns.a : [];
          const dnsStatus = data.dns ? data.dns.status_code : "N/A";

          if (data.http.length > 0) {
            // Create one row per HTTP record
            data.http.forEach(record => {
              const priority = computePriority(record, data.dns);
              const row = document.createElement("tr");
              row.innerHTML = `
                <td style="background-color: ${getPriorityColor(priority)}; color: #fff;">${priority}</td>
                <td>${domain}</td>
                <td>${formatCell(dnsResolvers)}</td>
                <td>${formatCell(dnsA)}</td>
                <td>${dnsStatus}</td>
                <td>${record.cdn_name || "N/A"}</td>
                <td>${record.cdn_type || "N/A"}</td>
                <td>${record.port || "N/A"}</td>
                <td>${record.url || "N/A"}</td>
                <td>${record.location || "N/A"}</td>
                <td>${record.title || "N/A"}</td>
                <td>${record.webserver || "N/A"}</td>
                <td>${record.tech ? record.tech.join("<br>") : "N/A"}</td>
                <td>${record.status_code !== undefined ? record.status_code : "N/A"}</td>
                <td>${record.content_length !== undefined ? record.content_length : "N/A"}</td>
                <td>${record.cdn !== undefined ? record.cdn : "N/A"}</td>
              `;
              table.appendChild(row);
            });
          } else {
            // No HTTP record: create one row with HTTP fields as N/A
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
            `;
            table.appendChild(row);
          }
        });
      } catch (error) {
        console.error("Error loading data:", error);
      }
    }
    loadData();
  </script>
</body>
</html>
EOF

  info "HTML report generated in $report_html"
}

##############################################
# 7) Main Execution
##############################################
main() {
  # 1) Run enumerations
  run_chaos
  run_subfinder
  run_assetfinder
  run_crtsh

  # 2) Merge final subdomains
  echo "$domain_name" >> "$ALL_TEMP"
  echo "www.$domain_name" >> "$ALL_TEMP"
  sort -u "$ALL_TEMP" > "$MASTER_SUBS"
  rm -f "$ALL_TEMP"

  local total_subs
  total_subs=$(wc -l < "$MASTER_SUBS")
  warning "Combined total subdomains found: $total_subs"
  info "Results saved to $MASTER_SUBS"

  # 3) Run live checks and recon
  run_dnsx
  run_naabu
  run_httpx

  # 4) Build HTML report
  build_html_report
}

main
