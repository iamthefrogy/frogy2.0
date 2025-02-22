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
# 4f) DNSX – Live Domain Check
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
# 4g) Naabu – Port Scanning
##############################################
run_naabu() {
  if [[ "$USE_NAABU" == "true" ]]; then
    info "Running naabu..."
    # limiting to top ports or specific ports is optional
    # Adjust to suit your environment
    naabu -silent \
          -l "output/$cdir/master_subdomains.txt" \
          --top-ports 100 \
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
# 4h) HTTPX – Web Recon
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
    <meta charset="UTF-8">
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
      /* Charts row: flexible containers */
      .charts-row {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-bottom: 20px;
      }
      .chart-container {
        flex: 1 1 300px;
        min-width: 300px;
        max-width: 400px;
        background-color: var(--table-bg);
        border: 1px solid var(--table-border);
        border-radius: 5px;
        padding: 10px;
        box-sizing: border-box;
      }
      .chart-container canvas {
        width: 100%;
        height: 300px;
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
    </style>
  </head>
  <body>
    <div class="header">
      <h1>External Attack Surface Analysis Report</h1>
      <button id="themeToggle" class="toggle-btn">Change View</button>
    </div>
    <div class="container">
      <!-- SCOREBOARD -->
      <div class="scoreboard" id="scoreboard">
        <!-- JS will populate summary stats here -->
      </div>
      <!-- CHARTS -->
      <div class="charts-row">
        <!-- New Pie Chart for Login Interfaces vs Other Endpoints -->
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
      </div>
      <!-- SEARCH BOX -->
      <input type="text" id="searchBox" placeholder="Filter table (e.g. domain, status code, tech)..." />
      <!-- MAIN TABLE -->
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
          <th>Login Found</th>
          <th>Technology Stack</th>
          <th>Status Code</th>
          <th>Content Length</th>
          <th>CDN</th>
        </tr>
      </table>
    </div>
    <script>
      // Theme toggle
      const toggleButton = document.getElementById('themeToggle');
      toggleButton.addEventListener('click', () => {
        document.body.classList.toggle('dark');
      });

      // Table search
      const searchBox = document.getElementById('searchBox');
      const reportTable = document.getElementById('report-table');
      searchBox.addEventListener('input', () => {
        const query = searchBox.value.toLowerCase();
        const rows = reportTable.getElementsByTagName('tr');
        for (let i = 1; i < rows.length; i++) {
          const rowText = rows[i].innerText.toLowerCase();
          rows[i].style.display = rowText.includes(query) ? '' : 'none';
        }
      });

      // Utility
      const formatCell = arr => (arr && arr.length) ? arr.join("<br>") : "N/A";

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
        switch(priority) {
          case "P0": return "#e74c3c";
          case "P1": return "#e67e22";
          case "P2": return "#2ecc71";
          case "P3": return "#3498db";
          case "P4": return "#85c1e9";
          default:   return "inherit";
        }
      }

      async function loadData() {
        try {
          const [dnsxRes, naabuRes, httpxRes, loginRes] = await Promise.all([
            fetch("dnsx.json"),
            fetch("naabu.json"),
            fetch("httpx.json"),
            fetch("login.json")
          ]);
          const dnsxData = await dnsxRes.json().catch(() => []);
          const naabuData = await naabuRes.json().catch(() => []);
          const httpxData = await httpxRes.json().catch(() => []);
          const loginData = await loginRes.json().catch(() => []);

          // Build a lookup for login statuses keyed by URL
          const loginMap = {};
          loginData.forEach(item => {
            loginMap[item.url] = item.login_found;
          });

          // Compute counts for the pie chart
          const endpointsCount = httpxData.length;
          const loginFoundCount = loginData.filter(item => item.login_found === "Yes").length;
          buildLoginPieChart(endpointsCount, loginFoundCount);

          // Build scoreboard
          const liveSubs = dnsxData.filter(d => d.status_code==="NOERROR").length;
          const domainSet = new Set();
          dnsxData.forEach(d => { if(d.host) domainSet.add(d.host); });
          const totalSubdomains = domainSet.size;
          const distinctPorts = new Set(naabuData.map(n => n.port)).size;
          buildScoreboard({
            totalSubdomains,
            liveSubs,
            totalHttpx: endpointsCount,
            loginFoundCount
          });

          // Build distributions for charts
          const statusCount = {};
          httpxData.forEach(h => {
            const code = h.status_code || 0;
            statusCount[code] = (statusCount[code]||0) + 1;
          });
          const priorityCount = { "P0":0, "P1":0, "P2":0, "P3":0, "P4":0 };
          const dnsMap = {};
          dnsxData.forEach(d => { dnsMap[d.host] = d; });
          httpxData.forEach(h => {
            const domain = (h.input||"").split(":")[0];
            const dnsRec = dnsMap[domain] || null;
            const prio = computePriority(h, dnsRec);
            priorityCount[prio] = (priorityCount[prio]||0) + 1;
          });
          const portCount = {};
          naabuData.forEach(n => {
            const p = n.port || "unknown";
            portCount[p] = (portCount[p]||0) + 1;
          });
          const techCount = {};
          httpxData.forEach(h => {
            if(h.tech && Array.isArray(h.tech)) {
              h.tech.forEach(t => {
                techCount[t] = (techCount[t]||0) + 1;
              });
            }
          });

          buildCharts({
            statusCount,
            priorityCount,
            portCount,
            techCount
          });

          // Build main table
          const combinedData = {};
          dnsxData.forEach(d => {
            const domain = d.host;
            combinedData[domain] = { dns: d, http: [] };
          });
          httpxData.forEach(h => {
            const domain = (h.input||"").split(":")[0];
            if(!combinedData[domain]) combinedData[domain] = { dns: null, http: [h] };
            else combinedData[domain].http.push(h);
          });
          const table = document.getElementById("report-table");
          Object.keys(combinedData).forEach(domain => {
            const { dns, http } = combinedData[domain];
            const dnsResolvers = dns && dns.resolver ? dns.resolver : [];
            const dnsA = dns && dns.a ? dns.a : [];
            const dnsStatus = dns ? dns.status_code : "N/A";
            if(http && http.length) {
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
                  <td>${(h.status_code!==undefined) ? h.status_code : "N/A"}</td>
                  <td>${(h.content_length!==undefined) ? h.content_length : "N/A"}</td>
                  <td>${(h.cdn!==undefined) ? h.cdn : "N/A"}</td>
                `;
                table.appendChild(row);
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
              `;
              table.appendChild(row);
            }
          });
        } catch(err) {
          console.error("Error loading data or building report:", err);
        }
      }

      function buildScoreboard({totalSubdomains, liveSubs, totalHttpx, loginFoundCount}) {
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

      function buildCharts({statusCount, priorityCount, portCount, techCount}) {
        const scCanvas   = document.getElementById("statusCodeChart");
        const prCanvas   = document.getElementById("priorityChart");
        const portCanvas = document.getElementById("portChart");
        const techCanvas = document.getElementById("techChart");

        // Priority distribution chart
        if(prCanvas) {
          const labels = ["P0","P1","P2","P3","P4"];
          const data = labels.map(l => priorityCount[l] || 0);
          new Chart(prCanvas, {
            type: 'bar',
            data: {
              labels,
              datasets: [{
                label: 'Priority Buckets',
                data,
                backgroundColor: ['#e74c3c','#e67e22','#2ecc71','#3498db','#85c1e9']
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { display: false },
                title: { display: true, text: 'Asset Attractiveness by Hackers' }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // HTTP Status Codes chart
        if(scCanvas) {
          const labels = Object.keys(statusCount).sort((a,b)=> +a - +b);
          const data   = labels.map(l => statusCount[l]);
          new Chart(scCanvas, {
            type: 'bar',
            data: {
              labels,
              datasets: [{
                label: 'HTTP Status Codes',
                data,
                backgroundColor: ['#3498db','#1abc9c','#9b59b6','#f1c40f','#e74c3c','#34495e','#95a5a6']
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { display: false },
                title: { display: true, text: 'HTTP Status Codes' }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // Port usage chart
        if(portCanvas) {
          const sortedPorts = Object.keys(portCount).sort((a,b)=> +a - +b);
          const portVals = sortedPorts.map(p => portCount[p]);
          new Chart(portCanvas, {
            type: 'bar',
            data: {
              labels: sortedPorts,
              datasets: [{
                label: 'Open Ports',
                data: portVals,
                backgroundColor: '#f39c12'
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { display: false },
                title: { display: true, text: 'Port Usage' }
              },
              scales: { y: { beginAtZero: true } }
            }
          });
        }

        // Tech usage chart (horizontal)
        if(techCanvas) {
          const sortedTech = Object.keys(techCount).sort((a,b)=> techCount[b]-techCount[a]);
          const top10 = sortedTech.slice(0,10);
          const topVals = top10.map(t => techCount[t]);
          new Chart(techCanvas, {
            type: 'bar',
            data: {
              labels: top10,
              datasets: [{
                label: 'Tech Usage (Top 10)',
                data: topVals,
                backgroundColor: '#9b59b6'
              }]
            },
            options: {
              responsive: true,
              indexAxis: 'y',
              plugins: {
                legend: { display: false },
                title: { display: true, text: 'Top 10 Technologies' }
              },
              scales: { x: { beginAtZero: true } }
            }
          });
        }
      }

      function buildLoginPieChart(endpointsCount, loginFoundCount) {
        const canvas = document.getElementById("loginPieChart");
        if (canvas) {
          new Chart(canvas, {
            type: 'bar',
            data: {
              labels: ["Found", "Not Found"],
              datasets: [{
                // no label here
                data: [loginFoundCount, endpointsCount - loginFoundCount],
                backgroundColor: ['#e74c3c', '#2ecc71']
              }]
            },
            options: {
              responsive: true,
              plugins: {
                title: {
                  display: true,
                  text: 'Login Interfaces Identified'
                },
                legend: {
                  display: false  // <--- hide the legend
                }
              }
            }
          });
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

  # 3) Run DNSX, Naabu, HTTPX
  run_dnsx
  run_naabu
  run_httpx

  # 4) Run Login Detection
  run_login_detection

  # 5) Build HTML report
  build_html_report

  # 6) Final summary
  show_summary
}

main
