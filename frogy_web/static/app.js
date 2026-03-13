"use strict";

/* ── Utilities ──────────────────────────────────────────────────── */
const domainPattern = /^[A-Za-z0-9.-]+$/;

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatDateTimeShort(iso) {
  if (!iso) return "—";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return "—";
  const now = new Date();
  const diff = now - dt;
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return dt.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatDuration(seconds) {
  if (!seconds || seconds < 0) return "";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/* ── State ──────────────────────────────────────────────────────── */
const state = {
  scans: [],
  selected: new Set(),
  pollTimer: null,
  pollInterval: 5000,
  modalMode: "create",
  editingSlug: null,
  flashTimeout: null,
  activeFilter: "all",
  searchText: "",
};

/* ── DOM References ─────────────────────────────────────────────── */
const el = {
  tableBody:           () => document.getElementById("scan-table-body"),
  selectAll:           () => document.getElementById("select-all"),
  newButton:           () => document.getElementById("new-scan-btn"),
  flash:               () => document.getElementById("flash-message"),
  themeToggle:         () => document.getElementById("theme-toggle"),
  modal:               () => document.getElementById("scan-modal"),
  backdrop:            () => document.getElementById("modal-backdrop"),
  modalTitle:          () => document.getElementById("modal-title"),
  modalForm:           () => document.getElementById("modal-form"),
  modalName:           () => document.getElementById("modal-project-name"),
  modalTargets:        () => document.getElementById("modal-targets"),
  modalExclusions:     () => document.getElementById("modal-exclusions"),
  modalScheduleField:  () => document.getElementById("modal-schedule-field"),
  modalSchedule:       () => document.getElementById("modal-schedule"),
  modalFeedback:       () => document.getElementById("modal-feedback"),
  modalClose:          () => document.getElementById("modal-close"),
  modalCancel:         () => document.getElementById("modal-cancel"),
  modalActionButtons:  () => document.querySelectorAll("#modal-form [data-run-mode]"),
  modalCompanyName:    () => document.getElementById("modal-company-name"),
  targetsModal:        () => document.getElementById("targets-modal"),
  targetsModalClose:   () => document.getElementById("targets-modal-close"),
  targetsModalOk:      () => document.getElementById("targets-modal-ok"),
  targetsList:         () => document.getElementById("targets-list"),
  targetsCount:        () => document.getElementById("targets-count"),
  bulkBar:             () => document.getElementById("bulk-bar"),
  bulkCount:           () => document.getElementById("bulk-count"),
  bulkDeleteBtn:       () => document.getElementById("bulk-delete-btn"),
  bulkDeselectBtn:     () => document.getElementById("bulk-deselect-btn"),
  searchInput:         () => document.getElementById("scan-search"),
  // KPI cards
  kpiProjects:         () => document.getElementById("kpi-projects"),
  kpiRunning:          () => document.getElementById("kpi-running"),
  kpiSucceeded:        () => document.getElementById("kpi-succeeded"),
  kpiQueued:           () => document.getElementById("kpi-queued"),
};

/* ── Flash ──────────────────────────────────────────────────────── */
function refreshFlash(message, type = "info") {
  const flashEl = el.flash();
  if (!flashEl) return;
  flashEl.textContent = message || "";
  flashEl.classList.remove("error", "success");
  if (!message) return;
  if (type === "error")   flashEl.classList.add("error");
  if (type === "success") flashEl.classList.add("success");
  clearTimeout(state.flashTimeout);
  state.flashTimeout = window.setTimeout(() => {
    flashEl.textContent = "";
    flashEl.classList.remove("error", "success");
  }, 4000);
}

function setModalFeedback(message, isError = false) {
  const fb = el.modalFeedback();
  if (!fb) return;
  fb.textContent = message || "";
  fb.classList.toggle("error", Boolean(isError));
}

/* ── Status Badges ──────────────────────────────────────────────── */
function statusBadgeHtml(status) {
  const map = {
    succeeded: { cls: "success",   label: "Done" },
    success:   { cls: "success",   label: "Done" },
    failed:    { cls: "failed",    label: "Failed" },
    running:   { cls: "running",   label: "Running" },
    queued:    { cls: "queued",    label: "Queued" },
    scheduled: { cls: "scheduled", label: "Scheduled" },
  };
  const info = map[status] || { cls: "never", label: "Never run" };
  return `<span class="status-badge status-badge--${info.cls}"><span class="dot"></span>${info.label}</span>`;
}

/* ── Render Project List ────────────────────────────────────────── */
function renderProjectList(scans) {
  const body = el.tableBody();
  if (!body) return;
  body.innerHTML = "";

  if (!scans.length) {
    body.innerHTML = `<div class="project-list-empty">No projects yet. Start with <strong>+ New Scan</strong>.</div>`;
    syncBulkBar();
    return;
  }

  scans.forEach((scan) => {
    const isSelected = state.selected.has(scan.slug);
    const percent = Math.max(0, Math.min(100, scan.progress?.percent ?? 0));
    const statusDone   = scan.status === "succeeded" || scan.status === "success";
    const statusFailed = scan.status === "failed";
    const fillClass    = statusDone ? "done" : statusFailed ? "failed" : "";
    const stepTotal    = typeof scan.progress?.step === "number" && typeof scan.progress?.total === "number"
      ? `${scan.progress.step}/${scan.progress.total} steps`
      : `${percent}%`;
    const timeLabel = formatDateTimeShort(scan.ran_at);
    let durationStr = "";
    if (scan.started_at) {
      const startMs = new Date(scan.started_at).getTime();
      if (!isNaN(startMs)) {
        const isRunning = scan.status === "running";
        const endMs = isRunning ? Date.now() : (scan.ran_at ? new Date(scan.ran_at).getTime() : 0);
        const secs = Math.floor((endMs - startMs) / 1000);
        if (secs > 0) durationStr = ` · ${formatDuration(secs)}`;
      }
    }

    const stats = scan.summary_stats;
    const pipelineStats = statusDone && stats && Object.keys(stats).length
      ? `<div class="proj-stats-line">${scan.targets_count ?? 0} input${(scan.targets_count ?? 0) !== 1 ? "s" : ""} → ${stats.subdomains ?? 0} unique subdomains → ${stats.live_assets ?? 0} live → ${stats.web_hosts ?? 0} web</div>`
      : `<div class="project-card__meta">${scan.targets_count ?? 0} target${scan.targets_count !== 1 ? "s" : ""}</div>`;

    const hasArtifacts = typeof scan.run_id === "string" && scan.run_id.startsWith("run-");
    const reportBtn = hasArtifacts && scan.report
      ? `<a class="btn btn--ghost btn--sm" href="${escapeHtml(scan.report)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">Report →</a>`
      : "";

    const div = document.createElement("div");
    div.className = `project-card${isSelected ? " selected" : ""}`;
    div.dataset.slug   = scan.slug;
    div.dataset.name   = (scan.name || "").toLowerCase();
    div.dataset.status = scan.status || "never";
    div.setAttribute("role", "listitem");

    div.innerHTML = `
      <div><input type="checkbox" class="row-check" aria-label="Select ${escapeHtml(scan.name)}"${isSelected ? " checked" : ""}></div>
      <div>
        <div class="project-card__name">
          <a href="/projects/${escapeHtml(scan.slug)}" onclick="event.stopPropagation()">${escapeHtml(scan.name)}</a>
        </div>
        ${pipelineStats}
      </div>
      <div>${statusBadgeHtml(scan.status)}</div>
      <div>
        <div class="progress-bar-wrap">
          <div class="progress-bar-fill ${fillClass}" style="width:${percent}%"></div>
        </div>
        <div class="progress-label">${stepTotal} · ${timeLabel}${durationStr}</div>
      </div>
      <div class="project-card__actions">
        ${reportBtn}
        <button class="btn btn--ghost btn--sm menu-btn" data-slug="${escapeHtml(scan.slug)}" type="button" title="More actions" onclick="event.stopPropagation()">···</button>
      </div>`;

    // Row click = toggle select
    div.addEventListener("click", () => {
      const cb = div.querySelector(".row-check");
      const willSelect = !state.selected.has(scan.slug);
      toggleSelect(scan.slug, willSelect);
      if (cb) cb.checked = willSelect;
    });

    // Checkbox click
    const cb = div.querySelector(".row-check");
    if (cb) {
      cb.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleSelect(scan.slug, e.currentTarget.checked);
      });
    }

    // ··· menu
    const menuBtn = div.querySelector(".menu-btn");
    if (menuBtn) {
      menuBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openContextMenu(scan, menuBtn);
      });
    }

    body.appendChild(div);
  });

  syncBulkBar();
}

/* ── Apply Filter ───────────────────────────────────────────────── */
function applyFilter() {
  const body = el.tableBody();
  if (!body) return;
  const search = state.searchText.toLowerCase();
  const filter = state.activeFilter;
  const cards  = body.querySelectorAll(".project-card");
  let visible  = 0;

  cards.forEach((card) => {
    const name   = (card.dataset.name || "").toLowerCase();
    const status = card.dataset.status || "";
    const matchesSearch = !search || name.includes(search);
    const matchesFilter = filter === "all" || status === filter || (filter === "succeeded" && status === "success");
    const show = matchesSearch && matchesFilter;
    card.style.display = show ? "" : "none";
    if (show) visible++;
  });

  if (visible === 0 && state.scans.length > 0) {
    if (!body.querySelector(".filter-empty")) {
      const div = document.createElement("div");
      div.className = "project-list-empty filter-empty";
      div.textContent = "No projects match the current filter.";
      body.appendChild(div);
    }
  } else {
    const emp = body.querySelector(".filter-empty");
    if (emp) emp.remove();
  }
}

/* ── Load & Render ──────────────────────────────────────────────── */
async function loadScans() {
  try {
    const res = await fetch("/api/scans");
    if (!res.ok) throw new Error(`Request failed: ${res.status}`);
    const data = await res.json();
    state.scans = data.scans || [];
    updateKpiCards(state.scans);
    renderProjectList(state.scans);
    applyFilter();
  } catch (err) {
    refreshFlash(err.message, "error");
  }
}

function updateKpiCards(scans) {
  const total     = scans.length;
  const running   = scans.filter(s => s.status === "running").length;
  const succeeded = scans.filter(s => s.status === "succeeded" || s.status === "success").length;
  const queued    = scans.filter(s => s.status === "queued" || s.status === "scheduled").length;

  let lastScanTime = "—";
  const withRun = scans.filter(s => s.ran_at).sort((a, b) => new Date(b.ran_at) - new Date(a.ran_at));
  if (withRun.length) lastScanTime = formatDateTimeShort(withRun[0].ran_at);

  // KPI cards
  const kp = el.kpiProjects();  if (kp) kp.textContent = total;
  const kr = el.kpiRunning();   if (kr) kr.textContent = running;
  const ks = el.kpiSucceeded(); if (ks) ks.textContent = succeeded;
  const kq = el.kpiQueued();    if (kq) kq.textContent = queued;
}

/* ── Selection ──────────────────────────────────────────────────── */
function toggleSelect(slug, checked) {
  if (checked) {
    state.selected.add(slug);
  } else {
    state.selected.delete(slug);
  }
  // Sync visual state of the card
  const body = el.tableBody();
  if (body) {
    body.querySelectorAll(".project-card").forEach((card) => {
      const sel = state.selected.has(card.dataset.slug);
      card.classList.toggle("selected", sel);
      const cb = card.querySelector(".row-check");
      if (cb) cb.checked = sel;
    });
  }
  syncSelectAll();
  syncBulkBar();
}

function syncSelectAll() {
  const sa = el.selectAll();
  if (!sa || !state.scans.length) {
    if (sa) { sa.checked = false; sa.indeterminate = false; }
    return;
  }
  const size = state.selected.size;
  if (size === 0) {
    sa.checked = false; sa.indeterminate = false;
  } else if (size === state.scans.length) {
    sa.checked = true;  sa.indeterminate = false;
  } else {
    sa.checked = false; sa.indeterminate = true;
  }
}

function syncBulkBar() {
  const bar   = el.bulkBar();
  const count = el.bulkCount();
  if (!bar) return;
  const n = state.selected.size;
  bar.classList.toggle("hidden", n === 0);
  if (count) count.textContent = `${n} selected`;
}

/* ── Context Menu (··· button) ──────────────────────────────────── */
let activeMenu = null;

function openContextMenu(scan, anchor) {
  closeContextMenu();

  const isActive = scan.is_running || scan.is_queued || scan.is_scheduled;

  const menu = document.createElement("div");
  menu.className = "dropdown-menu";
  menu.style.cssText = `
    position:fixed; z-index:400; min-width:160px;
    background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius-lg); padding:4px;
    box-shadow:var(--shadow); font-size:0.875rem;
  `;

  const items = [
    { label: isActive ? "⏹ Stop" : "🔄 Rescan",
      action: () => isActive ? cancelScan(scan) : rescanScan(scan) },
    { label: "✏️ Modify", action: () => openModal("edit", scan), disabled: isActive },
    { label: "👁 Targets", action: () => openTargetsModal(scan) },
    { label: "📋 View Logs", action: () => openLogPanel(scan.slug, scan.name) },
    { sep: true },
    { label: "🗑 Delete", action: () => deleteScans([scan.slug]), danger: true, disabled: isActive },
  ];

  items.forEach((item) => {
    if (item.sep) {
      const hr = document.createElement("div");
      hr.style.cssText = "height:1px;background:var(--border);margin:3px 4px";
      menu.appendChild(hr);
      return;
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = item.label;
    btn.disabled = Boolean(item.disabled);
    btn.style.cssText = `
      display:block; width:100%; padding:6px 10px; border-radius:6px;
      border:none; background:transparent; text-align:left;
      cursor:${item.disabled ? "not-allowed" : "pointer"}; font-family:inherit;
      color:${item.danger ? "var(--danger)" : "var(--text-2)"};
      opacity:${item.disabled ? "0.45" : "1"};
      font-size:0.875rem;
    `;
    btn.addEventListener("mouseover", () => { if (!item.disabled) btn.style.background = "var(--surface-raised)"; });
    btn.addEventListener("mouseout",  () => { btn.style.background = "transparent"; });
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      closeContextMenu();
      item.action();
    });
    menu.appendChild(btn);
  });

  document.body.appendChild(menu);
  activeMenu = menu;

  // Position
  const rect = anchor.getBoundingClientRect();
  const mh = 200;
  let top = rect.bottom + 4;
  if (top + mh > window.innerHeight) top = rect.top - mh - 4;
  let left = rect.right - 160;
  if (left < 8) left = 8;
  menu.style.top  = `${top}px`;
  menu.style.left = `${left}px`;

  setTimeout(() => {
    document.addEventListener("click", closeContextMenu, { once: true });
  }, 0);
}

function closeContextMenu() {
  if (activeMenu) {
    activeMenu.remove();
    activeMenu = null;
  }
}

/* ── Modal ──────────────────────────────────────────────────────── */
function openModal(mode, scan = null) {
  state.modalMode    = mode;
  state.editingSlug  = scan?.slug || null;
  const titleEl = el.modalTitle();
  if (titleEl) titleEl.textContent = mode === "edit" ? "Modify Scan" : "New Scan";
  const nameEl = el.modalName();
  if (nameEl) nameEl.value = scan?.name || "";
  const cnEl = el.modalCompanyName();
  if (cnEl) cnEl.value = scan?.company_name || "";
  const targetsEl = el.modalTargets();
  if (targetsEl) targetsEl.value = scan?.targets || "";
  const exclEl = el.modalExclusions();
  if (exclEl) exclEl.value = (scan?.exclusions || []).join("\n");
  const scheduleEl = el.modalSchedule();
  if (scheduleEl) scheduleEl.value = "";
  const sfEl = el.modalScheduleField();
  if (sfEl) sfEl.classList.add("hidden");
  setModalFeedback("");
  const modalEl = el.modal();
  const backdropEl = el.backdrop();
  if (modalEl)  { modalEl.classList.remove("hidden"); modalEl.classList.add("show"); }
  if (backdropEl) backdropEl.classList.add("show");
  window.requestAnimationFrame(() => { const n = el.modalName(); if (n) n.focus(); });
}

function closeModal() {
  const modalEl = el.modal();
  const backdropEl = el.backdrop();
  if (modalEl)   modalEl.classList.remove("show");
  if (backdropEl) backdropEl.classList.remove("show");
  window.setTimeout(() => {
    if (modalEl) modalEl.classList.add("hidden");
  }, 200);
  setModalFeedback("");
}

function openTargetsModal(scan) {
  const targets = (scan.targets || "").split(/\r?\n/).filter(Boolean);
  const countEl = el.targetsCount();
  if (countEl) countEl.textContent = targets.length;
  const listEl  = el.targetsList();
  if (listEl) {
    listEl.innerHTML = "";
    targets.forEach((t) => {
      const li = document.createElement("li");
      li.textContent = t;
      listEl.appendChild(li);
    });
  }
  const tm = el.targetsModal();
  const bd = el.backdrop();
  if (tm)  { tm.classList.remove("hidden"); tm.classList.add("show"); }
  if (bd)  bd.classList.add("show");
}

function closeTargetsModal() {
  const tm = el.targetsModal();
  const bd = el.backdrop();
  if (tm) tm.classList.remove("show");
  if (bd) bd.classList.remove("show");
  window.setTimeout(() => { if (tm) tm.classList.add("hidden"); }, 200);
}

function toggleModalBusy(isBusy) {
  el.modalActionButtons().forEach((b) => { b.disabled = isBusy; });
  const mc = el.modalCancel(); if (mc) mc.disabled = isBusy;
  const cx = el.modalClose();  if (cx) cx.disabled = isBusy;
}

function validateTargets(text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (!lines.length) return { error: "Add at least one primary domain." };
  for (const line of lines) {
    if (!domainPattern.test(line)) return { error: `Invalid domain: ${line}` };
  }
  return { lines };
}

function toIsoString(value) {
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) throw new Error("Please provide a valid date & time.");
  return dt.toISOString();
}

async function submitScan(mode) {
  const nameEl    = el.modalName();
  const targetsEl = el.modalTargets();
  const projectName = (nameEl?.value || "").trim();
  const targetsText = (targetsEl?.value || "").trim();

  if (!projectName) {
    setModalFeedback("Company name is required.", true);
    nameEl?.focus();
    return;
  }
  const validation = validateTargets(targetsText);
  if (validation.error) {
    setModalFeedback(validation.error, true);
    targetsEl?.focus();
    return;
  }

  let scheduledFor = "";
  if (mode === "schedule") {
    const sfEl = el.modalScheduleField();
    const scheduleEl = el.modalSchedule();
    if (sfEl?.classList.contains("hidden")) {
      sfEl.classList.remove("hidden");
      setModalFeedback("Pick a future start date & time.", true);
      scheduleEl?.focus();
      return;
    }
    if (!scheduleEl?.value) {
      setModalFeedback("Pick a future start date & time.", true);
      scheduleEl?.focus();
      return;
    }
    scheduledFor = toIsoString(scheduleEl.value);
  }

  const cnEl = el.modalCompanyName();
  const companyName = (cnEl?.value || "").trim();
  const exclEl = el.modalExclusions();
  const exclusions = (exclEl?.value || "").split("\n").map(s => s.trim()).filter(Boolean);
  const payload = { project_name: projectName, targets: targetsText, start_mode: mode, exclusions };
  if (companyName) payload.company_name = companyName;
  if (scheduledFor) payload.scheduled_for = scheduledFor;

  const slug     = state.modalMode === "edit" ? state.editingSlug : null;
  const endpoint = slug ? `/api/scans/${encodeURIComponent(slug)}` : "/api/scans";
  const method   = slug ? "PUT" : "POST";

  try {
    setModalFeedback("Submitting…");
    toggleModalBusy(true);
    const res  = await fetch(endpoint, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed: ${res.status}`);
    closeModal();
    refreshFlash(body.message || "Scan saved.", "success");
    await loadScans();
    if (body.slug) state.selected = new Set([body.slug]);
  } catch (err) {
    setModalFeedback(err.message, true);
  } finally {
    toggleModalBusy(false);
  }
}

/* ── Scan Actions ────────────────────────────────────────────────── */
async function rescanScan(scan) {
  try {
    const res  = await fetch(`/api/scans/${encodeURIComponent(scan.slug)}/rescan`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed: ${res.status}`);
    refreshFlash(body.message || "Rescan started.", "success");
    await loadScans();
  } catch (err) { refreshFlash(err.message, "error"); }
}

async function cancelScan(scan) {
  try {
    const res  = await fetch(`/api/scans/${encodeURIComponent(scan.slug)}/cancel`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed: ${res.status}`);
    refreshFlash(body.message || "Cancellation requested.", "success");
    await loadScans();
  } catch (err) { refreshFlash(err.message, "error"); }
}

async function deleteScans(slugs) {
  if (!slugs.length) return;
  const names     = slugs.map(s => state.scans.find(sc => sc.slug === s)?.name || s).join(", ");
  const confirmed = window.confirm(`Delete ${slugs.length > 1 ? "these scans" : "scan"} (${names}) and all artifacts?`);
  if (!confirmed) return;
  try {
    const res  = await fetch("/api/scans/bulk-delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slugs }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed: ${res.status}`);
    refreshFlash(body.message || "Deletion complete.", "success");
    slugs.forEach(s => state.selected.delete(s));
    await loadScans();
  } catch (err) { refreshFlash(err.message, "error"); }
}

/* ── Downloads ──────────────────────────────────────────────────── */
function triggerFileDownload(url) {
  const a = document.createElement("a");
  a.href = url;
  a.setAttribute("download", "");
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function downloadCsvViaReport(scan, fallbackUrl) {
  if (!scan.report) { triggerFileDownload(fallbackUrl); return; }
  const iframe = document.createElement("iframe");
  iframe.style.cssText = "position:fixed;left:-9999px;width:0;height:0";
  iframe.setAttribute("aria-hidden", "true");
  iframe.src = `${scan.report}?ts=${Date.now()}`;
  const cleanup = () => { iframe.removeEventListener("load", onLoad); if (iframe.parentNode) iframe.parentNode.removeChild(iframe); };
  const onLoad = () => {
    try {
      const win = iframe.contentWindow;
      if (!win || typeof win.exportAllTableRowsToCSV !== "function") throw new Error("Unable to access report exporter.");
      const attemptExport = (retries = 12) => {
        try {
          const body = win.document.getElementById("report-table-body");
          const rowCount = body ? body.querySelectorAll("tr").length : 0;
          if (!rowCount) { if (retries > 0) { setTimeout(() => attemptExport(retries - 1), 250); return; } throw new Error("Report data not ready yet."); }
          win.exportAllTableRowsToCSV(`${scan.slug}-${scan.run_id}-report.csv`);
          setTimeout(cleanup, 2000);
        } catch (err) { if (retries > 0) setTimeout(() => attemptExport(retries - 1), 250); else { cleanup(); refreshFlash(err.message || "Unable to export CSV.", "error"); } }
      };
      attemptExport();
    } catch (err) { cleanup(); refreshFlash(err.message || "Unable to export CSV.", "error"); }
  };
  iframe.addEventListener("load", onLoad);
  iframe.addEventListener("error", () => { cleanup(); refreshFlash("Failed to load report for CSV export.", "error"); });
  document.body.appendChild(iframe);
}

/* ── Log Panel ───────────────────────────────────────────────────── */
let logPollTimer = null;

function openLogPanel(slug, name) {
  const panel = document.getElementById('log-panel');
  const backdrop = document.getElementById('log-backdrop');
  const output = document.getElementById('log-output');
  const title = document.getElementById('log-panel-title');
  if (!panel) return;
  title.textContent = `Logs — ${name}`;
  output.textContent = 'Loading…';
  panel.classList.remove('hidden');
  backdrop.classList.remove('hidden');
  let cursor = 0;
  async function poll() {
    try {
      const r = await fetch(`/api/scans/${encodeURIComponent(slug)}/logs?cursor=${cursor}`);
      if (!r.ok) return;
      const d = await r.json();
      if (d.lines && d.lines.length) {
        if (cursor === 0) output.textContent = '';
        output.textContent += d.lines.join('\n') + '\n';
        output.scrollTop = output.scrollHeight;
        cursor = d.cursor;
      }
      if (!d.done) { logPollTimer = setTimeout(poll, 1500); }
    } catch (_) {}
  }
  poll();
}

function closeLogPanel() {
  clearTimeout(logPollTimer);
  document.getElementById('log-panel')?.classList.add('hidden');
  document.getElementById('log-backdrop')?.classList.add('hidden');
  const out = document.getElementById('log-output');
  if (out) out.textContent = '';
}

/* ── API Keys Panel ─────────────────────────────────────────────── */
const API_KEY_META = {
  github_token:       { label: "GitHub Token",       note: "Enables GitHub surface discovery (repos + secrets)" },
  shodan_api_key:     { label: "Shodan API Key",     note: "Enables banner enrichment + favicon clustering" },
  censys_api_key:     { label: "Censys API Key",     note: "Censys Search v2 — single Bearer token (new platform)" },
  otx_api_key:        { label: "OTX API Key",        note: "Enhanced passive DNS from AlienVault OTX" },
  virustotal_api_key: { label: "VirusTotal API Key", note: "Additional passive subdomain source" },
  whoisxml_api_key:   { label: "WhoisXML API Key",   note: "Registrant email pivot for seed expansion" },
  chaos_api_key:      { label: "Chaos/PDCP Key",     note: "ProjectDiscovery passive subdomain feed" },
};

function openApiPanel() {
  const panel = document.getElementById("api-panel");
  const bd = document.getElementById("api-panel-backdrop");
  if (!panel) return;
  panel.classList.remove("hidden");
  bd?.classList.remove("hidden");
  loadApiPanelContent();
}

function closeApiPanel() {
  document.getElementById("api-panel")?.classList.add("hidden");
  document.getElementById("api-panel-backdrop")?.classList.add("hidden");
}

async function loadApiPanelContent() {
  const body = document.getElementById("api-panel-body");
  if (!body) return;
  body.innerHTML = '<p class="api-panel-loading">Loading…</p>';
  try {
    const res = await fetch("/api/config");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderApiPanel(body, data.api_keys || {}, data.settings || {});
  } catch (err) {
    body.innerHTML = `<p class="api-panel-loading" style="color:var(--danger)">Failed to load: ${escapeHtml(err.message)}</p>`;
  }
}

function renderApiPanel(body, apiKeys, settings) {
  let html = '<div class="api-panel-list">';
  for (const [keyName, meta] of Object.entries(API_KEY_META)) {
    const info = apiKeys[keyName] || { configured: false, preview: "" };
    const statusCls = info.configured ? "api-status--ok" : "api-status--none";
    const statusLabel = info.configured ? "✓ Configured" : "— Not set";
    html += `
      <div class="api-row" data-key="${escapeHtml(keyName)}">
        <div class="api-row__header">
          <span class="api-row__label">${escapeHtml(meta.label)}</span>
          <span class="api-status ${statusCls}">${statusLabel}</span>
        </div>
        <div class="api-row__note">${escapeHtml(meta.note)}</div>
        ${info.configured ? `<div class="api-row__preview">${escapeHtml(info.preview)}</div>` : ""}
        <div class="api-row__controls">
          <input type="password" class="api-input" placeholder="${info.configured ? "Enter new value to update" : "Paste API key"}" autocomplete="off" data-key="${escapeHtml(keyName)}">
          <button class="btn btn--ghost btn--sm api-save-btn" type="button" data-key="${escapeHtml(keyName)}">Save</button>
          <button class="btn btn--ghost btn--sm api-test-btn" type="button" data-key="${escapeHtml(keyName)}"${!info.configured ? " disabled" : ""}>Test</button>
          ${info.configured ? `<button class="btn btn--danger-ghost btn--sm api-clear-btn" type="button" data-key="${escapeHtml(keyName)}">Clear</button>` : ""}
        </div>
        <div class="api-row__feedback"></div>
      </div>`;
  }
  html += "</div>";

  body.innerHTML = html;

  body.querySelectorAll(".api-save-btn").forEach((btn) => {
    btn.addEventListener("click", () => saveApiKey(btn.dataset.key));
  });
  body.querySelectorAll(".api-test-btn").forEach((btn) => {
    btn.addEventListener("click", () => testApiKey(btn.dataset.key));
  });
  body.querySelectorAll(".api-clear-btn").forEach((btn) => {
    btn.addEventListener("click", () => clearApiKey(btn.dataset.key));
  });
}

async function saveApiKey(keyName) {
  const row = document.querySelector(`.api-row[data-key="${keyName}"]`);
  if (!row) return;
  const input = row.querySelector(".api-input");
  const feedback = row.querySelector(".api-row__feedback");
  const value = input?.value?.trim() || "";
  try {
    const res = await fetch("/api/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_keys: { [keyName]: value } }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    if (feedback) { feedback.textContent = "Saved."; feedback.style.color = "var(--success)"; }
    if (input) input.value = "";
    setTimeout(() => loadApiPanelContent(), 800);
  } catch (err) {
    if (feedback) { feedback.textContent = err.message; feedback.style.color = "var(--danger)"; }
  }
}

async function testApiKey(keyName) {
  const row = document.querySelector(`.api-row[data-key="${keyName}"]`);
  if (!row) return;
  const feedback = row.querySelector(".api-row__feedback");
  const btn = row.querySelector(".api-test-btn");
  if (btn) btn.disabled = true;
  if (feedback) { feedback.textContent = "Testing…"; feedback.style.color = "var(--text-3)"; }
  try {
    const res = await fetch(`/api/config/test/${encodeURIComponent(keyName)}`, { method: "POST" });
    const data = await res.json().catch(() => ({}));
    const ok = data.ok === true;
    if (feedback) {
      feedback.textContent = data.message || (ok ? "OK" : "Failed");
      feedback.style.color = ok ? "var(--success)" : "var(--danger)";
    }
  } catch (err) {
    if (feedback) { feedback.textContent = err.message; feedback.style.color = "var(--danger)"; }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function clearApiKey(keyName) {
  const row = document.querySelector(`.api-row[data-key="${keyName}"]`);
  if (!row) return;
  const feedback = row.querySelector(".api-row__feedback");
  const btn = row.querySelector(".api-clear-btn");
  if (btn) btn.disabled = true;
  try {
    const res = await fetch("/api/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_keys: { [keyName]: "" } }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    if (feedback) { feedback.textContent = "Cleared."; feedback.style.color = "var(--success)"; }
    setTimeout(() => loadApiPanelContent(), 800);
  } catch (err) {
    if (feedback) { feedback.textContent = err.message; feedback.style.color = "var(--danger)"; }
    if (btn) btn.disabled = false;
  }
}

/* ── Theme ───────────────────────────────────────────────────────── */
function applyTheme(theme) {
  document.body.dataset.theme = theme;
  const toggle = el.themeToggle();
  if (toggle) toggle.textContent = theme === "light" ? "🌞" : "🌙";
  localStorage.setItem("frogyTheme", theme);
}

function toggleTheme() {
  applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
}

function setupTheme() {
  const stored = localStorage.getItem("frogyTheme");
  if (stored === "light" || stored === "dark") {
    applyTheme(stored);
  } else {
    applyTheme(window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  }
}

/* ── Polling ─────────────────────────────────────────────────────── */
function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = window.setInterval(loadScans, state.pollInterval);
}

/* ── Project Detail Page ─────────────────────────────────────────── */
async function loadProjectDetail(slug) {
  window._currentSlug = slug;
  try {
    const res = await fetch(`/api/projects/${encodeURIComponent(slug)}`);
    if (!res.ok) throw new Error(`Project not found (${res.status})`);
    const d = await res.json();

    loadProjectExclusions(slug);

    // Title / breadcrumb
    document.querySelectorAll(".js-project-name").forEach(el => { el.textContent = d.name; });
    document.title = `Orbis — ${d.name}`;

    // Meta line
    const metaEl = document.getElementById("project-meta");
    if (metaEl) {
      const parts = [];
      if (d.created_at) parts.push(`Created ${formatDateTimeShort(d.created_at)}`);
      if (d.total_runs !== undefined) parts.push(`${d.total_runs} run${d.total_runs !== 1 ? "s" : ""}`);
      if (d.targets?.length) parts.push(`${d.targets.length} target${d.targets.length !== 1 ? "s" : ""}`);
      metaEl.textContent = parts.join(" · ");
    }

    // Summary stats
    const statsEl = document.getElementById("project-summary-stats");
    if (statsEl && d.summary_stats && Object.keys(d.summary_stats).length) {
      const s = d.summary_stats;
      statsEl.innerHTML = `
        <div class="summary-stats-row">
          ${s.subdomains  !== undefined ? `<div class="summary-stat"><span class="summary-stat-value">${s.subdomains}</span><span class="summary-stat-label">Subdomains</span></div>` : ""}
          ${s.live_assets !== undefined ? `<div class="summary-stat"><span class="summary-stat-value">${s.live_assets}</span><span class="summary-stat-label">Live Assets</span></div>` : ""}
          ${s.web_hosts   !== undefined ? `<div class="summary-stat"><span class="summary-stat-value">${s.web_hosts}</span><span class="summary-stat-label">Web Hosts</span></div>` : ""}
        </div>`;
    }

    // Targets list
    const tListEl = document.getElementById("targets-detail-list");
    if (tListEl && d.targets?.length) {
      tListEl.innerHTML = d.targets.map(t => `<li>${escapeHtml(t)}</li>`).join("");
    }

    // Run history
    const container = document.getElementById("run-history-list");
    if (container) renderRunHistory(d.runs || [], slug, container);

    // Poll if running
    if (d.last_status === "running") {
      setTimeout(() => loadProjectDetail(slug), 6000);
    }
  } catch (err) {
    refreshFlash(err.message, "error");
  }
}

/* ── Project Exclusions ──────────────────────────────────────────── */
async function loadProjectExclusions(slug) {
  try {
    const r = await fetch(`/api/projects/${encodeURIComponent(slug)}/exclusions`);
    if (!r.ok) return;
    const data = await r.json();
    renderExclusions(data.exclusions || []);
  } catch (_) {}
}

function renderExclusions(list) {
  window._currentExclusions = list;
  const badge = document.getElementById("excl-count-badge");
  const display = document.getElementById("excl-list-display");
  if (badge) badge.textContent = `${list.length} entr${list.length === 1 ? "y" : "ies"}`;
  if (display) {
    display.innerHTML = list.length
      ? list.map(e => `<span class="excl-pill">${escapeHtml(e)}</span>`).join("")
      : '<span class="excl-empty">No exclusions set.</span>';
  }
}

function editExclusions() {
  document.getElementById("excl-read-view").style.display = "none";
  document.getElementById("excl-edit-view").style.display = "";
  document.getElementById("excl-textarea").value = (window._currentExclusions || []).join("\n");
}

function cancelEditExclusions() {
  document.getElementById("excl-edit-view").style.display = "none";
  document.getElementById("excl-read-view").style.display = "";
}

async function saveExclusions() {
  const slug = window._currentSlug;
  if (!slug) return;
  const raw = document.getElementById("excl-textarea").value;
  const list = raw.split("\n").map(s => s.trim()).filter(Boolean);
  try {
    const r = await fetch(`/api/projects/${encodeURIComponent(slug)}/exclusions`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ exclusions: list }),
    });
    if (r.ok) {
      renderExclusions(list);
      cancelEditExclusions();
    }
  } catch (_) {}
}

function renderRunHistory(runs, slug, container) {
  container.innerHTML = "";

  if (!runs.length) {
    container.innerHTML = `<div class="run-history-empty">No runs recorded yet.</div>`;
    return;
  }

  // Header row
  const header = document.createElement("div");
  header.className = "run-history-header";
  header.innerHTML = `
    <span>Run ID</span>
    <span>Date</span>
    <span>Status</span>
    <span>Duration</span>
    <span>Discovery</span>
    <span></span>`;
  container.appendChild(header);

  runs.forEach((run) => {
    const row = document.createElement("div");
    row.className = "run-row";

    const stats = run.summary_stats || {};
    const discoveryHtml = (run.status === "succeeded" || run.status === "success") && Object.keys(stats).length
      ? `<strong>${stats.subdomains || 0}</strong> sub · <strong>${stats.live_assets || 0}</strong> live · <strong>${stats.web_hosts || 0}</strong> web`
      : "<span>—</span>";

    const reportBtn = run.report_url
      ? `<a class="btn btn--ghost btn--sm" href="${escapeHtml(run.report_url)}" target="_blank" rel="noopener noreferrer">Report →</a>`
      : "";

    const graphUrl = `/projects/${encodeURIComponent(slug)}/graph?run=${encodeURIComponent(run.run_id || "")}`;
    const graphBtn = run.run_id
      ? `<a class="btn btn--ghost btn--sm" href="${escapeHtml(graphUrl)}" title="Attack Graph">◈ Graph</a>`
      : "";

    const logBtn = run.has_log
      ? `<button class="btn btn--ghost btn--sm" type="button" onclick="openRunLog('${escapeHtml(slug)}','${escapeHtml(run.run_id)}')">Logs</button>`
      : "";

    row.innerHTML = `
      <div class="run-row__id">${escapeHtml(run.run_id || "—")}</div>
      <div style="font-size:0.8rem;color:var(--text-2)">${formatDateTime(run.started_at || run.ran_at || "")}</div>
      <div>${statusBadgeHtml(run.status)}</div>
      <div class="run-row__stat">${run.duration_seconds ? formatDuration(run.duration_seconds) : "—"}</div>
      <div class="run-row__stat">${discoveryHtml}</div>
      <div class="run-row__actions">${reportBtn}${graphBtn}${logBtn}</div>`;

    container.appendChild(row);
  });
}

function openRunLog(slug, runId) {
  window.open(`/api/scans/${encodeURIComponent(slug)}/logs?run_id=${encodeURIComponent(runId)}`, "_blank");
}

/* ── Dashboard Setup ─────────────────────────────────────────────── */
function setupDashboard() {
  // New scan button
  const newBtn = el.newButton();
  if (newBtn) newBtn.addEventListener("click", () => openModal("create"));

  // Modal buttons
  const mc = el.modalCancel(); if (mc) mc.addEventListener("click", closeModal);
  const cx = el.modalClose();  if (cx) cx.addEventListener("click", closeModal);
  const bd = el.backdrop();
  if (bd) bd.addEventListener("click", () => {
    const m  = el.modal();
    const tm = el.targetsModal();
    if (m  && !m.classList.contains("hidden"))  closeModal();
    if (tm && !tm.classList.contains("hidden")) closeTargetsModal();
  });

  // Modal action buttons (Run Now / Queue / Schedule)
  el.modalActionButtons().forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const mode = e.currentTarget.dataset.runMode;
      if (mode) submitScan(mode);
    });
  });

  const tmc = el.targetsModalClose(); if (tmc) tmc.addEventListener("click", closeTargetsModal);
  const tmo = el.targetsModalOk();    if (tmo) tmo.addEventListener("click", closeTargetsModal);

  // Select all
  const sa = el.selectAll();
  if (sa) {
    sa.addEventListener("click", (e) => {
      if (!state.scans.length) return;
      if (e.currentTarget.checked) {
        state.scans.forEach(s => state.selected.add(s.slug));
      } else {
        state.selected.clear();
      }
      renderProjectList(state.scans);
      applyFilter();
    });
  }

  // Search
  const searchEl = el.searchInput();
  if (searchEl) {
    searchEl.addEventListener("input", (e) => {
      state.searchText = e.target.value;
      applyFilter();
    });
  }

  // Filter tabs
  document.querySelectorAll(".filter-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("is-active"));
      tab.classList.add("is-active");
      state.activeFilter = tab.dataset.filter || "all";
      applyFilter();
    });
  });

  // Bulk bar
  const bdel = el.bulkDeleteBtn();
  if (bdel) bdel.addEventListener("click", () => deleteScans([...state.selected]));
  const bdes = el.bulkDeselectBtn();
  if (bdes) bdes.addEventListener("click", () => {
    state.selected.clear();
    renderProjectList(state.scans);
    applyFilter();
  });

  // Keyboard
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeContextMenu();
      const ap = document.getElementById("api-panel");
      if (ap && !ap.classList.contains("hidden")) { closeApiPanel(); return; }
      const lp = document.getElementById('log-panel');
      if (lp && !lp.classList.contains("hidden")) { closeLogPanel(); return; }
      const m  = el.modal();
      const tm = el.targetsModal();
      if (m  && !m.classList.contains("hidden"))  closeModal();
      if (tm && !tm.classList.contains("hidden")) closeTargetsModal();
    }
  });

  // Theme
  const tt = el.themeToggle();
  if (tt) tt.addEventListener("click", toggleTheme);

  // API Keys panel
  const apiBtn = document.getElementById("api-settings-btn");
  if (apiBtn) apiBtn.addEventListener("click", openApiPanel);
  const apiClose = document.getElementById("api-panel-close");
  if (apiClose) apiClose.addEventListener("click", closeApiPanel);
  const apiBd = document.getElementById("api-panel-backdrop");
  if (apiBd) apiBd.addEventListener("click", closeApiPanel);
}

/* ── DOMContentLoaded ────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", async () => {
  setupTheme();

  // Log panel close bindings (present on dashboard)
  const logClose = document.getElementById('log-panel-close');
  if (logClose) logClose.addEventListener('click', closeLogPanel);
  const logBackdrop = document.getElementById('log-backdrop');
  if (logBackdrop) logBackdrop.addEventListener('click', closeLogPanel);

  // Detect page type
  if (document.getElementById("run-history-list")) {
    // ── Project Detail Page ──
    const themeToggle = document.getElementById("theme-toggle");
    if (themeToggle) themeToggle.addEventListener("click", toggleTheme);
    const match = location.pathname.match(/\/projects\/([^/]+)/);
    if (match) await loadProjectDetail(match[1]);
  } else {
    // ── Dashboard ──
    setupDashboard();
    await loadScans();
    startPolling();
  }
});
