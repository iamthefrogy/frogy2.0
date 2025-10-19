const domainPattern = /^[A-Za-z0-9.-]+$/;

const state = {
  scans: [],
  selected: new Set(),
  pollTimer: null,
  pollInterval: 5000,
  modalMode: "create",
  editingSlug: null,
  flashTimeout: null,
};

const elements = {
  tableBody: document.getElementById("scan-table-body"),
  selectAll: document.getElementById("select-all"),
  newButton: document.getElementById("new-scan-btn"),
  modifyButton: document.getElementById("modify-scan-btn"),
  deleteButton: document.getElementById("delete-scan-btn"),
  flash: document.getElementById("flash-message"),
  themeToggle: document.getElementById("theme-toggle"),
  modal: document.getElementById("scan-modal"),
  backdrop: document.getElementById("modal-backdrop"),
  modalTitle: document.getElementById("modal-title"),
  modalForm: document.getElementById("modal-form"),
  modalName: document.getElementById("modal-project-name"),
  modalTargets: document.getElementById("modal-targets"),
  modalScheduleField: document.getElementById("modal-schedule-field"),
  modalSchedule: document.getElementById("modal-schedule"),
  modalFeedback: document.getElementById("modal-feedback"),
  modalClose: document.getElementById("modal-close"),
  modalCancel: document.getElementById("modal-cancel"),
  modalActionButtons: document.querySelectorAll("#modal-form [data-run-mode]"),
  targetsModal: document.getElementById("targets-modal"),
  targetsModalClose: document.getElementById("targets-modal-close"),
  targetsModalOk: document.getElementById("targets-modal-ok"),
  targetsList: document.getElementById("targets-list"),
  targetsCount: document.getElementById("targets-count"),
};

function refreshFlash(message, type = "info") {
  if (!elements.flash) return;
  elements.flash.textContent = message || "";
  elements.flash.classList.remove("error", "success");
  if (!message) return;
  if (type === "error") {
    elements.flash.classList.add("error");
  } else if (type === "success") {
    elements.flash.classList.add("success");
  }
  clearTimeout(state.flashTimeout);
  state.flashTimeout = window.setTimeout(() => {
    elements.flash.textContent = "";
    elements.flash.classList.remove("error", "success");
  }, 4000);
}

function setModalFeedback(message, isError = false) {
  elements.modalFeedback.textContent = message || "";
  elements.modalFeedback.classList.toggle("error", Boolean(isError));
}

function syncSelection() {
  const available = new Set(state.scans.map((scan) => scan.slug));
  [...state.selected].forEach((slug) => {
    if (!available.has(slug)) {
      state.selected.delete(slug);
    }
  });
  const size = state.selected.size;
  elements.modifyButton.disabled = size !== 1;
  elements.deleteButton.disabled = size === 0;
  if (elements.selectAll) {
    if (!state.scans.length) {
      elements.selectAll.checked = false;
      elements.selectAll.indeterminate = false;
    } else if (size === state.scans.length) {
      elements.selectAll.checked = true;
      elements.selectAll.indeterminate = false;
    } else if (size === 0) {
      elements.selectAll.checked = false;
      elements.selectAll.indeterminate = false;
    } else {
      elements.selectAll.checked = false;
      elements.selectAll.indeterminate = true;
    }
  }
}

function toggleSelect(slug, checked) {
  if (checked) {
    state.selected.add(slug);
  } else {
    state.selected.delete(slug);
  }
  syncSelection();
  elements.tableBody.querySelectorAll("tr").forEach((row) => {
    row.classList.toggle("selected", state.selected.has(row.dataset.slug));
    const checkbox = row.querySelector('input[type="checkbox"]');
    if (checkbox) checkbox.checked = state.selected.has(row.dataset.slug);
  });
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;
  return dt.toISOString().replace("T", " ");
}

function statusClass(status) {
  switch (status) {
    case "succeeded":
    case "success":
      return "status-succeeded";
    case "failed":
      return "status-failed";
    case "running":
      return "status-running";
    case "queued":
      return "status-queued";
    case "scheduled":
      return "status-scheduled";
    default:
      return "status-never";
  }
}

function renderTable(scans) {
  elements.tableBody.innerHTML = "";
  if (!scans.length) {
    const row = document.createElement("tr");
    row.className = "empty";
    const cell = document.createElement("td");
    cell.colSpan = 10;
    cell.innerHTML = "No scans yet. Start with <strong>New Scan</strong>.";
    row.appendChild(cell);
    elements.tableBody.appendChild(row);
    syncSelection();
    return;
  }

  scans.forEach((scan) => {
    const row = document.createElement("tr");
    row.dataset.slug = scan.slug;
    if (state.selected.has(scan.slug)) row.classList.add("selected");

    const selectCell = document.createElement("td");
    selectCell.className = "select-col";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selected.has(scan.slug);
    checkbox.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleSelect(scan.slug, event.currentTarget.checked);
    });
    selectCell.appendChild(checkbox);
    row.appendChild(selectCell);

    const indexCell = document.createElement("td");
    indexCell.textContent = scan.index ?? "";
    row.appendChild(indexCell);

    const projectCell = document.createElement("td");
    const projectName = document.createElement("div");
    projectName.className = "project-name";
    projectName.textContent = scan.name;
    projectCell.appendChild(projectName);
    if (scan.queue_position || scan.scheduled_for) {
      const sub = document.createElement("p");
      sub.className = "project-sub";
      if (scan.queue_position) {
        sub.textContent = `Queue position: ${scan.queue_position}`;
      } else if (scan.scheduled_for) {
        sub.textContent = `Scheduled: ${scan.scheduled_for}`;
      }
      projectCell.appendChild(sub);
    }
    row.appendChild(projectCell);

    const targetsCell = document.createElement("td");
    const targetsContent = document.createElement("div");
    targetsContent.className = "targets-content";
    const count = document.createElement("span");
    count.className = "targets-count";
    count.textContent = `${scan.targets_count || 0}`;
    const viewButton = document.createElement("button");
    viewButton.type = "button";
    viewButton.className = "targets-button";
    viewButton.textContent = "View";
    viewButton.title = "View target domains";
    viewButton.addEventListener("click", (event) => {
      event.stopPropagation();
      openTargetsModal(scan);
    });
    targetsContent.append(count, viewButton);
    targetsCell.appendChild(targetsContent);
    row.appendChild(targetsCell);

    const progressCell = document.createElement("td");
    progressCell.className = "progress-col";
    const progressWrapper = document.createElement("div");
    progressWrapper.className = "progress-wrapper";
    const progressBar = document.createElement("div");
    progressBar.className = "progress-bar";
    const progressFill = document.createElement("div");
    progressFill.className = "progress-fill";
    const percent = Math.max(0, Math.min(100, scan.progress?.percent ?? 0));
    progressFill.style.width = `${percent}%`;
    progressBar.appendChild(progressFill);
    const progressMeta = document.createElement("div");
    progressMeta.className = "progress-meta";
    const stepText =
      typeof scan.progress?.step === "number" && typeof scan.progress?.total === "number"
        ? `Step ${scan.progress.step}/${scan.progress.total}`
        : "Progress";
    const label = scan.progress?.label || stepText;
    const labelSpan = document.createElement("span");
    labelSpan.textContent = label;
    const percentSpan = document.createElement("span");
    percentSpan.textContent = `${percent}%`;
    progressMeta.append(labelSpan, percentSpan);
    progressWrapper.append(progressBar, progressMeta);
    progressCell.appendChild(progressWrapper);
    row.appendChild(progressCell);

    const lastRunCell = document.createElement("td");
    lastRunCell.textContent = formatDateTime(scan.ran_at);
    row.appendChild(lastRunCell);

    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `status-badge ${statusClass(scan.status)}`;
    badge.textContent = (scan.status || "unknown").replace(/^\w/, (c) => c.toUpperCase());
    if (scan.status_message) {
      badge.title = scan.status_message;
    }
    statusCell.appendChild(badge);
    row.appendChild(statusCell);

    const resultsCell = document.createElement("td");
    const resultsButton = document.createElement("button");
    resultsButton.type = "button";
    resultsButton.className = "results-button";
    resultsButton.textContent = "Open Report";
    const hasArtifacts = typeof scan.run_id === "string" && scan.run_id.startsWith("run-");

    if (scan.report && hasArtifacts) {
      resultsButton.addEventListener("click", (event) => {
        event.stopPropagation();
        window.open(scan.report, "_blank", "noopener,noreferrer");
      });
    } else {
      resultsButton.disabled = true;
      resultsButton.textContent = scan.status === "running" ? "In Progress…" : "Unavailable";
    }
    resultsCell.appendChild(resultsButton);
    row.appendChild(resultsCell);

    const downloadsCell = document.createElement("td");
    downloadsCell.className = "download-col";
    const downloadsContent = document.createElement("div");
    downloadsContent.className = "downloads-content";
    const jsonDownload = document.createElement("button");
    jsonDownload.type = "button";
    jsonDownload.className = "download-button";
    jsonDownload.textContent = "JSON";
    jsonDownload.title = "Download datasets as JSON";
    const csvDownload = document.createElement("button");
    csvDownload.type = "button";
    csvDownload.className = "download-button";
    csvDownload.textContent = "CSV";
    csvDownload.title = "Download application endpoints CSV";
    if (hasArtifacts) {
      const jsonUrl = `/projects/${encodeURIComponent(scan.slug)}/runs/${encodeURIComponent(scan.run_id)}/download/json`;
      const csvUrl = `/projects/${encodeURIComponent(scan.slug)}/runs/${encodeURIComponent(scan.run_id)}/download/csv`;
      jsonDownload.addEventListener("click", (event) => {
        event.stopPropagation();
        triggerFileDownload(jsonUrl);
      });
      csvDownload.addEventListener("click", (event) => {
        event.stopPropagation();
        downloadCsvViaReport(scan, csvUrl);
      });
    } else {
      jsonDownload.disabled = true;
      csvDownload.disabled = true;
    }
    downloadsContent.append(jsonDownload, csvDownload);
    downloadsCell.appendChild(downloadsContent);
    row.appendChild(downloadsCell);

    const actionsCell = document.createElement("td");
    actionsCell.className = "actions-col";
    const actionsContent = document.createElement("div");
    actionsContent.className = "actions-content";
    const isActive = Boolean(scan.is_running) || Boolean(scan.is_queued) || Boolean(scan.is_scheduled);
    const rescanButton = createIconButton(isActive ? "⏹" : "🔄", isActive ? "Stop" : "Rescan", () => {
      if (isActive) {
        cancelScan(scan);
      } else {
        rescanScan(scan);
      }
    });
    if (isActive) {
      rescanButton.classList.add("icon-button--stop");
    }
    const editButton = createIconButton("✏️", "Modify", () => openModal("edit", scan));
    const deleteButton = createIconButton("🗑️", "Delete", () => deleteScans([scan.slug]));
    deleteButton.classList.add("danger");
    if (isActive) {
      editButton.disabled = true;
      deleteButton.disabled = true;
    }
    actionsContent.append(rescanButton, editButton, deleteButton);
    actionsCell.appendChild(actionsContent);
    row.appendChild(actionsCell);

    row.addEventListener("click", () => {
      const checkboxEl = row.querySelector('input[type="checkbox"]');
      const willSelect = !state.selected.has(scan.slug);
      toggleSelect(scan.slug, willSelect);
      if (checkboxEl) checkboxEl.checked = willSelect;
    });

    elements.tableBody.appendChild(row);
  });

  syncSelection();
}

function createIconButton(symbol, title, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-button";
  button.textContent = symbol;
  button.title = title;
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    handler();
  });
  return button;
}

async function loadScans() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) {
      throw new Error(`Request failed with status ${response.status}`);
    }
    const data = await response.json();
    state.scans = data.scans || [];
    renderTable(state.scans);
  } catch (error) {
    refreshFlash(error.message, "error");
  }
}

function validateTargets(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) return { error: "Add at least one primary domain." };
  for (const line of lines) {
    if (!domainPattern.test(line)) {
      return { error: `Invalid domain: ${line}` };
    }
  }
  return { lines };
}

function openModal(mode, scan = null) {
  state.modalMode = mode;
  state.editingSlug = scan?.slug || null;
  elements.modalTitle.textContent = mode === "edit" ? "Modify Scan" : "New Scan";
  elements.modalName.value = scan?.name || "";
  elements.modalTargets.value = scan?.targets || "";
  elements.modalSchedule.value = "";
  elements.modalScheduleField.classList.add("hidden");
  setModalFeedback("");
  elements.modal.classList.remove("hidden");
  elements.modal.classList.add("show");
  elements.backdrop.classList.add("show");
  window.requestAnimationFrame(() => elements.modalName.focus());
}

function closeModal() {
  elements.modal.classList.remove("show");
  elements.backdrop.classList.remove("show");
  window.setTimeout(() => {
    elements.modal.classList.add("hidden");
  }, 200);
  setModalFeedback("");
}

function openTargetsModal(scan) {
  const targets = (scan.targets || "").split(/\r?\n/).filter(Boolean);
  elements.targetsCount.textContent = targets.length;
  elements.targetsList.innerHTML = "";
  targets.forEach((target) => {
    const li = document.createElement("li");
    li.textContent = target;
    elements.targetsList.appendChild(li);
  });
  elements.targetsModal.classList.remove("hidden");
  elements.targetsModal.classList.add("show");
  elements.backdrop.classList.add("show");
}

function closeTargetsModal() {
  elements.targetsModal.classList.remove("show");
  elements.backdrop.classList.remove("show");
  window.setTimeout(() => {
    elements.targetsModal.classList.add("hidden");
  }, 200);
}

function toggleModalBusy(isBusy) {
  elements.modalActionButtons.forEach((button) => {
    button.disabled = isBusy;
  });
  elements.modalCancel.disabled = isBusy;
  elements.modalClose.disabled = isBusy;
}

function toIsoString(value) {
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) throw new Error("Please provide a valid date & time.");
  return dt.toISOString();
}

async function submitScan(mode) {
  const projectName = elements.modalName.value.trim();
  const targetsText = elements.modalTargets.value.trim();
  if (!projectName) {
    setModalFeedback("Company name is required.", true);
    elements.modalName.focus();
    return;
  }
  const validation = validateTargets(targetsText);
  if (validation.error) {
    setModalFeedback(validation.error, true);
    elements.modalTargets.focus();
    return;
  }

  let scheduledFor = "";
  if (mode === "schedule") {
    if (elements.modalScheduleField.classList.contains("hidden")) {
      elements.modalScheduleField.classList.remove("hidden");
      setModalFeedback("Pick a future start date & time.", true);
      elements.modalSchedule.focus();
      return;
    }
    if (!elements.modalSchedule.value) {
      setModalFeedback("Pick a future start date & time.", true);
      elements.modalSchedule.focus();
      return;
    }
    const iso = toIsoString(elements.modalSchedule.value);
    scheduledFor = iso;
  }

  const payload = {
    project_name: projectName,
    targets: targetsText,
    start_mode: mode,
  };
  if (scheduledFor) payload.scheduled_for = scheduledFor;

  const slug = state.modalMode === "edit" ? state.editingSlug : null;
  const endpoint = slug ? `/api/scans/${encodeURIComponent(slug)}` : "/api/scans";
  const method = slug ? "PUT" : "POST";

  try {
    setModalFeedback("Submitting…");
    toggleModalBusy(true);
    const response = await fetch(endpoint, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed with status ${response.status}`);
    closeModal();
    refreshFlash(body.message || "Scan saved.", "success");
    await loadScans();
    if (body.slug) {
      state.selected = new Set([body.slug]);
    }
  } catch (error) {
    setModalFeedback(error.message, true);
  } finally {
    toggleModalBusy(false);
    syncSelection();
  }
}

async function rescanScan(scan) {
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(scan.slug)}/rescan`, {
      method: "POST",
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed with status ${response.status}`);
    refreshFlash(body.message || "Rescan started.", "success");
    await loadScans();
  } catch (error) {
    refreshFlash(error.message, "error");
  }
}

async function cancelScan(scan) {
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(scan.slug)}/cancel`, {
      method: "POST",
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed with status ${response.status}`);
    refreshFlash(body.message || "Cancellation requested.", "success");
    await loadScans();
  } catch (error) {
    refreshFlash(error.message, "error");
  }
}

async function deleteScans(slugs) {
  if (!slugs.length) return;
  const names = slugs
    .map((slug) => state.scans.find((scan) => scan.slug === slug)?.name || slug)
    .join(", ");
  const confirmed = window.confirm(`Delete ${slugs.length > 1 ? "these scans" : "scan"} (${names}) and all artifacts?`);
  if (!confirmed) return;

  try {
    const response = await fetch("/api/scans/bulk-delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slugs }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed with status ${response.status}`);
    refreshFlash(body.message || "Deletion complete.", "success");
    slugs.forEach((slug) => state.selected.delete(slug));
    await loadScans();
  } catch (error) {
    refreshFlash(error.message, "error");
  }
}

function handleRunAction(event) {
  const mode = event.currentTarget.dataset.runMode;
  if (!mode) return;
  submitScan(mode);
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = window.setInterval(loadScans, state.pollInterval);
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  elements.themeToggle.textContent = theme === "light" ? "🌞" : "🌙";
  localStorage.setItem("frogyTheme", theme);
}

function triggerFileDownload(url) {
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.setAttribute("download", "");
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
}

function downloadCsvViaReport(scan, fallbackUrl) {
  if (!scan.report) {
    triggerFileDownload(fallbackUrl);
    return;
  }

  const iframe = document.createElement("iframe");
  iframe.style.position = "fixed";
  iframe.style.left = "-9999px";
  iframe.style.width = "0";
  iframe.style.height = "0";
  iframe.setAttribute("aria-hidden", "true");
  iframe.src = `${scan.report}?ts=${Date.now()}`;

  const cleanup = () => {
    iframe.removeEventListener("load", onLoad);
    if (iframe.parentNode) {
      iframe.parentNode.removeChild(iframe);
    }
  };

  const onLoad = () => {
    try {
      const win = iframe.contentWindow;
      if (!win || typeof win.exportAllTableRowsToCSV !== "function") {
        throw new Error("Unable to access report exporter.");
      }

      const attemptExport = (retries = 12) => {
        try {
          const reportBody = win.document.getElementById("report-table-body");
          const rowCount = reportBody ? reportBody.querySelectorAll("tr").length : 0;
          if (!rowCount) {
            if (retries > 0) {
              setTimeout(() => attemptExport(retries - 1), 250);
              return;
            }
            throw new Error("Report data not ready yet.");
          }
          const filename = `${scan.slug}-${scan.run_id}-report.csv`;
          win.exportAllTableRowsToCSV(filename);
          setTimeout(cleanup, 2000);
        } catch (error) {
          if (retries > 0) {
            setTimeout(() => attemptExport(retries - 1), 250);
          } else {
            cleanup();
            refreshFlash(error.message || "Unable to export CSV from report.", "error");
          }
        }
      };

      attemptExport();
    } catch (error) {
      cleanup();
      refreshFlash(error.message || "Unable to export CSV.", "error");
    }
  };

  iframe.addEventListener("load", onLoad);
  iframe.addEventListener("error", () => {
    cleanup();
    refreshFlash("Failed to load report for CSV export.", "error");
  });
  document.body.appendChild(iframe);
}

function toggleTheme() {
  const current = document.body.dataset.theme || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

function setupTheme() {
  const stored = localStorage.getItem("frogyTheme");
  if (stored === "light" || stored === "dark") {
    applyTheme(stored);
  } else {
    const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
    applyTheme(prefersLight ? "light" : "dark");
  }
}

function setupEventHandlers() {
  elements.newButton.addEventListener("click", () => openModal("create"));
  elements.modifyButton.addEventListener("click", () => {
    if (state.selected.size !== 1) return;
    const slug = [...state.selected][0];
    const scan = state.scans.find((item) => item.slug === slug);
    if (scan) openModal("edit", scan);
  });
  elements.deleteButton.addEventListener("click", () => {
    deleteScans([...state.selected]);
  });

  elements.modalCancel.addEventListener("click", closeModal);
  elements.modalClose.addEventListener("click", closeModal);
  elements.backdrop.addEventListener("click", () => {
    if (!elements.modal.classList.contains("hidden")) closeModal();
    if (!elements.targetsModal.classList.contains("hidden")) closeTargetsModal();
  });

  elements.modalActionButtons.forEach((button) => {
    button.addEventListener("click", handleRunAction);
  });

  elements.targetsModalClose.addEventListener("click", closeTargetsModal);
  elements.targetsModalOk.addEventListener("click", closeTargetsModal);

  if (elements.selectAll) {
    elements.selectAll.addEventListener("click", (event) => {
      if (!state.scans.length) return;
      if (event.currentTarget.checked) {
        state.selected = new Set(state.scans.map((scan) => scan.slug));
      } else {
        state.selected.clear();
      }
      renderTable(state.scans);
    });
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (!elements.modal.classList.contains("hidden")) closeModal();
      if (!elements.targetsModal.classList.contains("hidden")) closeTargetsModal();
    }
  });

  elements.themeToggle.addEventListener("click", toggleTheme);
}

document.addEventListener("DOMContentLoaded", async () => {
  setupTheme();
  setupEventHandlers();
  await loadScans();
  startPolling();
});
