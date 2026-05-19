/* ============================================================
   Thesis pipeline — neutral interview UI
   Vanilla JS only. No external libraries. Works fully offline.
   ============================================================ */

(function () {
  "use strict";

  const projectId = window.PIPELINE_CONFIG.projectId;
  const rotation = window.PIPELINE_CONFIG.rotation; // { c1: "List 1", c2: "List 3", ... }

  let rankingsData = null;

  // ---- Filter state ----
  let filterSeverity = "";
  let filterQuality = "";

  // ---- Severity labels ----
  const SEV_LABELS = {
    BLOCKER: "Blocker",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
    INFO: "Info",
  };

  // ---- Quality badge labels ----
  const QUALITY_LABELS = {
    SECURITY: "Security",
    RELIABILITY: "Reliability",
    MAINTAINABILITY: "Maint.",
  };

  function severityLabel(severity) {
    const key = (severity || "INFO").toUpperCase();
    const label = SEV_LABELS[key] || key;
    return `<span class="sev-label sev-${key}">${label}</span>`;
  }

  function qualityBadge(quality) {
    if (!quality) return "";
    const key = quality.toUpperCase();
    const label = QUALITY_LABELS[key] || quality;
    return `<span class="quality-badge quality-${key}">${label}</span>`;
  }

  function ageFmt(days) {
    if (!days && days !== 0) return "";
    if (days < 1) return "today";
    if (days < 30) return days + "d";
    if (days < 365) return Math.floor(days / 30) + "mo";
    return Math.floor(days / 365) + "yr";
  }

  function truncate(str, n) {
    if (!str) return "";
    return str.length > n ? str.slice(0, n) + "…" : str;
  }

  function escHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function ratingBadge(val) {
    if (!val) return "—";
    const colors = { A: "#047857", B: "#15803d", C: "#b45309", D: "#c2410c", E: "#b91c1c" };
    const color = colors[val] || "#6b7280";
    return `<strong style="color:${color}">${val}</strong>`;
  }

  function buildExpandRow(issue, hasReasoning) {
    const reasoning = hasReasoning && issue.reasoning
      ? `<div class="expand-section expand-reasoning">
           <span class="expand-label">Analysis notes:</span>
           <span class="expand-value">${escHtml(issue.reasoning)}</span>
         </div>`
      : "";

    const coverageStr = issue.file_coverage > 0
      ? issue.file_coverage + "%"
      : "No data";

    const techDebtMins = issue.file_sqale_index || 0;
    const techDebtStr = techDebtMins >= 60
      ? Math.round(techDebtMins / 60) + "h " + (techDebtMins % 60) + "min"
      : techDebtMins + "min";

    return `
      <div class="expand-content">
        <div class="expand-section">
          <span class="expand-label">Full path</span>
          <span class="expand-value">${escHtml(issue.file_path)}</span>
        </div>
        <div class="expand-section">
          <span class="expand-label">Rule</span>
          <span class="expand-value">${escHtml(issue.rule)}</span>
        </div>
        <div class="expand-section">
          <span class="expand-label">Line</span>
          <span class="expand-value">${issue.line !== null ? issue.line : "—"}</span>
        </div>
        <div class="expand-section">
          <span class="expand-label">Effort</span>
          <span class="expand-value">${escHtml(issue.effort) || "—"}</span>
        </div>
        ${reasoning}
        <div class="expand-metrics">
          <span class="metric-chip">Complexity: <strong>${issue.file_complexity}</strong></span>
          <span class="metric-chip">Cognitive complexity: <strong>${issue.file_cognitive_complexity}</strong></span>
          <span class="metric-chip">Coverage: <strong>${coverageStr}</strong></span>
          <span class="metric-chip">Violations in file: <strong>${issue.file_violations}</strong></span>
          <span class="metric-chip">Tech debt: <strong>${techDebtStr}</strong></span>
          <span class="metric-chip">Duplication: <strong>${issue.file_duplicated_lines_density}%</strong></span>
          <span class="metric-chip">Reliability: <strong>${ratingBadge(issue.file_reliability_rating)}</strong></span>
          <span class="metric-chip">Security: <strong>${ratingBadge(issue.file_security_rating)}</strong></span>
        </div>
      </div>`;
  }

  // ---- Filtering ----
  function applyFilters(issues) {
    return issues.filter(function (issue) {
      if (filterSeverity && issue.display_severity !== filterSeverity) return false;
      if (filterQuality && issue.display_quality !== filterQuality) return false;
      return true;
    });
  }

  function renderAll() {
    if (!rankingsData) return;
    ["c1", "c2", "c3"].forEach(function (cond) {
      if (rankingsData[cond]) {
        renderTable(cond, applyFilters(rankingsData[cond]));
      }
    });
    updateFilterUI();
  }

  function updateFilterUI() {
    const hasFilter = filterSeverity !== "" || filterQuality !== "";
    const resetBtn = document.getElementById("filter-reset");
    if (resetBtn) resetBtn.style.display = hasFilter ? "" : "none";

    const sevEl = document.getElementById("filter-severity");
    const qualEl = document.getElementById("filter-quality");
    if (sevEl) sevEl.classList.toggle("active", filterSeverity !== "");
    if (qualEl) qualEl.classList.toggle("active", filterQuality !== "");
  }

  function renderTable(condition, issues) {
    const tbody = document.getElementById("tbody-" + condition);
    const table = document.getElementById("table-" + condition);
    const loading = document.getElementById("loading-" + condition);
    const countEl = document.getElementById("count-" + condition);

    if (countEl) {
      const total = rankingsData && rankingsData[condition]
        ? rankingsData[condition].length : issues.length;
      countEl.textContent = (issues.length < total)
        ? issues.length + "/" + total
        : issues.length;
    }

    tbody.innerHTML = "";

    if (issues.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 7;
      td.style.cssText = "padding:24px;text-align:center;color:#6b7280;";
      td.textContent = "No issues match the current filters.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      if (loading) loading.style.display = "none";
      table.style.display = "table";
      return;
    }

    const hasReasoning = condition !== "c1";

    issues.forEach(function (issue) {
      const tr = document.createElement("tr");
      tr.dataset.issueKey = issue.issue_key;

      tr.innerHTML =
        '<td class="col-severity">' + severityLabel(issue.display_severity) + "</td>" +
        '<td class="col-quality">' + qualityBadge(issue.display_quality) + "</td>" +
        '<td class="col-message">' + escHtml(truncate(issue.message, 120)) + "</td>" +
        '<td class="col-file" title="' + escHtml(issue.file_path) + '">' + escHtml(issue.file) + "</td>" +
        '<td class="col-line">' + (issue.line !== null ? issue.line : "") + "</td>" +
        '<td class="col-effort">' + escHtml(issue.effort) + "</td>" +
        '<td class="col-age">' + ageFmt(issue.age_days) + "</td>";

      const expandTr = document.createElement("tr");
      expandTr.className = "expand-row";
      expandTr.style.display = "none";
      const expandTd = document.createElement("td");
      expandTd.colSpan = 7;
      expandTd.innerHTML = buildExpandRow(issue, hasReasoning);
      expandTr.appendChild(expandTd);

      tr.addEventListener("click", function () {
        const isOpen = expandTr.style.display !== "none";
        expandTr.style.display = isOpen ? "none" : "table-row";
        tr.classList.toggle("expanded", !isOpen);
      });

      tbody.appendChild(tr);
      tbody.appendChild(expandTr);
    });

    if (loading) loading.style.display = "none";
    table.style.display = "table";
  }

  function loadData() {
    const url = "/api/rankings/" + encodeURIComponent(projectId);
    fetch(url)
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (data) {
        rankingsData = data.rankings;
        ["c1", "c2", "c3"].forEach(function (cond) {
          if (rankingsData[cond] && rankingsData[cond].length > 0) {
            renderTable(cond, applyFilters(rankingsData[cond]));
          } else {
            const loading = document.getElementById("loading-" + cond);
            if (loading) loading.textContent = "No data available.";
          }
        });
      })
      .catch(function (err) {
        console.error("Failed to load rankings:", err);
        ["c1", "c2", "c3"].forEach(function (cond) {
          const loading = document.getElementById("loading-" + cond);
          if (loading) loading.textContent = "Error loading data.";
        });
      });
  }

  // ---- Filter controls ----
  function initFilters() {
    const sevEl = document.getElementById("filter-severity");
    const qualEl = document.getElementById("filter-quality");
    const resetBtn = document.getElementById("filter-reset");

    if (sevEl) {
      sevEl.addEventListener("change", function () {
        filterSeverity = this.value;
        renderAll();
      });
    }
    if (qualEl) {
      qualEl.addEventListener("change", function () {
        filterQuality = this.value;
        renderAll();
      });
    }
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        filterSeverity = "";
        filterQuality = "";
        if (sevEl) sevEl.value = "";
        if (qualEl) qualEl.value = "";
        renderAll();
      });
    }
  }

  // ---- Tab switching ----
  function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabPanels = document.querySelectorAll(".tab-panel");

    tabBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        tabBtns.forEach(function (b) {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        tabPanels.forEach(function (p) { p.classList.remove("active"); });

        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");
        const target = document.getElementById("panel-" + btn.dataset.condition);
        if (target) target.classList.add("active");
      });
    });
  }

  // ---- Latin Square selector ----
  // Changing the dropdown navigates to ?order=XXX. Server re-renders with the new
  // condition→list mapping; rankings data is reloaded under the new rotation.
  function initLatinSquare() {
    const sel = document.getElementById("latin-square-select");
    if (!sel) return;
    sel.addEventListener("change", function () {
      const order = this.value;
      const url = new URL(window.location.href);
      url.searchParams.set("order", order);
      window.location.href = url.toString();
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTabs();
    initFilters();
    initLatinSquare();
    if (projectId) loadData();
  });
})();
