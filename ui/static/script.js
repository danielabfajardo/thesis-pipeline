/* ============================================================
   Thesis pipeline — neutral interview UI
   Vanilla JS only. No external libraries. Works fully offline.
   ============================================================ */

(function () {
  "use strict";

  const projectId = window.PIPELINE_CONFIG.projectId;
  const rotation = window.PIPELINE_CONFIG.rotation; // { c1: "List 1", c2: "List 3", ... }

  // Invert: "List 1" -> "c1"
  const labelToCondition = {};
  Object.entries(rotation).forEach(([cond, label]) => { labelToCondition[label] = cond; });

  let rankingsData = null;

  // ---- SVG icons ----
  const ICONS = {
    BUG: `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 1a3 3 0 0 0-3 3v.5H3.5a.5.5 0 0 0 0 1H5v1H3.5a.5.5 0 0 0 0 1H5C5 9.657 6.343 11 8 11s3-1.343 3-3.5h1.5a.5.5 0 0 0 0-1H11v-1h1.5a.5.5 0 0 0 0-1H11V4a3 3 0 0 0-3-3Z" fill="#d4333f"/>
      <rect x="6.5" y="11" width="3" height="1" rx="0.5" fill="#d4333f"/>
      <rect x="7" y="12" width="2" height="2" rx="1" fill="#d4333f"/>
    </svg>`,
    VULNERABILITY: `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 1L2 4v4c0 3.314 2.686 6 6 6s6-2.686 6-6V4L8 1Z" stroke="#ed7d20" stroke-width="1.5" fill="none"/>
      <path d="M8 5v3M8 10v.5" stroke="#ed7d20" stroke-width="1.5" stroke-linecap="round"/>
    </svg>`,
    CODE_SMELL: `<svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2Z" stroke="#6b7280" stroke-width="1.5" fill="none"/>
      <path d="M5 8c0-1.657 1.343-3 3-3" stroke="#6b7280" stroke-width="1.5" stroke-linecap="round"/>
      <circle cx="8" cy="11" r="0.75" fill="#6b7280"/>
    </svg>`,
  };

  function severityDot(severity) {
    const cls = "sev-" + (severity || "INFO").toUpperCase();
    return `<span class="sev-dot ${cls}" title="${severity}"></span>`;
  }

  function typeIcon(type) {
    const svg = ICONS[type] || ICONS["CODE_SMELL"];
    return `<span class="type-icon" title="${type}">${svg}</span>`;
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

  function buildExpandRow(issue, hasReasoning) {
    const reasoning = hasReasoning && issue.reasoning
      ? `<div class="expand-section expand-reasoning">
           <span class="expand-label">Analysis notes:</span>
           <span class="expand-value">${escHtml(issue.reasoning)}</span>
         </div>`
      : "";

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
          <span class="metric-chip">Coverage: <strong>${issue.file_coverage}%</strong></span>
          <span class="metric-chip">Bugs in file: <strong>${issue.file_bugs}</strong></span>
        </div>
      </div>`;
  }

  function escHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderTable(condition, issues) {
    const tbody = document.getElementById("tbody-" + condition);
    const table = document.getElementById("table-" + condition);
    const loading = document.getElementById("loading-" + condition);
    const countEl = document.getElementById("count-" + condition);

    if (countEl) countEl.textContent = issues.length;

    tbody.innerHTML = "";

    const hasReasoning = condition !== "c1";

    issues.forEach((issue) => {
      const tr = document.createElement("tr");
      tr.dataset.issueKey = issue.issue_key;

      tr.innerHTML = `
        <td class="col-severity">${severityDot(issue.severity)}</td>
        <td class="col-type">${typeIcon(issue.type)}</td>
        <td class="col-message">${escHtml(truncate(issue.message, 120))}</td>
        <td class="col-file" title="${escHtml(issue.file_path)}">${escHtml(issue.file)}</td>
        <td class="col-line">${issue.line !== null ? issue.line : ""}</td>
        <td class="col-effort">${escHtml(issue.effort)}</td>
        <td class="col-age">${ageFmt(issue.age_days)}</td>
      `;

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
        // Render all tabs so switching is instant
        ["c1", "c2", "c3"].forEach(function (cond) {
          if (rankingsData[cond]) {
            renderTable(cond, rankingsData[cond]);
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

  document.addEventListener("DOMContentLoaded", function () {
    initTabs();
    if (projectId) loadData();
  });
})();
