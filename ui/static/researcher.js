/* ============================================================
   Thesis pipeline — researcher transparency view
   Loads each pipeline stage from /api/researcher/* endpoints
   and renders inline panels. Vanilla JS, no build step.
   ============================================================ */

(function () {
  "use strict";

  const projectId = window.RESEARCHER_CONFIG.projectId;

  // ---------------- generic helpers ----------------
  function escHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmt(v) {
    if (v === null || v === undefined || v === "") return "—";
    if (typeof v === "boolean") return v ? "✓" : "✗";
    return v;
  }

  function api(path) {
    return fetch(path).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status + " " + path);
      return r.json();
    });
  }

  function setBody(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  function fail(id, err) {
    setBody(id, '<div class="stage-error">Failed to load: ' + escHtml(err.message || err) + '</div>');
  }

  // Render a list-of-objects as an HTML table. Pass column hints if you want a
  // particular order; otherwise the first row's keys are used.
  function renderTable(rows, columns) {
    if (!rows || rows.length === 0) return '<div class="stage-empty">No rows.</div>';
    const cols = columns || Object.keys(rows[0]);
    const head = "<thead><tr>" + cols.map(function (c) {
      return "<th>" + escHtml(c) + "</th>";
    }).join("") + "</tr></thead>";
    const body = "<tbody>" + rows.map(function (row) {
      return "<tr>" + cols.map(function (c) {
        const v = row[c];
        const s = (typeof v === "object" && v !== null) ? JSON.stringify(v) : fmt(v);
        return '<td title="' + escHtml(s) + '">' + escHtml(s) + "</td>";
      }).join("") + "</tr>";
    }).join("") + "</tbody>";
    return '<div class="data-table-wrap"><table class="data-table">' + head + body + "</table></div>";
  }

  function renderHistogram(items, label) {
    if (!items || items.length === 0) return "";
    const max = Math.max.apply(null, items.map(function (i) { return i.count; }));
    const rows = items.map(function (i) {
      const pct = max ? (100 * i.count / max) : 0;
      return '<tr>' +
        '<td class="hist-label">' + escHtml(fmt(i.value)) + '</td>' +
        '<td class="hist-bar"><div class="bar" style="width:' + pct.toFixed(1) + '%"></div></td>' +
        '<td class="hist-count">' + i.count + '</td>' +
      '</tr>';
    }).join("");
    return '<table class="histogram"><caption>' + escHtml(label || "") + '</caption>' + rows + '</table>';
  }

  function renderKVList(obj) {
    const keys = Object.keys(obj || {});
    if (!keys.length) return '<div class="stage-empty">Empty.</div>';
    return '<ul class="kv-list">' + keys.map(function (k) {
      const v = obj[k];
      const display = (typeof v === "object" && v !== null) ? JSON.stringify(v) : fmt(v);
      return '<li><strong>' + escHtml(k) + ':</strong> <span>' + escHtml(display) + '</span></li>';
    }).join("") + '</ul>';
  }

  function statBox(label, value, hint) {
    return '<div class="stat-box">' +
      '<div class="stat-value">' + escHtml(fmt(value)) + '</div>' +
      '<div class="stat-label">' + escHtml(label) + '</div>' +
      (hint ? '<div class="stat-hint">' + escHtml(hint) + '</div>' : '') +
      '</div>';
  }

  // Toggleable raw-JSON disclosure
  function rawDisclosure(label, payload) {
    const json = JSON.stringify(payload, null, 2);
    return '<details class="raw-json"><summary>' + escHtml(label) + '</summary>' +
           '<pre>' + escHtml(json) + '</pre></details>';
  }

  // ---------------- summary ----------------
  function loadSummary() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/summary").then(function (data) {
      const fileRows = Object.keys(data.files).map(function (k) {
        return { file: k, exists: data.files[k] };
      });
      const html =
        '<div class="stat-row">' +
          statBox("Project", data.project_id) +
          statBox("SATD method", data.satd_method || "—") +
          statBox("Outputs present", fileRows.filter(function (r) { return r.exists; }).length + " / " + fileRows.length) +
        '</div>' +
        '<h4>Pipeline outputs</h4>' +
        renderTable(fileRows, ["file", "exists"]) +
        '<h4>run_summary.txt</h4>' +
        '<pre class="text-block">' + escHtml(data.run_summary || "(missing)") + '</pre>' +
        '<h4>Project config</h4>' +
        rawDisclosure("Show config (token redacted)", data.config);
      setBody("summary-body", html);
    }).catch(function (e) { fail("summary-body", e); });
  }

  // ---------------- SonarQube ----------------
  function loadSonarQube() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/sonarqube").then(function (data) {
      const html =
        '<div class="stat-row">' +
          statBox("Issues fetched", data.issues_total, "rows in sonarqube_issues.csv") +
          statBox("Files measured", data.measures_total, "rows in sonarqube_measures.csv") +
          statBox("Issue columns", data.issues_columns.length) +
        '</div>' +
        '<div class="two-col">' +
          '<div>' + renderHistogram(data.by_impact_severity, "By impact_severity (10.x model)") + '</div>' +
          '<div>' + renderHistogram(data.by_impact_quality, "By impact_quality") + '</div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div>' + renderHistogram(data.by_legacy_severity, "By legacy severity (BLOCKER…INFO)") + '</div>' +
          '<div>' + renderHistogram(data.by_type, "By type") + '</div>' +
        '</div>' +
        '<h4>Top rules</h4>' +
        renderHistogram(data.top_rules.slice(0, 25), "Top 25 rules by alert count") +
        '<h4>Issues — sample (first 50 rows)</h4>' +
        '<p class="stage-meta">All ' + data.issues_columns.length + ' columns: <code>' + escHtml(data.issues_columns.join(", ")) + '</code></p>' +
        renderTable(data.issues_sample, ["issue_key", "rule", "impact_severity", "impact_quality", "type", "file", "line", "message", "creationDate"]) +
        '<h4>Measures — sample (first 25 files)</h4>' +
        '<p class="stage-meta">All measure columns: <code>' + escHtml(data.measures_columns.join(", ")) + '</code></p>' +
        renderTable(data.measures_sample, ["file_path", "bugs", "vulnerabilities", "code_smells", "violations", "complexity", "cognitive_complexity", "coverage", "sqale_index", "reliability_rating", "security_rating"]);
      setBody("sonarqube-body", html);
    }).catch(function (e) { fail("sonarqube-body", e); });
  }

  // ---------------- GitHub ----------------
  function loadGithub() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/github").then(function (data) {
      const meta = data.metadata || {};
      const html =
        '<div class="stat-row">' +
          statBox("Files with churn data", data.churn_files) +
          statBox("Alert blame rows", data.alert_churn_total) +
          statBox("Blame matched", data.alert_churn_with_blame, "alerts where line_last_modified_days is not null") +
        '</div>' +
        '<h4>Extraction window</h4>' +
        renderKVList({
          "github_extraction_date": meta.github_extraction_date,
          "churn_window_start": meta.churn_window_start,
          "churn_window_end": meta.churn_window_end,
        }) +
        '<h4>File-level churn — sample (top 50 by total churn)</h4>' +
        '<p class="stage-meta">Columns: <code>' + escHtml(data.churn_columns.join(", ")) + '</code></p>' +
        renderTable(data.churn_sample, ["file_path", "commit_count", "unique_authors", "bus_factor", "lines_added", "lines_deleted", "churn", "days_since_modified", "file_age_days"]) +
        '<h4>Alert-level blame — sample (first 50)</h4>' +
        '<p class="stage-meta">Columns: <code>' + escHtml(data.alert_churn_columns.join(", ")) + '</code></p>' +
        renderTable(data.alert_churn_sample, ["issue_key", "line_last_modified_days", "line_author"]);
      setBody("github-body", html);
    }).catch(function (e) { fail("github-body", e); });
  }

  // ---------------- SATD ----------------
  function loadSatd() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/satd").then(function (data) {
      const cols = data.schema_kind === "java-bailiff"
        ? ["file_path", "satd_count", "satd_text", "satd_types", "satd_age_days", "satd_change_count"]
        : ["file_path", "satd_count", "satd_text"];
      const html =
        '<div class="stat-row">' +
          statBox("Method", data.method || "—", data.schema_kind) +
          statBox("Files with SATD", data.files_with_satd) +
          statBox("Total SATD comments", data.total_satd_count) +
        '</div>' +
        '<h4>SATD comments — sample</h4>' +
        '<p class="stage-meta">Schema: <code>' + escHtml(data.columns.join(", ")) + '</code></p>' +
        renderTable(data.sample, cols) +
        (data.bailiff_repos_csv
          ? '<h4>SATDBailiff repos.csv (terminal commit hash)</h4><pre class="text-block">' + escHtml(data.bailiff_repos_csv) + '</pre>'
          : "");
      setBody("satd-body", html);
    }).catch(function (e) { fail("satd-body", e); });
  }

  // ---------------- Pool ----------------
  function loadPool() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/pool").then(function (data) {
      const html =
        '<div class="stat-row">' +
          statBox("Source alerts", data.source_total_alerts, "rows in sonarqube_issues.csv") +
          statBox("Pool size", data.pool_size, "rows in alert_pool_200.csv") +
          statBox("Enriched pool", data.enriched_pool_size, "rows in enriched_pool_200.csv (LLM input)") +
          statBox("Unique rules", data.unique_rules_in_pool) +
          statBox("Unique files", data.unique_files_in_pool) +
        '</div>' +
        '<div class="constraint-row">' +
          '<div class="constraint-card">Tier budgets · ' + JSON.stringify(data.tier_budgets) + '</div>' +
          '<div class="constraint-card">Rule cap · ' + data.rule_cap + ' (max in pool: <strong>' + data.max_per_rule + '</strong>)</div>' +
          '<div class="constraint-card">File cap · ' + data.file_cap + ' (max in pool: <strong>' + data.max_per_file + '</strong>)</div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div>' + renderHistogram(data.tier_distribution, "By impact_severity") + '</div>' +
          '<div>' + renderHistogram(data.quality_distribution, "By impact_quality") + '</div>' +
        '</div>' +
        '<h4>Top rules in pool</h4>' +
        renderHistogram(data.top_rules_in_pool, "Rules by alert count (cap = " + data.rule_cap + ")") +
        '<h4>Pool — first 100 rows (in pool_rank order)</h4>' +
        renderTable(data.pool_sample, ["pool_rank", "issue_key", "rule", "impact_severity", "impact_quality", "file", "message"]);
      setBody("pool-body", html);
    }).catch(function (e) { fail("pool-body", e); });
  }

  // ---------------- LLM (C2 / C3) ----------------
  function loadLlm(condition, bodyId) {
    Promise.all([
      api("/api/researcher/" + encodeURIComponent(projectId) + "/llm_prompt/" + condition),
      api("/api/researcher/" + encodeURIComponent(projectId) + "/llm_output/" + condition),
    ]).then(function (parts) {
      const prompt = parts[0];
      const output = parts[1];

      if (prompt.error) {
        setBody(bodyId, '<div class="stage-error">' + escHtml(prompt.error) + '</div>');
        return;
      }

      const sampleIssue = (prompt.issues && prompt.issues.length) ? prompt.issues[0] : {};

      const outputBlock = output.error
        ? '<div class="stage-error">' + escHtml(output.error) + '</div>'
        : renderTable(output.rows, [condition + "_rank", "issue_key", "rule", "impact_severity", "file", "message", "llm_reasoning"]);

      const html =
        '<div class="stat-row">' +
          statBox("Alerts in prompt", prompt.alert_count) +
          statBox("Fields per alert", prompt.field_count_per_alert) +
          statBox("Prompt length", prompt.full_prompt_length_chars + " chars") +
          statBox("Ranked rows", output.alert_count || 0, "ranking_" + condition + ".csv") +
        '</div>' +
        '<h4>Per-alert JSON fields sent to the LLM</h4>' +
        '<p class="stage-meta">Forbidden fields (severity / impact_severity / impact_quality / llm_severity / line_author) are <strong>not</strong> in this set — verify in the field list below.</p>' +
        '<div class="field-pills">' + prompt.fields.map(function (f) {
          return '<span class="field-pill">' + escHtml(f) + '</span>';
        }).join("") + '</div>' +
        '<h4>Sample input (first alert)</h4>' +
        '<pre class="text-block">' + escHtml(JSON.stringify(sampleIssue, null, 2)) + '</pre>' +
        '<h4>Prompt template</h4>' +
        '<pre class="text-block">' + escHtml(prompt.template) + '</pre>' +
        '<details class="raw-json"><summary>Show full materialized prompt sent to API (' + prompt.full_prompt_length_chars + ' chars)</summary>' +
        '<pre class="text-block">' + escHtml(prompt.full_prompt) + '</pre></details>' +
        '<h4>LLM output — ranking_' + condition + '.csv</h4>' +
        outputBlock;
      setBody(bodyId, html);
    }).catch(function (e) { fail(bodyId, e); });
  }

  // ---------------- Display set ----------------
  function loadDisplaySet() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/display_set").then(function (data) {
      const html =
        '<div class="stat-row">' +
          statBox("Display set size", data.size, "exactly 15 expected") +
          statBox("Unique files", data.files.length) +
          statBox("Unique rules", data.rules.length) +
        '</div>' +
        '<div class="constraint-row">' +
          '<div class="constraint-card">Bucket budgets · ' + JSON.stringify(data.bucket_budgets) + '</div>' +
          '<div class="constraint-card">Max per file · ' + data.file_cap + '</div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div>' + renderHistogram(data.tier_distribution, "By impact_severity") + '</div>' +
          '<div>' + renderHistogram(data.quality_distribution, "By impact_quality") + '</div>' +
        '</div>' +
        '<h4>display_set.csv — all 15 rows</h4>' +
        renderTable(data.rows, ["issue_key", "rule", "impact_severity", "impact_quality", "file", "message", "c1_rank", "c2_rank", "c3_rank"]);
      setBody("display-body", html);
    }).catch(function (e) { fail("display-body", e); });
  }

  // ---------------- C1 vs C2 vs C3 diff ----------------
  function loadDiff() {
    api("/api/researcher/" + encodeURIComponent(projectId) + "/diff").then(function (data) {
      if (data.error) {
        setBody("diff-body", '<div class="stage-error">' + escHtml(data.error) + '</div>');
        return;
      }

      function deltaCell(d) {
        if (d === null || d === undefined) return '<td>—</td>';
        if (d === 0) return '<td class="delta-zero">0</td>';
        const cls = d > 0 ? "delta-down" : "delta-up";
        const arrow = d > 0 ? "▼" : "▲";
        return '<td class="' + cls + '">' + arrow + " " + Math.abs(d) + '</td>';
      }

      const rows = data.rows.map(function (r) {
        return '<tr>' +
          '<td><code>' + escHtml(r.issue_key) + '</code></td>' +
          '<td>' + escHtml(r.rule) + '</td>' +
          '<td>' + escHtml(r.impact_severity) + '</td>' +
          '<td title="' + escHtml(r.message) + '">' + escHtml((r.message || "").slice(0, 70)) + '</td>' +
          '<td><strong>' + fmt(r.c1_rank) + '</strong></td>' +
          '<td><strong>' + fmt(r.c2_rank) + '</strong></td>' +
          '<td><strong>' + fmt(r.c3_rank) + '</strong></td>' +
          deltaCell(r.c1_to_c2_delta) +
          deltaCell(r.c2_to_c3_delta) +
          deltaCell(r.c1_to_c3_delta) +
        '</tr>' +
        '<tr class="diff-reasoning-row">' +
          '<td colspan="10">' +
            '<div class="diff-reasoning"><strong>C2:</strong> ' + escHtml(r.llm_reasoning_c2 || "—") + '</div>' +
            '<div class="diff-reasoning"><strong>C3:</strong> ' + escHtml(r.llm_reasoning_c3 || "—") + '</div>' +
          '</td>' +
        '</tr>';
      }).join("");

      const html =
        '<p class="stage-meta">Delta = (rank in second condition) − (rank in first). Positive means the alert moved <em>down</em> the list (less important); negative means it moved <em>up</em>.</p>' +
        '<div class="data-table-wrap"><table class="data-table diff-table">' +
          '<thead><tr>' +
            '<th>issue_key</th><th>rule</th><th>sev.</th><th>message</th>' +
            '<th>C1</th><th>C2</th><th>C3</th>' +
            '<th>Δ C1→C2</th><th>Δ C2→C3</th><th>Δ C1→C3</th>' +
          '</tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table></div>';
      setBody("diff-body", html);
    }).catch(function (e) { fail("diff-body", e); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!projectId) return;
    loadSummary();
    loadSonarQube();
    loadGithub();
    loadSatd();
    loadPool();
    loadLlm("c2", "llm-c2-body");
    loadLlm("c3", "llm-c3-body");
    loadDisplaySet();
    loadDiff();
  });
})();
