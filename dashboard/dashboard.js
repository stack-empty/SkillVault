const DEFAULT_DATA_PATH = "../artifacts/demo-risky-skill/dashboard_data.json";
const DATA_PATH = new URLSearchParams(window.location.search).get("data") || DEFAULT_DATA_PATH;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function severityClass(value) {
  return String(value || "info").toLowerCase();
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function dimensionClass(score) {
  if (score >= 75) return "high";
  if (score >= 45) return "medium";
  return "low";
}

async function loadDashboardData() {
  const response = await fetch(DATA_PATH, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Unable to load ${DATA_PATH}. Start a local server from the repository root.`);
  }
  return response.json();
}

function renderSummaryCards(data) {
  const baseCards = Array.isArray(data.summary_cards) ? data.summary_cards : [];
  const extraCards = [
    {
      label: "Confidence",
      value: `${Math.round((data.confidence || 0) * 100)}%`,
      description: "Estimated confidence from available evidence.",
    },
    {
      label: "Static Findings",
      value: String((data.static_findings || []).length),
      description: "Findings identified before execution.",
    },
    {
      label: "Dynamic Findings",
      value: String((data.dynamic_findings || []).length),
      description: "Findings observed during monitored behavior.",
    },
  ];
  return [...baseCards, ...extraCards]
    .map((card) => `
      <article class="metric-card">
        <span class="metric-label">${escapeHtml(card.label)}</span>
        <strong>${escapeHtml(card.value)}</strong>
        <p class="level3-muted">${escapeHtml(card.description)}</p>
      </article>
    `)
    .join("");
}

function renderRiskDimensions(dimensions) {
  return Object.entries(dimensions || {})
    .map(([key, value]) => {
      const score = Math.max(0, Math.min(100, Number(value) || 0));
      return `
        <div class="bar-row">
          <strong>${escapeHtml(titleCase(key))}</strong>
          <div class="bar-track" aria-label="${escapeHtml(key)} ${score}">
            <div class="bar-fill ${dimensionClass(score)}" style="width: ${score}%"></div>
          </div>
          <span>${score}</span>
        </div>
      `;
    })
    .join("");
}

function renderTimeline(events) {
  return (events || [])
    .map((event) => `
      <li class="timeline-item">
        <strong>${escapeHtml(event.timestamp)}</strong>
        <span>${escapeHtml(event.event_type)}</span>
        <span class="severity ${severityClass(event.severity)}">${escapeHtml(event.severity)}</span>
        <div>
          <strong>${escapeHtml(event.message)}</strong>
          <p class="level3-muted">${escapeHtml(event.evidence)}</p>
        </div>
      </li>
    `)
    .join("");
}

function renderFindings(findings) {
  return (findings || [])
    .map((finding) => `
      <tr>
        <td><code>${escapeHtml(finding.rule_id)}</code></td>
        <td>${escapeHtml(finding.title)}</td>
        <td><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
        <td><span class="finding-source">${escapeHtml(finding.source)}</span></td>
        <td><code>${escapeHtml(finding.evidence)}</code></td>
        <td>${escapeHtml(finding.explanation)}</td>
        <td>${escapeHtml(finding.recommendation)}</td>
      </tr>
    `)
    .join("");
}

function renderComparison(rows) {
  return (rows || [])
    .map((row) => `
      <tr>
        <td>${escapeHtml(row.risk)}</td>
        <td>${row.static_detected ? "Yes" : "No"}</td>
        <td>${row.dynamic_triggered ? "Yes" : "No"}</td>
        <td>${escapeHtml(row.conclusion)}</td>
      </tr>
    `)
    .join("");
}

function renderRecommendations(items) {
  return (items || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
}

function renderNotes(items) {
  if (!items || items.length === 0) return "";
  return `
    <div class="notes">
      <strong>Notes</strong>
      <ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>
  `;
}

function renderDashboard(data) {
  const app = document.getElementById("app");
  const riskLevelClass = severityClass(data.risk_level);
  app.innerHTML = `
    <div class="level3-shell">
      <header class="level3-hero">
        <div>
          <p class="level3-eyebrow">SkillVault</p>
          <h1>Level3 Visual Dashboard</h1>
          <p class="level3-muted">${escapeHtml(data.skill_name)} · ${escapeHtml(data.analysis_mode)} · ${escapeHtml(data.level)}</p>
        </div>
        <span class="risk-pill ${riskLevelClass}">${escapeHtml(data.risk_level)}</span>
      </header>

      <section class="dashboard-section" aria-label="Risk overview">
        <h2>Risk Overview</h2>
        <div class="metrics-grid">${renderSummaryCards(data)}</div>
      </section>

      <section class="dashboard-section" aria-label="Risk dimensions">
        <h2>Risk Dimensions</h2>
        <div class="bar-grid">${renderRiskDimensions(data.risk_dimensions)}</div>
      </section>

      <section class="dashboard-section" aria-label="Dynamic behavior timeline">
        <h2>Dynamic Behavior Timeline</h2>
        <ul class="timeline-list">${renderTimeline(data.timeline_events)}</ul>
      </section>

      <section class="dashboard-section" aria-label="Rule findings">
        <h2>Rule Findings</h2>
        <div class="table-wrap">
          <table class="level3-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Evidence</th>
                <th>Explanation</th>
                <th>Recommendation</th>
              </tr>
            </thead>
            <tbody>${renderFindings(data.rule_findings)}</tbody>
          </table>
        </div>
      </section>

      <section class="dashboard-section" aria-label="Static and dynamic comparison">
        <h2>Static vs Dynamic Comparison</h2>
        <div class="table-wrap">
          <table class="level3-table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Static Detected</th>
                <th>Dynamic Triggered</th>
                <th>Conclusion</th>
              </tr>
            </thead>
            <tbody>${renderComparison(data.static_dynamic_comparison)}</tbody>
          </table>
        </div>
      </section>

      <section class="dashboard-section" aria-label="Recommendations">
        <h2>Recommendations</h2>
        <ul class="recommendations">${renderRecommendations(data.recommendations)}</ul>
        ${renderNotes(data.notes)}
      </section>
    </div>
  `;
}

function renderError(error) {
  const app = document.getElementById("app");
  app.innerHTML = `
    <div class="error-box">
      <h1>SkillVault Level3 Visual Dashboard</h1>
      <p>${escapeHtml(error.message)}</p>
      <p>Run <code>python3 tools/generate_dashboard_data.py examples/demo-risky-skill</code> and serve the repository with <code>python3 -m http.server 8000</code>.</p>
    </div>
  `;
}

const DIMENSION_EXPLANATIONS = {
  static_risk: "Risk inferred from source files, manifests, and declared behavior before execution.",
  dynamic_risk: "Risk observed during monitored behavior or imported runtime evidence.",
  network_risk: "Potential or observed external communication behavior.",
  secret_risk: "Potential or observed access to secrets, credentials, tokens, or sensitive files.",
  persistence_risk: "Behavior that may survive beyond a single skill run.",
  prompt_injection_risk: "Instructions that may override user or system intent.",
  evasion_risk: "Obfuscation or behavior that makes detection and review harder.",
};

const reviewState = {
  data: null,
  reviewMode: true,
  timelineSeverity: "attention",
  timelineType: "all",
  timelineQuery: "",
  findingSeverity: "attention",
  findingSource: "all",
  findingQuery: "",
};

function decisionForRisk(level) {
  const normalized = String(level || "UNKNOWN").toUpperCase();
  if (["HIGH", "CRITICAL"].includes(normalized)) return "Block or isolate before manual approval";
  if (normalized === "MEDIUM") return "Require manual review before use";
  if (normalized === "LOW") return "Allow with monitoring";
  if (normalized === "INFO") return "Informational only";
  return "Review required";
}

function isAttentionSeverity(severity) {
  return ["CRITICAL", "HIGH", "MEDIUM"].includes(String(severity || "").toUpperCase());
}

function formatBool(value, positive, negative) {
  return value ? positive : negative;
}

function normalizedText(...values) {
  return values.map((value) => String(value || "").toLowerCase()).join(" ");
}

function sortedBySeverity(items) {
  const weight = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  return [...(items || [])].sort((a, b) => {
    const severityDelta = (weight[String(b.severity || "").toUpperCase()] || 0) - (weight[String(a.severity || "").toUpperCase()] || 0);
    return severityDelta || String(a.rule_id || a.timestamp || "").localeCompare(String(b.rule_id || b.timestamp || ""));
  });
}

function getReviewerSummary(data) {
  const fallback = {
    verdict: `${data.risk_level || "Unknown"} risk skill`,
    summary: "Review the static and dynamic evidence before allowing this skill to run.",
    manual_review_required: ["CRITICAL", "HIGH", "MEDIUM"].includes(String(data.risk_level || "").toUpperCase()),
    suggested_decision: decisionForRisk(data.risk_level),
    top_risks: [],
  };
  return { ...fallback, ...(data.reviewer_summary || {}) };
}

function getSecurityFlags(data) {
  return {
    sensitive_file_access: false,
    shell_execution: false,
    network_attempt: false,
    prompt_injection_risk: false,
    persistence_risk: false,
    evasion_risk: false,
    ...(data.security_flags || {}),
  };
}

function getMetricValue(data, label) {
  const card = (data.summary_cards || []).find((item) => item.label === label);
  return card ? card.value : "";
}

function renderStatusLine(message, state = "info") {
  const node = document.getElementById("load-status");
  if (node) {
    node.textContent = message;
    node.className = `load-status ${state}`;
  }
}

function renderReviewHeader(data) {
  return `
    <header class="review-header">
      <div>
        <p class="level3-eyebrow">SkillVault</p>
        <h1>SkillVault Security Review Dashboard</h1>
        <p class="level3-muted">Level3.1 security review interface for inspecting skill risk evidence.</p>
      </div>
      <div class="header-badges">
        <span class="badge risk ${severityClass(data.risk_level)}">${escapeHtml(data.risk_level || "UNKNOWN")}</span>
        <span class="badge mode ${severityClass(data.analysis_mode)}">${escapeHtml(String(data.analysis_mode || "unknown").toUpperCase())}</span>
      </div>
      <dl class="header-meta">
        <div><dt>Skill</dt><dd>${escapeHtml(data.skill_name)}</dd></div>
        <div><dt>Generated</dt><dd>${escapeHtml(data.generated_at || "Unknown")}</dd></div>
        <div><dt>Data Source</dt><dd>${escapeHtml(data.data_source || DATA_PATH)}</dd></div>
      </dl>
    </header>
    <div id="load-status" class="load-status success">Dashboard data loaded successfully.</div>
  `;
}

function renderDecisionPanel(data) {
  const summary = getReviewerSummary(data);
  const manual = Boolean(summary.manual_review_required);
  return `
    <section class="dashboard-section decision-panel ${manual ? "requires-review" : ""}">
      <div class="section-heading">
        <div>
          <h2>Review Decision Panel</h2>
          <p class="level3-muted">Operational guidance for whether this skill can run.</p>
        </div>
        <label class="review-toggle">
          <input id="review-mode-toggle" type="checkbox" ${reviewState.reviewMode ? "checked" : ""}>
          Security Review Mode
        </label>
      </div>
      <div class="decision-grid">
        <article class="decision-primary">
          <span class="metric-label">Suggested Decision</span>
          <strong>${escapeHtml(summary.suggested_decision || decisionForRisk(data.risk_level))}</strong>
          <p>${escapeHtml(summary.summary)}</p>
        </article>
        <article><span class="metric-label">Manual Review Required</span><strong>${manual ? "Yes" : "No"}</strong></article>
        <article><span class="metric-label">Risk Level</span><strong>${escapeHtml(data.risk_level || "UNKNOWN")}</strong></article>
        <article><span class="metric-label">Confidence</span><strong>${Math.round((data.confidence || 0) * 100)}%</strong></article>
        <article><span class="metric-label">Analysis Mode</span><strong>${escapeHtml(String(data.analysis_mode || "unknown").toUpperCase())}</strong></article>
        <article><span class="metric-label">Data Source</span><strong class="compact">${escapeHtml(data.data_source || DATA_PATH)}</strong></article>
      </div>
    </section>
  `;
}

function renderKeyRiskSummary(data) {
  const summary = getReviewerSummary(data);
  const flags = getSecurityFlags(data);
  const severeEvidence = sortedBySeverity([...(data.dynamic_findings || []), ...(data.static_findings || []), ...(data.rule_findings || [])])[0];
  const flagRows = [
    ["Sensitive file access", flags.sensitive_file_access],
    ["Shell execution", flags.shell_execution],
    ["Network attempt", flags.network_attempt],
    ["Prompt injection risk", flags.prompt_injection_risk],
    ["Persistence risk", flags.persistence_risk],
    ["Evasion risk", flags.evasion_risk],
  ];
  return `
    <section class="dashboard-section">
      <h2>Key Risk Summary</h2>
      <div class="key-risk-grid">
        <article>
          <h3>Top 3 Risks</h3>
          <ol>${(summary.top_risks || []).slice(0, 3).map((risk) => `<li>${escapeHtml(risk)}</li>`).join("")}</ol>
        </article>
        <article>
          <h3>Most Severe Evidence</h3>
          <p><strong>${escapeHtml(severeEvidence?.title || severeEvidence?.message || "No high severity evidence")}</strong></p>
          <pre>${escapeHtml(severeEvidence?.evidence || "No evidence available")}</pre>
        </article>
        <article class="flag-list">
          <h3>Security Flags</h3>
          ${flagRows.map(([label, value]) => `
            <div><span>${escapeHtml(label)}</span><strong class="${value ? "flagged" : "clear"}">${value ? "Present" : "Not observed"}</strong></div>
          `).join("")}
        </article>
      </div>
    </section>
  `;
}

function renderReviewOverview(data) {
  const cards = [
    ["Risk Score", getMetricValue(data, "Risk Score") || `${data.risk_score || 0}/100`],
    ["Risk Level", data.risk_level || "UNKNOWN"],
    ["Confidence", `${Math.round((data.confidence || 0) * 100)}%`],
    ["Triggered Rules", getMetricValue(data, "Triggered Rules") || String((data.rule_findings || []).length)],
    ["Evidence Events", getMetricValue(data, "Evidence Events") || String((data.timeline_events || []).length)],
    ["Static Findings", String((data.static_findings || []).length)],
    ["Dynamic Findings", String((data.dynamic_findings || []).length)],
    ["Analysis Mode", String(data.analysis_mode || "unknown").toUpperCase()],
  ];
  return `
    <section class="dashboard-section">
      <h2>Risk Overview</h2>
      <div class="metrics-grid review-metrics">
        ${cards.map(([label, value]) => `
          <article class="metric-card">
            <span class="metric-label">${escapeHtml(label)}</span>
            <strong>${escapeHtml(value)}</strong>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function renderReviewDimensions(data) {
  const rows = Object.entries(data.risk_dimensions || {})
    .map(([key, value]) => [key, Math.max(0, Math.min(100, Number(value) || 0))])
    .sort((a, b) => b[1] - a[1]);
  return `
    <section class="dashboard-section">
      <h2>Risk Dimensions</h2>
      <div class="bar-grid">
        ${rows.map(([key, score]) => `
          <div class="dimension-row">
            <div>
              <strong>${escapeHtml(titleCase(key))}</strong>
              <p>${escapeHtml(DIMENSION_EXPLANATIONS[key] || "Risk dimension from available evidence.")}</p>
            </div>
            <div class="bar-track"><div class="bar-fill ${dimensionClass(score)}" style="width: ${score}%"></div></div>
            <span>${score}</span>
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

function uniqueValues(items, key) {
  return [...new Set((items || []).map((item) => item[key]).filter(Boolean))].sort();
}

function filterItems(items, severityFilter, sourceOrTypeFilter, query, mode, sourceKey) {
  const normalizedQuery = String(query || "").toLowerCase();
  return sortedBySeverity(items).filter((item) => {
    const severity = String(item.severity || "").toUpperCase();
    const sourceOrType = String(item[sourceKey] || "");
    const matchesSeverity = severityFilter === "all"
      || (severityFilter === "attention" ? isAttentionSeverity(severity) : severity === severityFilter);
    const matchesSource = sourceOrTypeFilter === "all" || sourceOrType === sourceOrTypeFilter;
    const matchesQuery = !normalizedQuery || normalizedText(item.rule_id, item.title, item.message, item.evidence, item.explanation, item.recommendation, item.event_type).includes(normalizedQuery);
    const matchesMode = !mode || !reviewState.reviewMode || isAttentionSeverity(severity);
    return matchesSeverity && matchesSource && matchesQuery && matchesMode;
  });
}

function filterTimelineEvents(items, severityFilter, typeFilter, query) {
  const normalizedQuery = String(query || "").toLowerCase();
  return [...(items || [])].filter((item) => {
    const severity = String(item.severity || "").toUpperCase();
    const type = String(item.event_type || "");
    const matchesSeverity = severityFilter === "all"
      || (severityFilter === "attention" ? isAttentionSeverity(severity) : severity === severityFilter);
    const matchesType = typeFilter === "all" || type === typeFilter;
    const matchesQuery = !normalizedQuery || normalizedText(item.event_type, item.message, item.evidence).includes(normalizedQuery);
    const matchesMode = !reviewState.reviewMode || isAttentionSeverity(severity);
    return matchesSeverity && matchesType && matchesQuery && matchesMode;
  });
}

function renderTimelineControls(data) {
  return `
    <div class="filters">
      <label>Severity
        <select id="timeline-severity">
          <option value="attention">HIGH + MEDIUM</option>
          <option value="all">All</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
      </label>
      <label>Event Type
        <select id="timeline-type">
          <option value="all">All</option>
          ${uniqueValues(data.timeline_events, "event_type").map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("")}
        </select>
      </label>
      <label>Search
        <input id="timeline-search" type="search" placeholder="Search evidence or message">
      </label>
    </div>
  `;
}

function renderTimelineReview(data) {
  const events = filterTimelineEvents(data.timeline_events || [], reviewState.timelineSeverity, reviewState.timelineType, reviewState.timelineQuery);
  return `
    <section class="dashboard-section focus-section">
      <div class="section-heading">
        <div>
          <h2>Evidence Timeline</h2>
          <p class="level3-muted">Filtered runtime and evidence events. High severity items are listed first in review mode.</p>
        </div>
        <span class="result-count">${events.length} shown</span>
      </div>
      ${renderTimelineControls(data)}
      <ul class="timeline-list review-timeline">
        ${events.map((event) => `
          <li class="timeline-item ${severityClass(event.severity)}">
            <div><strong>${escapeHtml(event.timestamp)}</strong><span>${escapeHtml(event.event_type)}</span></div>
            <span class="severity ${severityClass(event.severity)}">${escapeHtml(event.severity)}</span>
            <div>
              <strong>${escapeHtml(event.message)}</strong>
              <details>
                <summary>Evidence</summary>
                <pre>${escapeHtml(event.evidence)}</pre>
              </details>
            </div>
          </li>
        `).join("") || `<li class="empty-row">No events match the current filters.</li>`}
      </ul>
    </section>
  `;
}

function renderFindingControls() {
  return `
    <div class="filters">
      <label>Severity
        <select id="finding-severity">
          <option value="attention">HIGH + MEDIUM</option>
          <option value="all">All</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
      </label>
      <label>Source
        <select id="finding-source">
          <option value="all">All</option>
          <option value="static">Static</option>
          <option value="dynamic">Dynamic</option>
        </select>
      </label>
      <label>Search
        <input id="finding-search" type="search" placeholder="Search rules or evidence">
      </label>
    </div>
  `;
}

function renderFindingsReview(data) {
  const findings = filterItems(data.rule_findings || [], reviewState.findingSeverity, reviewState.findingSource, reviewState.findingQuery, true, "source");
  return `
    <section class="dashboard-section focus-section">
      <div class="section-heading">
        <div>
          <h2>Rule Findings</h2>
          <p class="level3-muted">Rule matches with evidence, explanation, and recommended handling.</p>
        </div>
        <span class="result-count">${findings.length} shown</span>
      </div>
      ${renderFindingControls()}
      <div class="finding-list">
        ${findings.map((finding) => `
          <article class="finding-card ${severityClass(finding.severity)}">
            <header>
              <code>${escapeHtml(finding.rule_id)}</code>
              <span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
              <span class="badge source">${escapeHtml(finding.source)}</span>
            </header>
            <h3>${escapeHtml(finding.title)}</h3>
            <dl>
              <div><dt>Evidence</dt><dd><pre>${escapeHtml(finding.evidence)}</pre></dd></div>
              <div><dt>Explanation</dt><dd>${escapeHtml(finding.explanation)}</dd></div>
              <div><dt>Recommendation</dt><dd>${escapeHtml(finding.recommendation)}</dd></div>
            </dl>
          </article>
        `).join("") || `<p class="empty-row">No rule findings match the current filters.</p>`}
      </div>
    </section>
  `;
}

function renderComparisonReview(data) {
  return `
    <section class="dashboard-section">
      <h2>Static vs Dynamic Comparison</h2>
      <div class="table-wrap">
        <table class="level3-table comparison-table">
          <thead>
            <tr><th>Risk</th><th>Static</th><th>Dynamic</th><th>Conclusion</th></tr>
          </thead>
          <tbody>
            ${(data.static_dynamic_comparison || []).map((row) => `
              <tr>
                <td>${escapeHtml(row.risk)}</td>
                <td>${escapeHtml(formatBool(row.static_detected, "Detected", "Not detected"))}</td>
                <td>${escapeHtml(formatBool(row.dynamic_triggered, "Triggered", "Not triggered"))}</td>
                <td><strong>${escapeHtml(row.conclusion || "Needs review")}</strong></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderActions(data) {
  return `
    <section class="dashboard-section action-panel">
      <h2>Recommended Actions</h2>
      <ul class="recommendations">${renderRecommendations(data.recommendations)}</ul>
      ${renderNotes(data.notes)}
    </section>
  `;
}

function renderRawData(data) {
  return `
    <section class="dashboard-section raw-data">
      <div class="section-heading">
        <div>
          <h2>Raw Evidence Data</h2>
          <p class="level3-muted">Current data path: <code>${escapeHtml(DATA_PATH)}</code></p>
        </div>
        <button id="copy-json" type="button">Copy JSON</button>
      </div>
      <details>
        <summary>Show formatted dashboard_data.json</summary>
        <pre id="raw-json">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>
    </section>
  `;
}

function renderDemoNotice(data) {
  if (String(data.analysis_mode || "").toLowerCase() !== "demo") return "";
  return `
    <div class="demo-notice">
      <strong>DEMO DATA</strong>
      <span>This data shows dashboard structure and review workflow only. It is not a verified VM Mode C execution result.</span>
    </div>
  `;
}

function renderSecurityReviewDashboard(data) {
  reviewState.data = data;
  const app = document.getElementById("app");
  app.innerHTML = `
    <div class="level3-shell security-review ${reviewState.reviewMode ? "review-mode" : ""}">
      ${renderReviewHeader(data)}
      ${renderDemoNotice(data)}
      ${renderDecisionPanel(data)}
      ${renderKeyRiskSummary(data)}
      ${renderReviewOverview(data)}
      ${renderReviewDimensions(data)}
      ${renderTimelineReview(data)}
      ${renderFindingsReview(data)}
      ${renderComparisonReview(data)}
      ${renderActions(data)}
      ${renderRawData(data)}
    </div>
  `;
  attachReviewHandlers();
}

function preserveControlValues() {
  const timelineSeverity = document.getElementById("timeline-severity");
  const timelineType = document.getElementById("timeline-type");
  const timelineSearch = document.getElementById("timeline-search");
  const findingSeverity = document.getElementById("finding-severity");
  const findingSource = document.getElementById("finding-source");
  const findingSearch = document.getElementById("finding-search");
  if (timelineSeverity) timelineSeverity.value = reviewState.timelineSeverity;
  if (timelineType) timelineType.value = reviewState.timelineType;
  if (timelineSearch) timelineSearch.value = reviewState.timelineQuery;
  if (findingSeverity) findingSeverity.value = reviewState.findingSeverity;
  if (findingSource) findingSource.value = reviewState.findingSource;
  if (findingSearch) findingSearch.value = reviewState.findingQuery;
}

function attachReviewHandlers() {
  preserveControlValues();
  const reviewToggle = document.getElementById("review-mode-toggle");
  if (reviewToggle) {
    reviewToggle.addEventListener("change", (event) => {
      reviewState.reviewMode = event.target.checked;
      if (reviewState.reviewMode) {
        reviewState.timelineSeverity = "attention";
        reviewState.findingSeverity = "attention";
      }
      renderSecurityReviewDashboard(reviewState.data);
    });
  }
  const bind = (id, key) => {
    const node = document.getElementById(id);
    if (node) {
      node.addEventListener("input", (event) => {
        reviewState[key] = event.target.value;
        renderSecurityReviewDashboard(reviewState.data);
      });
    }
  };
  bind("timeline-severity", "timelineSeverity");
  bind("timeline-type", "timelineType");
  bind("timeline-search", "timelineQuery");
  bind("finding-severity", "findingSeverity");
  bind("finding-source", "findingSource");
  bind("finding-search", "findingQuery");
  const copy = document.getElementById("copy-json");
  if (copy) {
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(JSON.stringify(reviewState.data, null, 2));
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy JSON"; }, 1200);
    });
  }
}

function renderSecurityReviewError(error) {
  const app = document.getElementById("app");
  app.innerHTML = `
    <div class="error-box">
      <h1>SkillVault Security Review Dashboard</h1>
      <p><strong>Failed to load dashboard_data.json.</strong></p>
      <p>${escapeHtml(error.message)}</p>
      <p>Current data path: <code>${escapeHtml(DATA_PATH)}</code></p>
      <p>Please run:</p>
      <pre>python3 tools/generate_dashboard_data.py examples/demo-risky-skill
python3 -m http.server 8000</pre>
    </div>
  `;
}

function initSecurityReviewDashboard() {
  const app = document.getElementById("app");
  app.innerHTML = `
    <div class="error-box">
      <h1>SkillVault Security Review Dashboard</h1>
      <p id="load-status" class="load-status">Loading dashboard data...</p>
      <p>Current data path: <code>${escapeHtml(DATA_PATH)}</code></p>
    </div>
  `;
  loadDashboardData()
    .then((data) => {
      renderStatusLine("Dashboard data loaded successfully.", "success");
      renderSecurityReviewDashboard(data);
    })
    .catch(renderSecurityReviewError);
}

initSecurityReviewDashboard();
