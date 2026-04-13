const jsonHeaders = {
  "content-type": "application/json",
};

const modelPreferenceStorageKey = "fortiedr.portal.modelPreference";
const analysisProfileStorageKey = "fortiedr.portal.analysisProfile";
const engineSourceStorageKey = "fortiedr.portal.engineSource";
const privateEnginePreferenceStorageKey = "fortiedr.portal.privateEnginePreference";

const timestampFormatter = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

export async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload?.error?.message || `Request failed with status ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    error.details = payload?.error?.details || [];
    throw error;
  }
  return payload;
}

export async function postJson(url, payload) {
  return fetchJson(url, {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify(payload),
  });
}

export function show(element) {
  element.classList.remove("hidden");
}

export function hide(element) {
  element.classList.add("hidden");
}

export function setState(element, message) {
  element.textContent = message;
  show(element);
}

export function clearState(element) {
  element.textContent = "";
  hide(element);
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function virusTotalUrl(hash) {
  const rendered = String(hash ?? "").trim();
  if (!rendered) {
    return null;
  }
  return `https://www.virustotal.com/gui/file/${encodeURIComponent(rendered)}`;
}

function virusTotalIcon() {
  return `
    <svg class="virustotal-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 89" aria-hidden="true" focusable="false">
      <path fill-rule="evenodd" d="M45.292 44.5 0 89h100V0H0l45.292 44.5zM90 80H22l35.987-35.2L22 9h68v71z"></path>
    </svg>
  `;
}

function copyIcon() {
  return `
    <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M5 2.5A1.5 1.5 0 0 1 6.5 1h5A1.5 1.5 0 0 1 13 2.5v7A1.5 1.5 0 0 1 11.5 11h-5A1.5 1.5 0 0 1 5 9.5z" fill="none" stroke="currentColor" stroke-width="1.3"/>
      <path d="M3.5 5H3A1 1 0 0 0 2 6v7a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-.5" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
    </svg>
  `;
}

function renderVirusTotalLink(hash, label = "Open in VirusTotal") {
  const url = virusTotalUrl(hash);
  if (!url) {
    return "";
  }
  return `
    <a
      class="virustotal-link"
      href="${escapeHtml(url)}"
      target="_blank"
      rel="noopener noreferrer"
      title="${escapeHtml(`${label}: ${hash}`)}"
      aria-label="${escapeHtml(`${label}: ${hash}`)}"
    >
      ${virusTotalIcon()}
    </a>
  `;
}

function normalizeToken(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll(/[^\w]+/g, "_")
    .replaceAll(/^_+|_+$/g, "");
}

function humanizeToken(value) {
  return String(value ?? "n/a")
    .replaceAll(/_/g, " ")
    .replaceAll(/\s+/g, " ")
    .trim();
}

function friendlyTokenLabel(value) {
  const rendered = humanizeToken(value);
  if (!rendered || rendered.toLowerCase() === "n/a") {
    return "n/a";
  }
  return rendered.replace(/\b([a-z])/g, (match) => match.toUpperCase());
}

function parseTimestamp(value) {
  if (!value) {
    return null;
  }
  const raw = String(value).trim();
  const normalized =
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw) ? raw.replace(" ", "T") + "Z" : raw;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function prettyDate(value) {
  if (!value) {
    return "n/a";
  }
  const date = parseTimestamp(value);
  if (!date) {
    return value;
  }
  return `${timestampFormatter.format(date)} UTC`;
}

export function runLabel(run) {
  const timestamp = prettyDate(run?.completed_at || run?.created_at);
  return timestamp === "n/a" ? "Analysis run" : `Analysis · ${timestamp}`;
}

function toneForValue(value, fallbackTone = "neutral") {
  const normalized = normalizeToken(value);
  if (
    [
      "critical",
      "high",
      "failed",
      "incorrect",
      "malicious",
      "confirmed_malicious_activity",
      "red_team",
      "red_team_activity",
    ].includes(normalized)
  ) {
    return "danger";
  }
  if (
    [
      "medium",
      "suspicious",
      "suspicious_activity_requiring_validation",
      "needs_validation",
      "partially_correct",
      "pup",
      "unknown",
    ].includes(normalized)
  ) {
    return "warn";
  }
  if (
    [
      "low",
      "success",
      "passed",
      "correct",
      "useful",
      "benign",
      "false_positive",
      "legitimate_admin_activity",
      "analyzed",
    ].includes(normalized)
  ) {
    return "ok";
  }
  if (["info", "open", "block", "blocked", "unhandled"].includes(normalized)) {
    return "info";
  }
  return fallbackTone;
}

export function badge(value, fallbackClass = "", options = {}) {
  const label = value ?? "n/a";
  const normalized = normalizeToken(value || fallbackClass || "neutral");
  const tone = options.tone || toneForValue(value || fallbackClass, "neutral");
  const title = options.title ?? humanizeToken(label);
  const classes = ["badge", `tone-${tone}`, `kind-${normalized || "neutral"}`];
  if (normalized === "running") {
    classes.push("is-spinning");
  }
  return `<span class="${escapeHtml(classes.join(" "))}" title="${escapeHtml(title)}">${escapeHtml(humanizeToken(label))}</span>`;
}

export function sourceBadge(kind) {
  const normalized = normalizeToken(kind);
  const label = normalized === "llm" ? "LLM" : "API";
  return `<span class="source-chip source-chip-${escapeHtml(normalized)}">${label}</span>`;
}

export function textValue(value, options = {}) {
  const rendered = value == null || value === "" ? "n/a" : String(value);
  const classes = ["value-text"];
  if (options.mono) {
    classes.push("value-mono");
  }
  if (options.small) {
    classes.push("value-small");
  }
  return `<strong class="${classes.join(" ")}" title="${escapeHtml(rendered)}">${escapeHtml(rendered)}</strong>`;
}

function inlineMetadataValue(value, { mono = false } = {}) {
  const rendered = value == null || value === "" ? "n/a" : String(value);
  return `<span class="meta-pill-value ${mono ? "mono-inline" : ""}" title="${escapeHtml(rendered)}">${escapeHtml(rendered)}</span>`;
}

export function renderHashValue(value) {
  const rendered = value == null || value === "" ? "n/a" : String(value);
  return `
    <span class="hash-inline">
      <span class="meta-pill-value mono-inline" title="${escapeHtml(rendered)}">${escapeHtml(rendered)}</span>
      ${rendered !== "n/a" ? renderVirusTotalLink(rendered) : ""}
    </span>
  `;
}

function renderMetaPill(label, content, { wide = false } = {}) {
  return `
    <div class="meta-pill ${wide ? "meta-pill-wide" : ""}">
      <span class="meta-pill-label">${escapeHtml(label)}</span>
      <span class="meta-pill-content">${content}</span>
    </div>
  `;
}

export function renderLabeledValue(label, content) {
  return `
    <div class="meta-item">
      <span>${escapeHtml(label)}</span>
      ${content}
    </div>
  `;
}

export function renderKeyMetadata(keyMetadata) {
  const fields = [
    ["hostname", "Hostname", "text"],
    ["user", "User", "text"],
    ["process_name", "Process", "text"],
    ["process_path", "Process Path", "text"],
    ["severity", "Severity", "badge"],
    ["classification", "Classification", "badge"],
    ["first_seen", "First Seen", "date"],
    ["last_seen", "Last Seen", "date"],
    ["action", "Action", "badge"],
  ];

  const items = fields
    .map(([key, label, type]) => {
      const field = keyMetadata?.[key];
      if (!field?.value) {
        return "";
      }
      let content = inlineMetadataValue(field.value);
      let wide = false;
      let extraClass = "";
      if (type === "badge") {
        content = badge(field.value);
      } else if (type === "date") {
        content = inlineMetadataValue(prettyDate(field.value));
      } else if (key === "process_path") {
        content = inlineMetadataValue(field.value);
        wide = true;
        extraClass = "meta-pill-multiline meta-pill-process-path";
      }
      return renderMetaPill(label, content, { wide, extraClass });
    })
    .join("");

  const hashes = keyMetadata?.hashes || {};
  return `
    <div class="meta-flow">
      ${items}
      ${hashes.md5 ? renderMetaPill("MD5", renderHashValue(hashes.md5)) : ""}
      ${hashes.sha256 ? renderMetaPill("SHA256", renderHashValue(hashes.sha256)) : ""}
    </div>
  `;
}

function renderEvidence(evidence = []) {
  if (!evidence.length) {
    return `<p class="small-note">No evidence recorded.</p>`;
  }
  return `
    <div class="fact-evidence">
      ${evidence
        .map(
          (item) =>
            `<span class="evidence-chip" title="${escapeHtml(`${item.tool} · ${item.path}`)}">${escapeHtml(item.tool)} · ${escapeHtml(item.path)}</span>`,
        )
        .join("")}
    </div>
  `;
}

function renderList(items = [], emptyMessage = "No items recorded.") {
  if (!items.length) {
    return `<p class="small-note">${escapeHtml(emptyMessage)}</p>`;
  }
  return `<ul class="clean-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

export function renderAnalysisOverview(run, options = {}) {
  const analysis = run?.validated_output;
  const availableRuns = options.availableRuns || [];
  const selectedRunId = String(options.selectedRunId || run?.run_id || "");
  const completedAt = prettyDate(run.completed_at || run.created_at);
  const summaryText = analysis?.executive_summary
    ? analysis.executive_summary
    : run?.status === "running"
      ? "Analysis is still running in the background."
      : run?.error?.message || "This run did not produce a validated executive summary.";
  const chips = analysis
    ? `
        ${badge(analysis.risk_level)}
        ${badge(friendlyTokenLabel(analysis.possible_classification?.label), analysis.possible_classification?.label)}
      `
    : `
        ${badge(friendlyTokenLabel(run?.status), run?.status)}
        ${run?.validation_status ? badge(friendlyTokenLabel(run.validation_status), run.validation_status) : ""}
      `;
  return `
    <div class="overview-card">
      <div class="overview-header">
        <div>
          ${
            availableRuns.length
              ? `
                <label class="overview-run-picker">
                  <span>Run</span>
                  <select id="overview-run-selector">
                    ${availableRuns
                      .map(
                        (entry) => `
                          <option value="${escapeHtml(entry.run_id)}" ${String(entry.run_id) === selectedRunId ? "selected" : ""}>
                            ${escapeHtml(`${runLabel(entry)} · ${friendlyTokenLabel(entry.status)}`)}
                          </option>
                        `,
                      )
                      .join("")}
                  </select>
                </label>
              `
              : ""
          }
        </div>
        <div class="chip-row">
          ${chips}
        </div>
      </div>
      <div class="overview-layout">
        <div class="overview-meta-stack">
          <div class="summary-item"><span>Provider</span>${textValue(run.llm_provider ?? "n/a")}</div>
          <div class="summary-item"><span>Model</span>${textValue(run.model_name ?? "n/a")}</div>
          <div class="summary-item"><span>Completed</span>${textValue(completedAt)}</div>
        </div>
        <div class="overview-text-card">
          <p class="overview-text">${escapeHtml(summaryText)}</p>
        </div>
      </div>
      <div class="overview-actions">
        <a class="link-button link-button-llm overview-open-button" href="/portal/runs/${run.run_id}">Open Run</a>
      </div>
    </div>
  `;
}

export function renderAnalysis(analysis, options = {}) {
  if (!analysis) {
    return `<p class="small-note">No analysis available.</p>`;
  }

  const includeExecutiveSummary = options.includeExecutiveSummary !== false;
  const includeKeyMetadata = options.includeKeyMetadata !== false;

  const facts = (analysis.observed_facts || [])
    .map(
      (fact) => `
        <div class="fact-card">
          <strong class="value-text">${escapeHtml(fact.statement)}</strong>
          ${renderEvidence(fact.evidence)}
        </div>
      `,
    )
    .join("");

  const hypotheses = (analysis.hypotheses || [])
    .map(
      (hypothesis) => `
        <div class="hypothesis-card">
          <div class="panel-heading">
            <strong class="value-text">${escapeHtml(friendlyTokenLabel(hypothesis.label))}</strong>
            ${badge(hypothesis.confidence)}
          </div>
          <p>${escapeHtml(hypothesis.rationale)}</p>
        </div>
      `,
    )
    .join("");

  const investigationNotes = (analysis.investigation_notes || [])
    .map(
      (note) => `
        <li><strong>${escapeHtml(note.topic)}:</strong> ${escapeHtml(note.content)}</li>
      `,
    )
    .join("");

  const sections = [];
  if (includeExecutiveSummary) {
    sections.push(`
      <section class="section-card">
        <div class="section-card-head">
          <h3>Executive Summary</h3>
          ${badge(analysis.risk_level)}
        </div>
        <p class="section-summary-text">${escapeHtml(analysis.executive_summary ?? "n/a")}</p>
      </section>
    `);
  }

  if (includeKeyMetadata) {
    sections.push(`
      <section class="section-card">
        <h3>Key Metadata</h3>
        ${renderKeyMetadata(analysis.key_metadata)}
      </section>
    `);
  }

  sections.push(`
    <section class="section-card">
      <h3>Observed Facts</h3>
      <div class="cards-grid">
        ${facts || `<p class="small-note">No observed facts recorded.</p>`}
      </div>
    </section>

    <section class="section-card">
      <h3>Hypotheses</h3>
      <div class="cards-grid">
        ${hypotheses || `<p class="small-note">No hypotheses recorded.</p>`}
      </div>
    </section>

    <section class="section-card">
      <div class="section-card-head">
        <h3>Classification</h3>
        <div class="chip-row">
          ${badge(friendlyTokenLabel(analysis.possible_classification?.label), analysis.possible_classification?.label)}
        </div>
      </div>
      <p>${escapeHtml(analysis.possible_classification?.rationale ?? "n/a")}</p>
    </section>

    <section class="section-card">
      <h3>Recommended Next Steps</h3>
      <div class="meta-grid">
        <div class="meta-item">
          <span>Immediate</span>
          ${renderList(analysis.recommended_next_steps?.immediate)}
        </div>
        <div class="meta-item">
          <span>Short Term</span>
          ${renderList(analysis.recommended_next_steps?.short_term)}
        </div>
        <div class="meta-item">
          <span>Validation</span>
          ${renderList(analysis.recommended_next_steps?.validation)}
        </div>
      </div>
    </section>

    <section class="section-card">
      <h3>Missing Information</h3>
      ${renderList(analysis.missing_information, "No missing information called out.")}
    </section>

    <section class="section-card">
      <h3>Investigation Notes</h3>
      ${
        investigationNotes
          ? `<ul class="clean-list">${investigationNotes}</ul>`
          : `<p class="small-note">No investigation notes recorded.</p>`
      }
    </section>

    <section class="section-card">
      <h3>Verdict</h3>
      <p>${escapeHtml(analysis.verdict ?? "n/a")}</p>
    </section>
  `);

  return `<div class="analysis-block">${sections.join("")}</div>`;
}

export function renderRunSummary(run) {
  return `
    <div class="meta-flow meta-flow-audit">
      ${renderMetaPill("Run Label", inlineMetadataValue(runLabel(run)))}
      ${renderMetaPill("Run ID", inlineMetadataValue(run.run_id, { mono: true }))}
      ${renderMetaPill("Incident ID", inlineMetadataValue(run.incident_id))}
      ${renderMetaPill("Profile", inlineMetadataValue(run.source_context?.analysis_profile ?? "standard"))}
      ${renderMetaPill("Status", badge(run.status))}
      ${renderMetaPill("Validation", badge(run.validation_status))}
      ${renderMetaPill("Provider", inlineMetadataValue(run.llm_provider ?? "n/a"))}
      ${renderMetaPill("Model", inlineMetadataValue(run.model_name ?? "n/a"))}
      ${renderMetaPill("Created", inlineMetadataValue(prettyDate(run.created_at)))}
      ${renderMetaPill("Completed", inlineMetadataValue(prettyDate(run.completed_at)))}
      ${renderMetaPill("Source Fingerprint", inlineMetadataValue(run.source_fingerprint ?? "n/a", { mono: true }))}
      ${renderMetaPill("Request ID", inlineMetadataValue(run.request_id ?? "n/a", { mono: true }))}
      ${renderMetaPill("Total Duration", inlineMetadataValue(run.timing?.total_duration_ms ? `${run.timing.total_duration_ms} ms` : "n/a"))}
      ${renderMetaPill("LLM Duration", inlineMetadataValue(run.timing?.llm_duration_ms ? `${run.timing.llm_duration_ms} ms` : "n/a"))}
      ${renderMetaPill("Prompt Tokens", inlineMetadataValue(run.usage?.prompt_tokens ?? "n/a"))}
      ${renderMetaPill("Completion Tokens", inlineMetadataValue(run.usage?.completion_tokens ?? "n/a"))}
    </div>
  `;
}

export function renderPayloads(run) {
  const renderPayloadBlock = (title, value) => `
    <details>
      <summary class="payload-summary">
        <span>${escapeHtml(title)}</span>
        <button
          class="payload-copy-button"
          type="button"
          aria-label="Copy ${escapeHtml(title)}"
          title="Copy ${escapeHtml(title)}"
        >
          ${copyIcon()}
        </button>
      </summary>
      <pre>${escapeHtml(JSON.stringify(value ?? null, null, 2))}</pre>
    </details>
  `;

  return `
    ${renderPayloadBlock("Normalized Input", run.normalized_input)}
    ${renderPayloadBlock("Raw LLM Output", run.llm_output)}
    ${renderPayloadBlock("Validated Output", run.validated_output)}
  `;
}

export function readModelPreference() {
  try {
    const value = window.localStorage.getItem(modelPreferenceStorageKey);
    return value ? JSON.parse(value) : null;
  } catch {
    return null;
  }
}

export function readAnalysisProfilePreference() {
  try {
    return window.localStorage.getItem(analysisProfileStorageKey) || null;
  } catch {
    return null;
  }
}

export function storeModelPreference(payload) {
  try {
    window.localStorage.setItem(modelPreferenceStorageKey, JSON.stringify(payload));
  } catch {
    // best effort only
  }
}

export function storeAnalysisProfilePreference(profileName) {
  try {
    window.localStorage.setItem(analysisProfileStorageKey, profileName);
  } catch {
    // best effort only
  }
}

export function readEngineSourcePreference() {
  try {
    return window.localStorage.getItem(engineSourceStorageKey) || null;
  } catch {
    return null;
  }
}

export function storeEngineSourcePreference(source) {
  try {
    window.localStorage.setItem(engineSourceStorageKey, source);
  } catch {
    // best effort only
  }
}

export function readPrivateEnginePreference() {
  try {
    const value = window.localStorage.getItem(privateEnginePreferenceStorageKey);
    return value ? JSON.parse(value) : null;
  } catch {
    return null;
  }
}

export function storePrivateEnginePreference(payload) {
  try {
    window.localStorage.setItem(privateEnginePreferenceStorageKey, JSON.stringify(payload));
  } catch {
    // best effort only
  }
}

export async function loadModelSelector(selectElement, profileElement = null) {
  if (!selectElement && !profileElement) {
    return null;
  }

  const payload = await fetchJson("/analysis/models");
  const options = payload.options || [];
  const preferred = readModelPreference();
  const defaultOption = preferred
    ? options.find(
        (option) =>
          option.provider === preferred.provider && option.model_name === preferred.model_name,
      )
    : null;
  const selected = defaultOption || payload.default || options[0] || null;

  if (selectElement) {
    selectElement.innerHTML = options.length
      ? options
          .map(
            (option) => `
              <option value="${escapeHtml(`${option.provider}|${option.model_name}`)}" ${
                selected &&
                option.provider === selected.provider &&
                option.model_name === selected.model_name
                  ? "selected"
                  : ""
              }>
                ${escapeHtml(option.label)}
              </option>
            `,
          )
          .join("")
      : `<option value="">Default configured model</option>`;

    selectElement.addEventListener("change", () => {
      const [provider, model_name] = (selectElement.value || "").split("|");
      if (provider && model_name) {
        storeModelPreference({ provider, model_name });
      }
    });
  }

  const profiles = payload.analysis_profiles || [];
  const preferredProfileName = readAnalysisProfilePreference();
  const selectedProfileName =
    (preferredProfileName &&
      profiles.find((profile) => profile.name === preferredProfileName)?.name) ||
    payload.default_profile ||
    profiles[0]?.name ||
    "standard";

  if (profileElement) {
    profileElement.innerHTML = profiles.length
      ? profiles
          .map(
            (profile) => `
              <option value="${escapeHtml(profile.name)}" ${
                profile.name === selectedProfileName ? "selected" : ""
              }>
                ${escapeHtml(profile.label)}
              </option>
            `,
          )
          .join("")
      : `<option value="standard">Standard</option>`;

    profileElement.addEventListener("change", () => {
      if (profileElement.value) {
        storeAnalysisProfilePreference(profileElement.value);
      }
    });
  }

  if (selected) {
    storeModelPreference({
      provider: selected.provider,
      model_name: selected.model_name,
    });
  }
  if (selectedProfileName) {
    storeAnalysisProfilePreference(selectedProfileName);
  }

  return {
    selected,
    options,
    defaultOption: payload.default || null,
    selectedProfileName,
    profiles,
    capabilities: payload.capabilities || {},
  };
}

export function selectedModelPayload(selectElement, profileElement = null) {
  const selectedProfile =
    profileElement?.value || readAnalysisProfilePreference() || "standard";
  const engineSource = readEngineSourcePreference() || "public";

  if (engineSource === "private") {
    const privatePreference = readPrivateEnginePreference();
    return {
      provider: privatePreference?.provider || "ollama",
      model_name: privatePreference?.model_name || null,
      analysis_profile: selectedProfile,
    };
  }

  const selectedValue = selectElement?.value || "";
  if (!selectedValue) {
    const preferred = readModelPreference();
    return {
      provider: preferred?.provider || "auto",
      model_name: preferred?.model_name || null,
      analysis_profile: selectedProfile,
    };
  }

  const [provider, model_name] = selectedValue.split("|");
  return {
    provider: provider || "auto",
    model_name: model_name || null,
    analysis_profile: selectedProfile,
  };
}
