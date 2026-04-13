import {
  badge,
  clearState,
  escapeHtml,
  fetchJson,
  hide,
  postJson,
  prettyDate,
  readAnalysisProfilePreference,
  readEngineSourcePreference,
  readModelPreference,
  readPrivateEnginePreference,
  selectedModelPayload,
  setState,
  show,
  storeAnalysisProfilePreference,
  storeEngineSourcePreference,
  storeModelPreference,
  storePrivateEnginePreference,
} from "/portal/static/shared.js";

const tableWrap = document.getElementById("incidents-table");
const state = document.getElementById("incidents-state");
const countChip = document.getElementById("incident-count");
const selectedChip = document.getElementById("selected-count");
const orgChip = document.getElementById("org-chip");
const searchInput = document.getElementById("incident-search");
const classificationFilter = document.getElementById("classification-filter");
const severityFilter = document.getElementById("severity-filter");
const certificateFilter = document.getElementById("certificate-filter");
const analysisFilter = document.getElementById("analysis-filter");
const resultsSummary = document.getElementById("results-summary");
const clearFiltersButton = document.getElementById("clear-filters-button");
const loadMoreWrap = document.getElementById("incidents-load-more");
const loadMoreButton = document.getElementById("load-more-button");
const settingsButton = document.getElementById("settings-button");
const analyzeSelectedButton = document.getElementById("analyze-selected-button");
const clearSelectionButton = document.getElementById("clear-selection-button");
const bulkBanner = document.getElementById("bulk-banner");

const settingsDialog = document.getElementById("settings-dialog");
const settingsForm = document.getElementById("settings-form");
const settingsMessage = document.getElementById("settings-message");
const settingsEngineSourcePublic = document.getElementById("settings-engine-source-public");
const settingsEngineSourcePrivate = document.getElementById("settings-engine-source-private");
const settingsEngineSummary = document.getElementById("settings-engine-summary");
const settingsPublicEngineBlock = document.getElementById("settings-public-engine-block");
const settingsPrivateEngineBlock = document.getElementById("settings-private-engine-block");
const settingsPrivateEngineActions = document.getElementById("settings-private-engine-actions");
const settingsPublicProviderSelector = document.getElementById("settings-public-provider-selector");
const settingsPublicModelSelector = document.getElementById("settings-public-model-selector");
const settingsProfileSelector = document.getElementById("settings-profile-selector");
const settingsPrivateProfileSelector = document.getElementById("settings-private-profile-selector");
const settingsLlmProviderSelector = document.getElementById("settings-llm-provider-selector");
const settingsLlmServerUrl = document.getElementById("settings-llm-server-url");
const settingsLlmServerModel = document.getElementById("settings-llm-server-model");
const settingsHost = document.getElementById("settings-host");
const settingsOrg = document.getElementById("settings-org");
const settingsUser = document.getElementById("settings-user");
const settingsPass = document.getElementById("settings-pass");
const settingsTestButton = document.getElementById("settings-test-button");
const settingsTestLlmButton = document.getElementById("settings-test-llm-button");
const settingsResetAvailable = document.getElementById("settings-reset-available");
const settingsResetWarningPanel = document.getElementById("settings-reset-warning-panel");
const settingsResetUnavailable = document.getElementById("settings-reset-unavailable");
const settingsResetToggleButton = document.getElementById("settings-reset-toggle-button");
const settingsResetConfirmation = document.getElementById("settings-reset-confirmation");
const settingsResetConfirmButton = document.getElementById("settings-reset-confirm-button");
const settingsResetCancelButton = document.getElementById("settings-reset-cancel-button");
const settingsCancelButton = document.getElementById("settings-cancel-button");
const settingsSaveButton = document.getElementById("settings-save-button");

const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 300;
const DEFAULT_CLASSIFICATION_OPTIONS = ["Malicious", "Suspicious", "Inconclusive", "PUP"];
const DEFAULT_SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
const CERTIFICATE_OPTIONS = [
  { value: "signed", label: "Signed" },
  { value: "unsigned", label: "Unsigned" },
  { value: "unknown", label: "Unknown" },
];
const ANALYSIS_OPTIONS = [
  { value: "success", label: "Analyzed" },
  { value: "running", label: "Running" },
  { value: "failed", label: "Failed" },
  { value: "not_analyzed", label: "Not analyzed" },
];
const SEVERITY_RANKS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};
const CERTIFICATE_RANKS = {
  signed: 2,
  unsigned: 1,
  unknown: 0,
};
const ANALYSIS_RANKS = {
  success: 3,
  running: 2,
  failed: 1,
  not_analyzed: 0,
};
const SORTABLE_COLUMNS = {
  incident_id: { label: "Incident", defaultDirection: "desc" },
  process: { label: "Process", defaultDirection: "asc" },
  host: { label: "Host", defaultDirection: "asc" },
  severity: { label: "Severity", defaultDirection: "desc" },
  classification: { label: "Classification", defaultDirection: "asc" },
  rules: { label: "EDR Rule", defaultDirection: "asc" },
  certificate: { label: "Certificate", defaultDirection: "desc" },
  analysis: { label: "Analysis", defaultDirection: "desc" },
  last_seen: { label: "Last Seen", defaultDirection: "desc" },
};

let incidents = [];
let allowDatabaseReset = false;
let settingsLoaded = false;
const selectedIncidentIds = new Set();
let pollTimer = null;
let searchTimer = null;
let currentPageNumber = 0;
let hasMoreIncidents = false;
let activeRequestToken = 0;
let publicModelOptions = [];
let privateModelOptions = [];
let sortState = {
  key: "last_seen",
  direction: "desc",
};

function currentSearchQuery() {
  return String(searchInput?.value || "").trim();
}

function currentClassification() {
  return String(classificationFilter?.value || "").trim();
}

function currentSeverity() {
  return String(severityFilter?.value || "").trim();
}

function currentCertificate() {
  return String(certificateFilter?.value || "").trim();
}

function currentAnalysisFilter() {
  return String(analysisFilter?.value || "").trim();
}

function hasActiveDropdownFilters() {
  return Boolean(
    currentClassification() ||
      currentSeverity() ||
      currentCertificate() ||
      currentAnalysisFilter(),
  );
}

function hasActiveFilters() {
  return Boolean(
    currentSearchQuery() ||
      currentClassification() ||
      currentSeverity() ||
      currentCertificate() ||
      currentAnalysisFilter(),
  );
}

function currentResultLabel() {
  return hasActiveFilters() ? "results" : "incidents";
}

function currentEngineSource() {
  return settingsEngineSourcePrivate?.checked ? "private" : "public";
}

function normalizeToken(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll(/[^\w]+/g, "_")
    .replaceAll(/^_+|_+$/g, "");
}

function parseIncidentTimestamp(value) {
  if (!value) {
    return null;
  }
  const raw = String(value).trim();
  const normalized =
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw) ? raw.replace(" ", "T") + "Z" : raw;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed.getTime();
}

function incidentLastSeenValue(incident) {
  return incident?.last_seen || incident?.first_seen || null;
}

function certificateFilterValue(incident) {
  return normalizeToken(incident?.signature_status) || "unknown";
}

function analysisFilterValue(analysis) {
  if (!analysis?.exists) {
    return "not_analyzed";
  }
  if (analysis?.status === "success") {
    return "success";
  }
  if (analysis?.status === "running") {
    return "running";
  }
  return "failed";
}

function buildAnalysisSortValue(incident) {
  const status = analysisFilterValue(incident.analysis);
  const timestamp = parseIncidentTimestamp(
    incident.analysis?.completed_at || incident.analysis?.created_at || null,
  );
  return {
    rank: ANALYSIS_RANKS[status] ?? 0,
    timestamp: timestamp ?? 0,
  };
}

function labelForOption(options, value) {
  const matched = options.find((option) => option.value === value);
  return matched?.label || value;
}

function setFilterActiveState(selectElement) {
  if (!selectElement) {
    return;
  }
  selectElement.classList.toggle("is-active", Boolean(selectElement.value));
  updateFilterResetButton();
}

function setSelectOptions(selectElement, values, currentValue = "") {
  if (!selectElement) {
    return;
  }

  const renderedOptions = [];
  const seen = new Set();
  const normalizedCurrentValue = String(currentValue || "").trim();

  renderedOptions.push('<option value="">Any</option>');
  for (const entry of values) {
    const option = typeof entry === "string" ? { value: entry, label: entry } : entry;
    const value = String(option?.value || "").trim();
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    renderedOptions.push(`
      <option value="${escapeHtml(value)}" ${value === normalizedCurrentValue ? "selected" : ""}>
        ${escapeHtml(option.label || value)}
      </option>
    `);
  }

  if (normalizedCurrentValue && !seen.has(normalizedCurrentValue)) {
    renderedOptions.push(`
      <option value="${escapeHtml(normalizedCurrentValue)}" selected>
        ${escapeHtml(normalizedCurrentValue)}
      </option>
    `);
  }

  selectElement.innerHTML = renderedOptions.join("");
  selectElement.value = normalizedCurrentValue;
  setFilterActiveState(selectElement);
}

function mergeFilterOptions(defaultValues, incidentValues, currentValue = "") {
  const merged = [];
  const seen = new Set();
  for (const value of [...defaultValues, ...incidentValues, currentValue]) {
    const rendered = String(value || "").trim();
    if (!rendered || seen.has(rendered)) {
      continue;
    }
    seen.add(rendered);
    merged.push(rendered);
  }
  return merged;
}

function syncFilterOptions() {
  const classificationValues = mergeFilterOptions(
    DEFAULT_CLASSIFICATION_OPTIONS,
    incidents.map((incident) => incident.classification),
    currentClassification(),
  );
  const severityValues = mergeFilterOptions(
    DEFAULT_SEVERITY_OPTIONS,
    incidents.map((incident) => incident.severity),
    currentSeverity(),
  );

  setSelectOptions(classificationFilter, classificationValues, currentClassification());
  setSelectOptions(severityFilter, severityValues, currentSeverity());
  setSelectOptions(certificateFilter, CERTIFICATE_OPTIONS, currentCertificate());
  setSelectOptions(analysisFilter, ANALYSIS_OPTIONS, currentAnalysisFilter());
  updateFilterResetButton();
}

function compareNullableText(leftValue, rightValue) {
  const left = String(leftValue || "").trim().toLowerCase();
  const right = String(rightValue || "").trim().toLowerCase();
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" });
}

function compareIncidents(leftIncident, rightIncident, sortKey) {
  switch (sortKey) {
    case "incident_id":
      return Number(leftIncident.incident_id || 0) - Number(rightIncident.incident_id || 0);
    case "process":
      return compareNullableText(leftIncident.process, rightIncident.process);
    case "host":
      return compareNullableText(leftIncident.host, rightIncident.host);
    case "severity":
      return (
        (SEVERITY_RANKS[normalizeToken(leftIncident.severity)] ?? 0) -
        (SEVERITY_RANKS[normalizeToken(rightIncident.severity)] ?? 0)
      );
    case "classification":
      return compareNullableText(leftIncident.classification, rightIncident.classification);
    case "rules":
      return compareNullableText(
        (leftIncident.rules || []).join(" | "),
        (rightIncident.rules || []).join(" | "),
      );
    case "certificate":
      return (
        (CERTIFICATE_RANKS[certificateFilterValue(leftIncident)] ?? 0) -
        (CERTIFICATE_RANKS[certificateFilterValue(rightIncident)] ?? 0)
      );
    case "analysis": {
      const left = buildAnalysisSortValue(leftIncident);
      const right = buildAnalysisSortValue(rightIncident);
      if (left.rank !== right.rank) {
        return left.rank - right.rank;
      }
      return left.timestamp - right.timestamp;
    }
    case "last_seen":
      return (
        (parseIncidentTimestamp(incidentLastSeenValue(leftIncident)) ?? 0) -
        (parseIncidentTimestamp(incidentLastSeenValue(rightIncident)) ?? 0)
      );
    default:
      return 0;
  }
}

function sortIncidents(items) {
  const directionMultiplier = sortState.direction === "asc" ? 1 : -1;
  return [...items].sort((leftIncident, rightIncident) => {
    const primaryComparison =
      compareIncidents(leftIncident, rightIncident, sortState.key) * directionMultiplier;
    if (primaryComparison !== 0) {
      return primaryComparison;
    }
    return Number(rightIncident.incident_id || 0) - Number(leftIncident.incident_id || 0);
  });
}

function incidentMatchesFilters(incident) {
  if (currentCertificate() && certificateFilterValue(incident) !== currentCertificate()) {
    return false;
  }
  if (currentAnalysisFilter() && analysisFilterValue(incident.analysis) !== currentAnalysisFilter()) {
    return false;
  }
  return true;
}

function visibleIncidents() {
  return sortIncidents(incidents.filter((incident) => incidentMatchesFilters(incident)));
}

function sortIcon(sortKey) {
  if (sortState.key !== sortKey) {
    return "↕";
  }
  return sortState.direction === "asc" ? "↑" : "↓";
}

function renderSortableHeader(sortKey, label, className = "") {
  const active = sortState.key === sortKey;
  return `
    <th class="${className}">
      <button
        class="table-sort-button ${active ? "is-active" : ""}"
        type="button"
        data-sort-key="${sortKey}"
        aria-label="Sort by ${escapeHtml(label)}"
      >
        <span>${escapeHtml(label)}</span>
        <span class="sort-icon" aria-hidden="true">${sortIcon(sortKey)}</span>
      </button>
    </th>
  `;
}

function setBanner(message, type = "") {
  bulkBanner.innerHTML = message;
  bulkBanner.className = `banner ${type}`.trim();
  show(bulkBanner);
}

function setSettingsMessage(message, type = "") {
  settingsMessage.innerHTML = `
    <div class="banner-message">${escapeHtml(message)}</div>
    <button class="banner-close" type="button" aria-label="Dismiss message">×</button>
  `;
  settingsMessage.className = `banner banner-dismissible ${type}`.trim();
  show(settingsMessage);
}

function clearSettingsMessage() {
  settingsMessage.innerHTML = "";
  settingsMessage.className = "banner hidden";
  hide(settingsMessage);
}

function resetDatabaseWarningUi() {
  hide(settingsResetConfirmation);
  hide(settingsResetWarningPanel);
  show(settingsResetToggleButton);
}

function stopIncidentsPolling() {
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
}

function stopSearchDebounce() {
  if (searchTimer) {
    window.clearTimeout(searchTimer);
    searchTimer = null;
  }
}

function updateResultsSummary() {
  if (!resultsSummary) {
    return;
  }

  if (currentSearchQuery()) {
    resultsSummary.textContent = "Search results";
    return;
  }
  resultsSummary.textContent = "Recent incidents";
}

function updateFilterResetButton() {
  if (!clearFiltersButton) {
    return;
  }
  if (hasActiveDropdownFilters()) {
    show(clearFiltersButton);
    return;
  }
  hide(clearFiltersButton);
}

function scheduleIncidentsPolling() {
  stopIncidentsPolling();
  if (currentPageNumber > 0) {
    return;
  }
  if (!incidents.some((incident) => incident.analysis?.status === "running")) {
    return;
  }

  const poll = async () => {
    try {
      await loadIncidents({ schedulePolling: false });
      if (currentPageNumber === 0 && incidents.some((incident) => incident.analysis?.status === "running")) {
        pollTimer = window.setTimeout(poll, 2000);
      } else {
        stopIncidentsPolling();
      }
    } catch {
      pollTimer = window.setTimeout(poll, 4000);
    }
  };

  pollTimer = window.setTimeout(poll, 2000);
}

function analysisBadge(analysis) {
  if (!analysis?.exists) {
    return badge("Not analyzed", "", { tone: "neutral" });
  }
  const label =
    analysis.status === "success"
      ? "Analyzed"
      : analysis.status === "running"
        ? "Running"
        : "Analysis failed";
  const tone =
    analysis.status === "success"
      ? "ok"
      : analysis.status === "running"
        ? "info"
        : "danger";

  return `
    <div class="analysis-status">
      ${badge(label, "", { tone })}
      <span class="small-note">${escapeHtml(prettyDate(analysis.completed_at || analysis.created_at))}</span>
    </div>
  `;
}

function renderRuleLines(rules) {
  if (!rules?.length) {
    return `<span class="table-empty">—</span>`;
  }
  return `
    <div class="table-rule-list">
      ${rules
        .map(
          (rule) =>
            `<div class="table-rule-line" title="${escapeHtml(rule)}">${escapeHtml(rule)}</div>`,
        )
        .join("")}
    </div>
  `;
}

function signatureBadge(signatureStatus) {
  if (signatureStatus === "signed") {
    return `<img class="certificate-icon" src="/portal/static/signed.svg" alt="Signed" title="Signed" />`;
  }
  if (signatureStatus === "unsigned") {
    return `<img class="certificate-icon" src="/portal/static/unsigned.svg" alt="Unsigned" title="Unsigned" />`;
  }
  return `<span class="certificate-icon-placeholder" title="Unknown certificate status">—</span>`;
}

function updateLoadMoreUi({ loading = false } = {}) {
  if (!loadMoreWrap || !loadMoreButton) {
    return;
  }

  if (!incidents.length || !hasMoreIncidents) {
    hide(loadMoreWrap);
    return;
  }

  loadMoreButton.disabled = loading;
  loadMoreButton.textContent = loading ? `Loading ${PAGE_SIZE}...` : `Load ${PAGE_SIZE} More`;
  show(loadMoreWrap);
}

function updateSelectionUi(currentVisibleIncidents = visibleIncidents()) {
  const selectedCount = selectedIncidentIds.size;
  const visibleCount = currentVisibleIncidents.length;
  const loadedCount = incidents.length;
  selectedChip.textContent = `${selectedCount} selected`;
  if (visibleCount !== loadedCount) {
    countChip.textContent = hasMoreIncidents
      ? `${visibleCount} of ${loadedCount} ${currentResultLabel()} loaded`
      : `${visibleCount} of ${loadedCount} ${currentResultLabel()}`;
  } else {
    countChip.textContent = hasMoreIncidents
      ? `${loadedCount} ${currentResultLabel()} loaded`
      : `${loadedCount} ${currentResultLabel()}`;
  }
  analyzeSelectedButton.disabled = selectedCount === 0;
  clearSelectionButton.disabled = selectedCount === 0;
}

function renderTable() {
  const renderedIncidents = visibleIncidents();
  updateResultsSummary();

  if (!renderedIncidents.length) {
    hide(tableWrap);
    setState(
      state,
      incidents.length
        ? "No loaded incidents match the current filters."
        : hasActiveFilters()
          ? "No incidents match the current server-side filters."
          : "No incidents returned by the backend.",
    );
    updateSelectionUi(renderedIncidents);
    updateLoadMoreUi();
    return;
  }

  clearState(state);
  tableWrap.innerHTML = `
    <table>
      <thead>
        <tr>
          <th class="checkbox-col"><input id="select-visible-checkbox" type="checkbox" ${
            renderedIncidents.length > 0 &&
            renderedIncidents.every((incident) => selectedIncidentIds.has(String(incident.incident_id)))
              ? "checked"
              : ""
          } /></th>
          ${renderSortableHeader("incident_id", "Incident")}
          ${renderSortableHeader("process", "Process")}
          ${renderSortableHeader("host", "Host")}
          ${renderSortableHeader("severity", "Severity")}
          ${renderSortableHeader("classification", "Classification")}
          ${renderSortableHeader("rules", "EDR Rule")}
          ${renderSortableHeader("certificate", "Certificate")}
          ${renderSortableHeader("analysis", "Analysis")}
          ${renderSortableHeader("last_seen", "Last Seen")}
        </tr>
      </thead>
      <tbody>
        ${renderedIncidents
          .map(
            (incident) => `
              <tr>
                <td class="checkbox-col">
                  <input class="incident-selector" type="checkbox" data-incident-id="${incident.incident_id}" ${
                    selectedIncidentIds.has(String(incident.incident_id)) ? "checked" : ""
                  } />
                </td>
                <td><a href="/portal/incidents/${incident.incident_id}">${escapeHtml(incident.incident_id)}</a></td>
                <td><span class="table-value" title="${escapeHtml(incident.process ?? "n/a")}">${escapeHtml(incident.process ?? "n/a")}</span></td>
                <td>${escapeHtml(incident.host ?? "n/a")}</td>
                <td>${badge(incident.severity)}</td>
                <td>${badge(incident.classification)}</td>
                <td>${renderRuleLines(incident.rules)}</td>
                <td>${signatureBadge(incident.signature_status)}</td>
                <td>${analysisBadge(incident.analysis)}</td>
                <td>${escapeHtml(prettyDate(incidentLastSeenValue(incident)))}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
  show(tableWrap);
  updateSelectionUi(renderedIncidents);
  updateLoadMoreUi();

  for (const checkbox of tableWrap.querySelectorAll(".incident-selector")) {
    checkbox.addEventListener("change", (event) => {
      const incidentId = event.currentTarget.dataset.incidentId;
      if (event.currentTarget.checked) {
        selectedIncidentIds.add(incidentId);
      } else {
        selectedIncidentIds.delete(incidentId);
      }
      updateSelectionUi();
      renderTable();
    });
  }

  for (const sortButton of tableWrap.querySelectorAll(".table-sort-button")) {
    sortButton.addEventListener("click", (event) => {
      const nextSortKey = event.currentTarget.dataset.sortKey;
      if (!nextSortKey || !SORTABLE_COLUMNS[nextSortKey]) {
        return;
      }
      if (sortState.key === nextSortKey) {
        sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
      } else {
        sortState = {
          key: nextSortKey,
          direction: SORTABLE_COLUMNS[nextSortKey].defaultDirection || "asc",
        };
      }
      renderTable();
    });
  }

  tableWrap.querySelector("#select-visible-checkbox")?.addEventListener("change", (event) => {
    if (event.currentTarget.checked) {
      renderedIncidents.forEach((incident) => selectedIncidentIds.add(String(incident.incident_id)));
    } else {
      renderedIncidents.forEach((incident) => selectedIncidentIds.delete(String(incident.incident_id)));
    }
    renderTable();
  });
}

function buildIncidentsUrl(pageNumber) {
  const params = new URLSearchParams({
    page_number: String(pageNumber),
    items_per_page: String(PAGE_SIZE),
  });
  const query = currentSearchQuery();
  const classification = currentClassification();
  const severity = currentSeverity();

  if (query) {
    params.set("query", query);
  }
  if (classification) {
    params.set("classification", classification);
  }
  if (severity) {
    params.set("severity", severity);
  }

  return `/incidents?${params.toString()}`;
}

function mergeIncidents(existing, incoming) {
  const byIncidentId = new Map(existing.map((incident) => [String(incident.incident_id), incident]));
  for (const incident of incoming) {
    byIncidentId.set(String(incident.incident_id), incident);
  }
  return Array.from(byIncidentId.values());
}

function providerLabel(provider) {
  if (provider === "openai") {
    return "OpenAI";
  }
  if (provider === "anthropic") {
    return "Anthropic";
  }
  if (provider === "ollama") {
    return "Ollama";
  }
  return provider || "n/a";
}

function normalizeServerDisplay(url) {
  if (!url) {
    return "";
  }
  try {
    const parsed = new URL(url);
    return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  } catch {
    return url.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  }
}

function uniqueProviders(options) {
  return Array.from(
    new Set(
      (options || [])
        .map((option) => String(option.provider || "").trim())
        .filter(Boolean),
    ),
  );
}

function selectedProfileName() {
  const primary = currentEngineSource() === "private" ? settingsPrivateProfileSelector : settingsProfileSelector;
  return primary?.value || readAnalysisProfilePreference() || "standard";
}

function syncProfileSelectors(sourceElement) {
  const nextValue = sourceElement?.value || readAnalysisProfilePreference() || "standard";
  if (settingsProfileSelector && settingsProfileSelector !== sourceElement) {
    settingsProfileSelector.value = nextValue;
  }
  if (settingsPrivateProfileSelector && settingsPrivateProfileSelector !== sourceElement) {
    settingsPrivateProfileSelector.value = nextValue;
  }
  if (nextValue) {
    storeAnalysisProfilePreference(nextValue);
  }
}

function populateProfileSelector(selectElement, profiles, selectedName) {
  if (!selectElement) {
    return;
  }

  const nextProfiles = profiles?.length
    ? profiles
    : [{ name: "standard", label: "Standard", description: "" }];
  const nextSelectedName =
    nextProfiles.find((profile) => profile.name === selectedName)?.name ||
    nextProfiles[0]?.name ||
    "standard";

  selectElement.innerHTML = nextProfiles
    .map(
      (profile) => `
        <option value="${escapeHtml(profile.name)}" ${profile.name === nextSelectedName ? "selected" : ""}>
          ${escapeHtml(profile.label)}
        </option>
      `,
    )
    .join("");
  selectElement.disabled = nextProfiles.length === 0;
}

function populatePrivateModelOptions(preferredModelName = null) {
  if (!settingsLlmServerModel) {
    return null;
  }

  const options = [];
  const seen = new Set();
  for (const option of privateModelOptions) {
    const modelName = String(option.model_name || "").trim();
    if (!modelName || seen.has(modelName)) {
      continue;
    }
    seen.add(modelName);
    options.push(modelName);
  }

  const fallbackModelName = String(preferredModelName || settingsLlmServerModel.value || "").trim();
  if (fallbackModelName && !seen.has(fallbackModelName)) {
    options.unshift(fallbackModelName);
  }

  if (!options.length) {
    settingsLlmServerModel.innerHTML = '<option value="">No private model discovered</option>';
    settingsLlmServerModel.disabled = true;
    return null;
  }

  const selectedModelName = options.find((modelName) => modelName === preferredModelName) || options[0];
  settingsLlmServerModel.innerHTML = options
    .map(
      (modelName) => `
        <option value="${escapeHtml(modelName)}" ${modelName === selectedModelName ? "selected" : ""}>
          ${escapeHtml(modelName)}
        </option>
      `,
    )
    .join("");
  settingsLlmServerModel.disabled = false;
  settingsLlmServerModel.value = selectedModelName;
  return selectedModelName;
}

function populatePublicModelSelector(preferredModelName = null) {
  const provider = settingsPublicProviderSelector?.value || "";
  const options = publicModelOptions.filter((option) => option.provider === provider);
  const preferred = readModelPreference();
  const selectedOption =
    options.find((option) => option.model_name === preferredModelName) ||
    options.find(
      (option) =>
        preferred &&
        option.provider === preferred.provider &&
        option.model_name === preferred.model_name,
    ) ||
    options[0] ||
    null;

  if (!settingsPublicModelSelector) {
    return selectedOption;
  }

  if (!options.length) {
    settingsPublicModelSelector.innerHTML = '<option value="">No public model available</option>';
    settingsPublicModelSelector.disabled = true;
    return null;
  }

  settingsPublicModelSelector.innerHTML = options
    .map(
      (option) => `
        <option value="${escapeHtml(option.model_name)}" ${
          selectedOption?.model_name === option.model_name ? "selected" : ""
        }>
          ${escapeHtml(option.model_name)}
        </option>
      `,
    )
    .join("");
  settingsPublicModelSelector.disabled = false;
  return selectedOption;
}

function populatePublicSelectors(preferredProvider = null, preferredModelName = null) {
  const providers = uniqueProviders(publicModelOptions);
  const preferred = readModelPreference();
  const selectedProvider =
    providers.find((provider) => provider === preferredProvider) ||
    providers.find((provider) => preferred && provider === preferred.provider) ||
    providers[0] ||
    "";

  if (settingsPublicProviderSelector) {
    if (!providers.length) {
      settingsPublicProviderSelector.innerHTML = '<option value="">No public provider configured</option>';
      settingsPublicProviderSelector.disabled = true;
    } else {
      settingsPublicProviderSelector.innerHTML = providers
        .map(
          (provider) => `
            <option value="${escapeHtml(provider)}" ${provider === selectedProvider ? "selected" : ""}>
              ${escapeHtml(providerLabel(provider))}
            </option>
          `,
        )
        .join("");
      settingsPublicProviderSelector.disabled = false;
      settingsPublicProviderSelector.value = selectedProvider;
    }
  }

  return populatePublicModelSelector(preferredModelName);
}

function updateEngineSummary() {
  if (!settingsEngineSummary) {
    return;
  }

  if (currentEngineSource() === "private") {
    const provider = settingsLlmProviderSelector?.value || "ollama";
    const modelName = settingsLlmServerModel?.value.trim() || privateModelOptions[0]?.model_name || "n/a";
    const server = normalizeServerDisplay(settingsLlmServerUrl?.value.trim() || "");
    settingsEngineSummary.textContent = server
      ? `Current engine: ${providerLabel(provider)} / ${modelName} @ ${server}`
      : `Current engine: ${providerLabel(provider)} / ${modelName}`;
    return;
  }

  const provider = settingsPublicProviderSelector?.value || "";
  const modelName = settingsPublicModelSelector?.value || "";
  settingsEngineSummary.textContent =
    provider && modelName
      ? `Current engine: ${providerLabel(provider)} / ${modelName}`
      : "Current engine: no public model configured";
}

function applyEngineSourceUi() {
  const privateMode = currentEngineSource() === "private";
  if (privateMode) {
    show(settingsPrivateEngineBlock);
    show(settingsPrivateEngineActions);
    hide(settingsPublicEngineBlock);
  } else {
    show(settingsPublicEngineBlock);
    hide(settingsPrivateEngineBlock);
    hide(settingsPrivateEngineActions);
  }
  if (settingsTestLlmButton) {
    settingsTestLlmButton.hidden = !privateMode;
  }
  updateEngineSummary();
}

function settingsPayload() {
  const availablePrivateModels = Array.from(
    new Set(
      privateModelOptions
        .map((option) => String(option.model_name || "").trim())
        .filter(Boolean),
    ),
  );
  return {
    host: settingsHost.value.trim(),
    organization: settingsOrg.value.trim(),
    user: settingsUser.value.trim(),
    password: settingsPass.value,
    engine_source: currentEngineSource(),
    llm_server_provider: settingsLlmProviderSelector.value,
    llm_server_url: settingsLlmServerUrl.value.trim(),
    llm_server_model: settingsLlmServerModel.value.trim(),
    llm_server_available_models: availablePrivateModels.join(","),
  };
}

function setSettingsLoading(isLoading) {
  settingsTestButton.disabled = isLoading;
  settingsTestLlmButton.disabled = isLoading;
  settingsSaveButton.disabled = isLoading;
  settingsCancelButton.disabled = isLoading;
  if (!settingsResetToggleButton.classList.contains("hidden")) {
    settingsResetToggleButton.disabled = isLoading;
    settingsResetConfirmButton.disabled = isLoading;
    settingsResetCancelButton.disabled = isLoading;
  }
}

async function loadSettings() {
  const [settings, modelData] = await Promise.all([fetchJson("/settings"), fetchJson("/analysis/models")]);

  publicModelOptions = modelData?.public_options || [];
  privateModelOptions = modelData?.private_options || [];
  allowDatabaseReset = Boolean(modelData?.capabilities?.allow_db_reset);
  if (allowDatabaseReset) {
    show(settingsResetAvailable);
    hide(settingsResetUnavailable);
  } else {
    hide(settingsResetAvailable);
    show(settingsResetUnavailable);
  }
  resetDatabaseWarningUi();
  settingsHost.value = settings.host || "";
  settingsOrg.value = settings.organization || "";
  settingsUser.value = settings.user || "";
  settingsPass.value = settings.password || "";
  settingsLlmProviderSelector.value = settings.llm_server_provider || "ollama";
  settingsLlmServerUrl.value = settings.llm_server_url || "";

  const preferredPublicModel = readModelPreference();
  populatePublicSelectors(
    preferredPublicModel?.provider || null,
    preferredPublicModel?.model_name || null,
  );

  const availableProfiles = modelData?.analysis_profiles || [];
  const preferredProfile =
    readAnalysisProfilePreference() || modelData?.default_profile || "standard";
  populateProfileSelector(settingsProfileSelector, availableProfiles, preferredProfile);
  populateProfileSelector(settingsPrivateProfileSelector, availableProfiles, preferredProfile);
  syncProfileSelectors(
    currentEngineSource() === "private" ? settingsPrivateProfileSelector : settingsProfileSelector,
  );

  const privatePreference = readPrivateEnginePreference();
  const preferredPrivateModel =
    settings.llm_server_model ||
    privatePreference?.model_name ||
    privateModelOptions[0]?.model_name ||
    "";
  populatePrivateModelOptions(preferredPrivateModel);
  storeEngineSourcePreference(settings.engine_source || modelData?.engine_source || "public");
  if (settings.engine_source === "private") {
    storePrivateEnginePreference({
      provider: settingsLlmProviderSelector.value || "ollama",
      model_name: settingsLlmServerModel.value.trim() || null,
    });
    settingsEngineSourcePrivate.checked = true;
    settingsEngineSourcePublic.checked = false;
  } else {
    settingsEngineSourcePublic.checked = true;
    settingsEngineSourcePrivate.checked = false;
  }

  const selectedPublicProvider = settingsPublicProviderSelector?.value || preferredPublicModel?.provider || null;
  const selectedPublicModel =
    settingsPublicModelSelector?.value || preferredPublicModel?.model_name || null;
  if (selectedPublicProvider && selectedPublicModel) {
    storeModelPreference({
      provider: selectedPublicProvider,
      model_name: selectedPublicModel,
    });
  }

  applyEngineSourceUi();
  settingsLoaded = true;
}

async function openSettings() {
  clearSettingsMessage();
  setSettingsLoading(false);
  settingsButton.disabled = true;
  try {
    await loadSettings();
    settingsDialog.showModal();
  } catch (error) {
    setBanner(error.message, "error");
  } finally {
    settingsButton.disabled = false;
  }
}

async function loadIncidents(options = {}) {
  const append = options.append ?? false;
  const schedulePolling = options.schedulePolling ?? true;
  const pageNumber = append ? currentPageNumber + 1 : 0;
  const requestToken = ++activeRequestToken;

  if (!append) {
    stopIncidentsPolling();
    hide(loadMoreWrap);
    setState(state, "Loading incidents...");
  }
  updateLoadMoreUi({ loading: append });

  try {
    const payload = await fetchJson(buildIncidentsUrl(pageNumber));
    if (requestToken !== activeRequestToken) {
      return;
    }

    const nextIncidents = payload.incidents || [];
    incidents = append ? mergeIncidents(incidents, nextIncidents) : nextIncidents;
    syncFilterOptions();
    currentPageNumber = Number(payload.page_number ?? pageNumber);
    hasMoreIncidents = Boolean(payload.has_more);
    orgChip.textContent = payload.organization || "n/a";
    renderTable();
    if (schedulePolling) {
      scheduleIncidentsPolling();
    }
  } catch (error) {
    if (requestToken !== activeRequestToken) {
      return;
    }

    stopIncidentsPolling();
    if (append) {
      setBanner(error.message, "error");
      updateLoadMoreUi({ loading: false });
      return;
    }

    incidents = [];
    currentPageNumber = 0;
    hasMoreIncidents = false;
    selectedIncidentIds.clear();
    syncFilterOptions();
    hide(tableWrap);
    hide(loadMoreWrap);
    setState(state, error.message);
    countChip.textContent = "Unavailable";
    selectedChip.textContent = "0 selected";
    orgChip.textContent = "n/a";
    updateResultsSummary();
    analyzeSelectedButton.disabled = true;
    clearSelectionButton.disabled = true;
  } finally {
    if (requestToken === activeRequestToken) {
      updateLoadMoreUi({ loading: false });
    }
  }
}

function reloadIncidentsFromFilters() {
  selectedIncidentIds.clear();
  currentPageNumber = 0;
  hasMoreIncidents = false;
  loadIncidents();
}

function scheduleFilteredReload() {
  stopSearchDebounce();
  searchTimer = window.setTimeout(() => {
    reloadIncidentsFromFilters();
  }, SEARCH_DEBOUNCE_MS);
}

async function loadMoreIncidents() {
  if (!hasMoreIncidents || loadMoreButton.disabled) {
    return;
  }
  await loadIncidents({ append: true, schedulePolling: false });
}

async function analyzeSelected() {
  const incidentIds = Array.from(selectedIncidentIds);
  if (!incidentIds.length) {
    return;
  }

  analyzeSelectedButton.disabled = true;
  clearSelectionButton.disabled = true;

  let succeeded = 0;
  let failed = 0;
  for (const [index, incidentId] of incidentIds.entries()) {
    setBanner(`Analyzing ${index + 1}/${incidentIds.length}: incident ${incidentId}...`);
    try {
      await postJson(`/incidents/${incidentId}/analyze`, {
        force: false,
        async_run: true,
        ...selectedModelPayload(),
      });
      succeeded += 1;
    } catch {
      failed += 1;
    }
  }

  await loadIncidents();
  setBanner(
    failed === 0
      ? `Queued ${succeeded} analysis run${succeeded === 1 ? "" : "s"} in background.`
      : `Queued ${succeeded} analysis run${succeeded === 1 ? "" : "s"} in background, ${failed} failed to start.`,
    failed === 0 ? "success" : "error",
  );
  updateSelectionUi();
}

async function clearDatabase() {
  if (!allowDatabaseReset) {
    return;
  }

  setSettingsLoading(true);
  clearSettingsMessage();
  try {
    const payload = await postJson("/analysis/database/clear", {});
    selectedIncidentIds.clear();
    settingsDialog.close();
    setBanner(
      `Cleared ${payload.deleted_runs} persisted analysis run${payload.deleted_runs === 1 ? "" : "s"}.`,
      "success",
    );
    await loadIncidents();
  } catch (error) {
    setSettingsMessage(error.message, "error");
  } finally {
    setSettingsLoading(false);
  }
}

async function testConnection() {
  setSettingsLoading(true);
  clearSettingsMessage();
  try {
    const payload = await postJson("/settings/test-connection", settingsPayload());
    setSettingsMessage(
      `${payload.message} Organization: ${payload.organization || "n/a"}. Sample events: ${payload.sample_count}.`,
      "success",
    );
  } catch (error) {
    setSettingsMessage(error.message, "error");
  } finally {
    setSettingsLoading(false);
  }
}

async function testLlmConnection() {
  setSettingsLoading(true);
  clearSettingsMessage();
  try {
    const payload = await postJson("/settings/test-llm", settingsPayload());
    privateModelOptions = (payload.models || []).map((modelName) => ({
      provider: payload.provider,
      model_name: modelName,
      label: `${providerLabel(payload.provider)} · ${modelName}`,
    }));
    populatePrivateModelOptions(settingsLlmServerModel.value.trim() || payload.models?.[0] || null);
    const summary =
      payload.model_count > 0
        ? `${payload.model_count} model${payload.model_count === 1 ? "" : "s"} discovered.`
        : "No models reported by the remote server.";
    setSettingsMessage(
      `${payload.message} Provider: ${payload.provider}. URL: ${payload.base_url}. ${summary}`,
      "success",
    );
    updateEngineSummary();
  } catch (error) {
    setSettingsMessage(error.message, "error");
  } finally {
    setSettingsLoading(false);
  }
}

async function saveSettings(event) {
  event.preventDefault();
  setSettingsLoading(true);
  clearSettingsMessage();
  try {
    const payload = settingsPayload();
    await postJson("/settings", payload);
    storeEngineSourcePreference(payload.engine_source);
    storeAnalysisProfilePreference(selectedProfileName());
    if (payload.engine_source === "private") {
      storePrivateEnginePreference({
        provider: payload.llm_server_provider || "ollama",
        model_name: payload.llm_server_model || null,
      });
    } else if (settingsPublicProviderSelector?.value && settingsPublicModelSelector?.value) {
      storeModelPreference({
        provider: settingsPublicProviderSelector.value,
        model_name: settingsPublicModelSelector.value,
      });
    }
    settingsDialog.close();
    setBanner("Settings saved. The backend has reloaded FortiEDR and LLM connection settings.", "success");
    await loadIncidents();
  } catch (error) {
    setSettingsMessage(error.message, "error");
  } finally {
    setSettingsLoading(false);
  }
}

clearSelectionButton.addEventListener("click", () => {
  selectedIncidentIds.clear();
  renderTable();
});

analyzeSelectedButton.addEventListener("click", analyzeSelected);
settingsButton.addEventListener("click", openSettings);
settingsTestButton.addEventListener("click", testConnection);
settingsTestLlmButton.addEventListener("click", testLlmConnection);
settingsEngineSourcePublic?.addEventListener("change", () => {
  applyEngineSourceUi();
});
settingsEngineSourcePrivate?.addEventListener("change", () => {
  applyEngineSourceUi();
});
settingsPublicProviderSelector?.addEventListener("change", () => {
  populatePublicModelSelector();
  updateEngineSummary();
});
settingsPublicModelSelector?.addEventListener("change", () => {
  updateEngineSummary();
});
settingsProfileSelector?.addEventListener("change", (event) => {
  syncProfileSelectors(event.currentTarget);
});
settingsPrivateProfileSelector?.addEventListener("change", (event) => {
  syncProfileSelectors(event.currentTarget);
});
settingsLlmProviderSelector?.addEventListener("change", () => {
  updateEngineSummary();
});
settingsLlmServerUrl?.addEventListener("input", () => {
  updateEngineSummary();
});
settingsLlmServerModel?.addEventListener("change", () => {
  updateEngineSummary();
});
settingsResetToggleButton.addEventListener("click", () => {
  hide(settingsResetToggleButton);
  show(settingsResetWarningPanel);
  show(settingsResetConfirmation);
  settingsResetConfirmButton.focus();
});
settingsResetCancelButton.addEventListener("click", () => {
  resetDatabaseWarningUi();
});
settingsResetConfirmButton.addEventListener("click", clearDatabase);
settingsCancelButton.addEventListener("click", () => settingsDialog.close());
settingsForm.addEventListener("submit", saveSettings);
loadMoreButton?.addEventListener("click", loadMoreIncidents);

searchInput?.addEventListener("input", () => {
  scheduleFilteredReload();
});
searchInput?.addEventListener("search", () => {
  scheduleFilteredReload();
});
classificationFilter?.addEventListener("change", () => {
  setFilterActiveState(classificationFilter);
  stopSearchDebounce();
  reloadIncidentsFromFilters();
});
severityFilter?.addEventListener("change", () => {
  setFilterActiveState(severityFilter);
  stopSearchDebounce();
  reloadIncidentsFromFilters();
});
certificateFilter?.addEventListener("change", () => {
  setFilterActiveState(certificateFilter);
  renderTable();
});
analysisFilter?.addEventListener("change", () => {
  setFilterActiveState(analysisFilter);
  renderTable();
});
clearFiltersButton?.addEventListener("click", () => {
  if (classificationFilter) {
    classificationFilter.value = "";
    setFilterActiveState(classificationFilter);
  }
  if (severityFilter) {
    severityFilter.value = "";
    setFilterActiveState(severityFilter);
  }
  if (certificateFilter) {
    certificateFilter.value = "";
    setFilterActiveState(certificateFilter);
  }
  if (analysisFilter) {
    analysisFilter.value = "";
    setFilterActiveState(analysisFilter);
  }
  stopSearchDebounce();
  reloadIncidentsFromFilters();
});

settingsDialog?.addEventListener("close", () => {
  if (settingsLoaded) {
    clearSettingsMessage();
    resetDatabaseWarningUi();
  }
});

settingsMessage?.addEventListener("click", (event) => {
  if (event.target.closest(".banner-close")) {
    clearSettingsMessage();
  }
});

window.addEventListener("beforeunload", () => {
  stopIncidentsPolling();
  stopSearchDebounce();
});

updateResultsSummary();
updateSelectionUi();
syncFilterOptions();
loadIncidents();
