import {
  badge,
  clearState,
  escapeHtml,
  fetchJson,
  postJson,
  prettyDate,
  renderAnalysisOverview,
  renderHashValue,
  runLabel,
  selectedModelPayload,
  setState,
  show,
} from "/portal/static/shared.js";

const incidentId = window.location.pathname.split("/").pop();

const title = document.getElementById("incident-title");
const banner = document.getElementById("incident-banner");
const analyzeButton = document.getElementById("analyze-button");
const analyzeForceButton = document.getElementById("analyze-force-button");
const incidentState = document.getElementById("incident-state");
const incidentMetadata = document.getElementById("incident-metadata");
const latestOverviewState = document.getElementById("latest-overview-state");
const latestOverview = document.getElementById("latest-overview");
const historyState = document.getElementById("history-state");
const historyContainer = document.getElementById("analysis-history");
const runDetailCache = new Map();
let overviewRuns = [];
let selectedOverviewRunId = null;
let pollTimer = null;

function setBanner(message, type = "") {
  banner.innerHTML = message;
  banner.className = `banner ${type}`.trim();
  show(banner);
}

function stopRunPolling() {
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
}

function inlineValue(value, { mono = false, full = false } = {}) {
  const rendered = value == null || value === "" ? "n/a" : String(value);
  return `<span class="meta-pill-value ${mono ? "mono-inline" : ""} ${full ? "meta-pill-value-full" : ""}" title="${escapeHtml(rendered)}">${escapeHtml(rendered)}</span>`;
}

function metaPill(label, content, { wide = false, extraClass = "" } = {}) {
  return `
    <div class="meta-pill ${wide ? "meta-pill-wide" : ""} ${extraClass}">
      <span class="meta-pill-label">${escapeHtml(label)}</span>
      <span class="meta-pill-content">${content}</span>
    </div>
  `;
}

function splitDetailText(value) {
  const rendered = String(value ?? "")
    .replace(/([.!?])(?=[A-Z])/g, "$1\n")
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  const seen = new Set();
  const unique = [];
  for (const line of rendered.length ? rendered : [String(value ?? "").trim()].filter(Boolean)) {
    const key = line.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(line);
  }
  return unique;
}

function renderExpandableTextBlock(title, value) {
  const rendered = String(value ?? "").trim();
  if (!rendered) {
    return "";
  }
  const lines = splitDetailText(rendered);
  const preview = rendered.length > 180 ? `${rendered.slice(0, 180).trimEnd()}…` : rendered;
  return `
    <details class="expandable-note">
      <summary>
        <span>${escapeHtml(title)}</span>
        <span class="expandable-note-toggle">+</span>
      </summary>
      <div class="expandable-note-preview" title="${escapeHtml(rendered)}">${escapeHtml(preview)}</div>
      <div class="expandable-note-body">
        ${lines.map((line) => `<div class="expandable-note-line">${escapeHtml(line)}</div>`).join("")}
      </div>
    </details>
  `;
}

function renderLineCard(title, lines, options = {}) {
  const emptyMessage = options.emptyMessage || "No data available.";
  const wrap = options.wrap === true;
  if (!lines?.length) {
    return `
      <div class="context-card">
        <h3>${escapeHtml(title)}</h3>
        <p class="small-note">${escapeHtml(emptyMessage)}</p>
      </div>
    `;
  }

  return `
    <div class="context-card">
      <h3>${escapeHtml(title)}</h3>
      <div class="line-list">
        ${lines
          .map(
            (line) => `
              <div class="line-item" title="${escapeHtml(line)}">
                <span class="line-item-text ${wrap ? "line-item-text-wrap" : ""}">${escapeHtml(line)}</span>
              </div>
            `,
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderMatchedRulesCard(title, rules, descriptions) {
  const normalizedDescriptions = new Map(
    (descriptions || []).map((entry) => [String(entry.rule_name || "").toLowerCase(), entry]),
  );
  const orderedRules = [];
  const seen = new Set();
  for (const rule of rules || []) {
    const rendered = String(rule || "").trim();
    if (!rendered) {
      continue;
    }
    const key = rendered.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    orderedRules.push(rendered);
  }

  if (!orderedRules.length) {
    return `
      <div class="context-card">
        <h3>${escapeHtml(title)}</h3>
        <p class="small-note">No matched EDR rule labels were available.</p>
      </div>
    `;
  }

  const descriptionBlocks = `
    <div class="policy-description-list">
      ${orderedRules
        .map((ruleName) => {
          const entry = normalizedDescriptions.get(ruleName.toLowerCase());
          return `
            <details class="policy-description-item">
              <summary>
                <span class="policy-description-title">${escapeHtml(ruleName)}</span>
                <span class="expandable-note-toggle">+</span>
              </summary>
              ${
                entry?.policy_name
                  ? `<div class="policy-description-meta">${escapeHtml(entry.policy_name)}</div>`
                  : ""
              }
              ${
                entry?.rule_subtitle
                  ? `<div class="policy-description-subtitle">${escapeHtml(entry.rule_subtitle)}</div>`
                  : ""
              }
              <div class="policy-description-body">
                ${
                  entry?.rule_details
                    ? `<p>${escapeHtml(entry.rule_details)}</p>`
                    : `<p class="small-note">No additional details available.</p>`
                }
                ${
                  entry?.forensics_recommendations
                    ? `<div class="policy-description-reco"><strong>Forensics Recommendations</strong><p>${escapeHtml(entry.forensics_recommendations)}</p></div>`
                    : ""
                }
              </div>
            </details>
          `;
        })
        .join("")}
    </div>
  `;

  return `
    <div class="context-card">
      <h3>${escapeHtml(title)}</h3>
      ${descriptionBlocks}
    </div>
  `;
}

function renderForensicsCard(forensicsSummary, forensicsEvents) {
  if (!forensicsSummary && !forensicsEvents?.selected_count) {
    return `
      <div class="context-card">
        <h3>Forensics Enrichment</h3>
        <p class="small-note">No forensic enrichment was returned for this incident.</p>
      </div>
    `;
  }

  const lines = [
    ["Selected Events", String(forensicsEvents?.selected_count ?? forensicsSummary?.selected_count ?? 0)],
    ["Certificate", forensicsSummary?.certificate_status],
    ["Process Owner", forensicsSummary?.process_owner],
    ["Host State", forensicsSummary?.host_state],
    ["Script Module", forensicsSummary?.process_script_module],
    ["Script Module Path", forensicsSummary?.process_script_module_path],
    ["Destinations", forensicsSummary?.destinations?.join(", ")],
  ]
    .filter(([, value]) => value)
    .map(
      ([label, value]) => `
        <div class="context-kv-row">
          <span>${escapeHtml(label)}</span>
          <strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong>
        </div>
      `,
    )
    .join("");

  return `
    <div class="context-card">
      <h3>Forensics Enrichment</h3>
      ${lines || `<p class="small-note">No curated forensic fields were available.</p>`}
      ${
        forensicsSummary?.handling_tooltip
          ? forensicsSummary.handling_tooltip.length > 180
            ? renderExpandableTextBlock("Additional Forensics Details", forensicsSummary.handling_tooltip)
            : `<p class="small-note">${escapeHtml(forensicsSummary.handling_tooltip)}</p>`
          : ""
      }
    </div>
  `;
}

function renderProcessStack(processStack) {
  if (!processStack?.length) {
    return `
      <div class="context-card context-card-wide">
        <h3>Process Stack</h3>
        <p class="small-note">No process lineage stack was available in FortiEDR telemetry.</p>
      </div>
    `;
  }

  const nodes = processStack
    .map((entry, index) => {
      const tooltipParts = [entry.process_path, entry.process_owner, entry.command_line].filter(Boolean);
      const tooltip = tooltipParts.join(" | ");
      return `
        <span class="process-node ${entry.highlighted ? "is-highlighted" : ""}" title="${escapeHtml(tooltip)}">
          ${escapeHtml(entry.process_name)}
        </span>
        ${index < processStack.length - 1 ? '<span class="process-arrow">›</span>' : ""}
      `;
    })
    .join("");

  return `
    <div class="context-card context-card-wide">
      <h3>Process Stack</h3>
      <div class="process-stack">${nodes}</div>
      <p class="small-note">Parent-to-child lineage from FortiEDR raw stack telemetry. The highlighted process is the incriminated process.</p>
    </div>
  `;
}

function renderIncidentMetadata(payload) {
  const incident = payload.incident;
  const derived = payload.derived_context || {};
  title.textContent = incident.process
    ? `Incident ${incident.incident_id} (${incident.process})`
    : `Incident ${incident.incident_id}`;
  const hashes = payload.derived_hashes || {};
  const certificateStatus =
    derived.forensics_summary?.certificate_status || incident.signature_status || "unknown";
  const commandLinePills = (derived.relevant_command_lines || []).map((entry) =>
    metaPill(
      `Command Line · ${entry.process_name}`,
      inlineValue(entry.command_line, { full: true }),
      { wide: true, extraClass: "meta-pill-multiline" },
    ),
  );
  incidentMetadata.innerHTML = `
    <div class="incident-metadata-layout">
      <div class="meta-flow">
        ${metaPill("Host", inlineValue(incident.host))}
        ${metaPill("User", inlineValue(incident.logged_user))}
        ${metaPill("Severity", badge(incident.severity))}
        ${metaPill("Classification", badge(incident.classification))}
        ${metaPill("Certificate", badge(certificateStatus))}
        ${metaPill("Process", inlineValue(incident.process))}
        ${metaPill("Process Path", inlineValue(incident.process_path, { full: true }), {
          wide: true,
          extraClass: "meta-pill-multiline meta-pill-process-path",
        })}
        ${metaPill("Action", badge(incident.action))}
        ${metaPill("Handling", badge(incident.handling_state))}
        ${metaPill("First Seen", inlineValue(prettyDate(incident.first_seen)))}
        ${metaPill("Last Seen", inlineValue(prettyDate(incident.last_seen)))}
        ${metaPill("Threat Name", inlineValue(incident.threat_name))}
        ${metaPill("Threat Family", inlineValue(incident.threat_family))}
        ${metaPill("MD5", renderHashValue(hashes.md5))}
        ${metaPill("SHA256", renderHashValue(hashes.sha256))}
        ${metaPill("Raw Items", inlineValue(payload.raw_data_item_count ?? "n/a"))}
        ${metaPill("Related Events", inlineValue(payload.related_events?.related_count ?? 0))}
        ${metaPill("Forensics Hits", inlineValue(payload.forensics_events?.selected_count ?? 0))}
        ${commandLinePills.join("")}
      </div>
      <div class="context-grid">
        ${renderProcessStack(derived.process_stack)}
        ${renderMatchedRulesCard(
          "Matched EDR Rules",
          derived.matched_rules,
          derived.matched_rule_descriptions,
        )}
        ${renderLineCard(
          "Relevant Command Lines",
          (derived.relevant_command_lines || []).map(
            (entry) => `${entry.process_name}: ${entry.command_line}`,
          ),
          { emptyMessage: "No relevant shell or script command line was available." },
        )}
        ${renderLineCard("Launch Context Clues", derived.launch_context_clues, {
          emptyMessage: "No conservative launch-context clues were derivable from the current telemetry.",
          wrap: true,
        })}
        ${renderForensicsCard(derived.forensics_summary, payload.forensics_events)}
      </div>
    </div>
  `;
  clearState(incidentState);
  show(incidentMetadata);
}

function renderHistory(history) {
  if (!history.runs?.length) {
    setState(historyState, "No prior analysis runs stored for this incident.");
    return;
  }

  clearState(historyState);
  historyContainer.innerHTML = `
    <table class="history-table">
      <thead>
        <tr>
          <th>Run</th>
          <th>Created</th>
          <th>Status</th>
          <th>Provider / Model</th>
        </tr>
      </thead>
      <tbody>
        ${history.runs
          .map(
            (run) => `
              <tr>
                <td><a href="/portal/runs/${run.run_id}">${escapeHtml(runLabel(run))}</a><div class="small-note">${escapeHtml(run.run_id)}</div></td>
                <td>${escapeHtml(prettyDate(run.created_at))}</td>
                <td>${badge(run.status)}</td>
                <td>${escapeHtml(run.llm_provider ?? "n/a")} / ${escapeHtml(run.model_name ?? "n/a")}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
  show(historyContainer);

  if (history.runs[0]?.status === "running") {
    scheduleRunPolling(history.runs[0].run_id);
  }
}

async function refreshHistory() {
  const historyPayload = await fetchJson(`/incidents/${incidentId}/analysis/history`);
  renderHistory(historyPayload);
  overviewRuns = historyPayload.runs || [];
  return historyPayload;
}

async function fetchRunDetail(runId, { force = false } = {}) {
  const cacheKey = String(runId);
  if (!force && runDetailCache.has(cacheKey)) {
    return runDetailCache.get(cacheKey);
  }
  const run = await fetchJson(`/analysis/runs/${runId}`);
  runDetailCache.set(cacheKey, run);
  return run;
}

function bindOverviewRunSelector() {
  const selector = latestOverview.querySelector("#overview-run-selector");
  if (!selector) {
    return;
  }
  selector.addEventListener("change", async (event) => {
    const nextRunId = String(event.currentTarget.value || "").trim();
    if (!nextRunId) {
      return;
    }
    try {
      selectedOverviewRunId = nextRunId;
      const run = await fetchRunDetail(nextRunId);
      latestOverview.innerHTML = renderAnalysisOverview(run, {
        availableRuns: overviewRuns,
        selectedRunId: nextRunId,
      });
      bindOverviewRunSelector();
    } catch (error) {
      setBanner(escapeHtml(error.message), "error");
    }
  });
}

function scheduleRunPolling(runId) {
  stopRunPolling();

  const poll = async () => {
    try {
      const run = await fetchRunDetail(runId, { force: true });
      if (run.status === "running") {
        pollTimer = window.setTimeout(poll, 2000);
        return;
      }
      stopRunPolling();
      const historyPayload = await refreshHistory();
      selectedOverviewRunId = historyPayload.runs?.[0]?.run_id || String(run.run_id);
      await loadOverviewRun(selectedOverviewRunId, { force: true });
      if (run.status === "success" && run.validated_output) {
        setBanner(
          `Background analysis <strong>${escapeHtml(runLabel(run))}</strong> completed.`,
          "success",
        );
      } else {
        const detail = run.validation_errors?.[0]
          ? `<div class="small-note">${escapeHtml(run.validation_errors[0])}</div>`
          : "";
        setBanner(
          `Background analysis <strong>${escapeHtml(runLabel(run))}</strong> failed. <a class="inline-link" href="/portal/runs/${run.run_id}">Open run</a>${detail}`,
          "error",
        );
      }
    } catch (error) {
      pollTimer = window.setTimeout(poll, 4000);
    }
  };

  pollTimer = window.setTimeout(poll, 2000);
}

async function loadOverviewRun(runId = null, options = {}) {
  if (!overviewRuns.length) {
    setState(latestOverviewState, "No analysis runs stored yet.");
    return;
  }

  const targetRunId = String(
    runId || selectedOverviewRunId || overviewRuns[0]?.run_id || "",
  ).trim();
  if (!targetRunId) {
    setState(latestOverviewState, "No analysis runs stored yet.");
    return;
  }

  const run = await fetchRunDetail(targetRunId, { force: options.force === true });
  selectedOverviewRunId = targetRunId;
  latestOverview.innerHTML = renderAnalysisOverview(run, {
    availableRuns: overviewRuns,
    selectedRunId: targetRunId,
  });
  bindOverviewRunSelector();
  clearState(latestOverviewState);
  show(latestOverview);
}

async function loadPage() {
  try {
    const [incidentPayload, historyPayload] = await Promise.all([
      fetchJson(`/incidents/${incidentId}`),
      fetchJson(`/incidents/${incidentId}/analysis/history`),
    ]);
    renderIncidentMetadata(incidentPayload);
    renderHistory(historyPayload);
    overviewRuns = historyPayload.runs || [];
    selectedOverviewRunId = overviewRuns[0]?.run_id || null;
    await loadOverviewRun();
  } catch (error) {
    setState(incidentState, error.message);
    setState(historyState, error.message);
    setState(latestOverviewState, error.message);
    title.textContent = `Incident ${incidentId}`;
  }
}

async function triggerAnalysis(force) {
  analyzeButton.disabled = true;
  analyzeForceButton.disabled = true;
  setBanner("Running analysis. This can take a few moments.");
  try {
    const payload = await postJson(`/incidents/${incidentId}/analyze`, {
      force,
      async_run: true,
      ...selectedModelPayload(),
    });
    const run = payload.run;
    runDetailCache.set(String(run.run_id), run);
    if (run.status === "running") {
      setBanner(
        `Started background analysis <strong>${escapeHtml(runLabel(run))}</strong>. You can keep navigating while it runs. <a class="inline-link" href="/portal/runs/${run.run_id}">Open run</a>`,
        "success",
      );
      const historyPayload = await refreshHistory();
      selectedOverviewRunId = historyPayload.runs?.[0]?.run_id || String(run.run_id);
      await loadOverviewRun(selectedOverviewRunId, { force: true });
      scheduleRunPolling(run.run_id);
    } else {
      setBanner(
        payload.from_cache
          ? `Returned cached analysis run <strong>${escapeHtml(runLabel(run))}</strong>.`
          : `Analysis run <strong>${escapeHtml(runLabel(run))}</strong> completed.`,
        "success",
      );
      const historyPayload = await refreshHistory();
      selectedOverviewRunId = historyPayload.runs?.[0]?.run_id || String(run.run_id);
      await loadOverviewRun(selectedOverviewRunId, { force: true });
    }
  } catch (error) {
    const failedRun = error.payload?.run;
    if (failedRun) {
      const detail = error.details?.[0] ? `<div class="small-note">${escapeHtml(error.details[0])}</div>` : "";
      setBanner(
        `Analysis run <strong>${escapeHtml(runLabel(failedRun))}</strong> was rejected by backend validation. <a class="inline-link" href="/portal/runs/${failedRun.run_id}">Open failed run</a>${detail}`,
        "error",
      );
      runDetailCache.set(String(failedRun.run_id), failedRun);
      const historyPayload = await refreshHistory();
      selectedOverviewRunId = historyPayload.runs?.[0]?.run_id || String(failedRun.run_id);
      await loadOverviewRun(selectedOverviewRunId, { force: true });
    } else {
      setBanner(escapeHtml(error.message), "error");
    }
  } finally {
    analyzeButton.disabled = false;
    analyzeForceButton.disabled = false;
  }
}

analyzeButton.addEventListener("click", () => triggerAnalysis(false));
analyzeForceButton.addEventListener("click", () => triggerAnalysis(true));

loadPage();
window.addEventListener("beforeunload", stopRunPolling);
