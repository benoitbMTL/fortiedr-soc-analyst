import {
  badge,
  clearState,
  escapeHtml,
  fetchJson,
  postJson,
  prettyDate,
  renderAnalysis,
  renderPayloads,
  renderRunSummary,
  runLabel,
  setState,
  show,
} from "/portal/static/shared.js";

const runId = window.location.pathname.split("/").pop();

const backLink = document.getElementById("run-back-link");
const title = document.getElementById("run-title");
const runState = document.getElementById("run-state");
const feedbackState = document.getElementById("feedback-state");
const runSummary = document.getElementById("run-summary");
const analysisRender = document.getElementById("analysis-render");
const runPayloads = document.getElementById("run-payloads");
const feedbackPanel = document.getElementById("feedback-panel");
const feedbackForm = document.getElementById("feedback-form");
const feedbackMessage = document.getElementById("feedback-message");
let refreshTimer = null;
let copyFeedbackTimer = null;
let lastCopiedButton = null;

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

function setCopyButtonState(button, copied) {
  if (!button) {
    return;
  }
  button.classList.toggle("is-copied", copied);
  button.title = copied ? "Copied" : "Copy";
  button.setAttribute("aria-label", copied ? "Copied" : "Copy payload");
}

function fillFeedback(feedback) {
  feedbackForm.usefulness.value = feedback?.usefulness ?? "";
  feedbackForm.correctness.value = feedback?.correctness ?? "";
  feedbackForm.analyst_classification.value = feedback?.analyst_classification ?? "";
  feedbackForm.comment.value = feedback?.comment ?? "";
  feedbackMessage.textContent = feedback?.updated_at
    ? `Last updated ${prettyDate(feedback.updated_at)}`
    : "No feedback saved yet.";
}

async function loadFeedback() {
  try {
    const payload = await fetchJson(`/analysis/runs/${runId}/feedback`);
    fillFeedback(payload.feedback);
    clearState(feedbackState);
    show(feedbackPanel);
  } catch (error) {
    setState(feedbackState, error.message);
  }
}

async function loadRun() {
  if (refreshTimer) {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  try {
    const run = await fetchJson(`/analysis/runs/${runId}`);
    title.textContent = runLabel(run);
    backLink.href = `/portal/incidents/${run.incident_id}`;
    runSummary.innerHTML = renderRunSummary(run);
    analysisRender.innerHTML = run.validated_output
      ? renderAnalysis(run.validated_output)
      : `
        <div class="section-card">
          <h3>Run Error</h3>
          <div class="chip-row">
            ${badge(run.status)}
            ${badge(run.validation_status)}
          </div>
          <p>${escapeHtml(run.error?.message ?? "Run did not produce a validated analysis.")}</p>
          ${
            run.validation_errors?.length
              ? `<ul class="clean-list">${run.validation_errors
                  .map((item) => `<li>${escapeHtml(item)}</li>`)
                  .join("")}</ul>`
              : run.status === "running"
                ? `<p class="small-note">Analysis is still running in the background. This page refreshes automatically.</p>`
                : `<p class="small-note">No detailed validation errors were recorded.</p>`
          }
        </div>
      `;
    runPayloads.innerHTML = renderPayloads(run);
    clearState(runState);
    show(runSummary);
    show(analysisRender);
    show(runPayloads);
    await loadFeedback();
    if (run.status === "running") {
      refreshTimer = window.setTimeout(loadRun, 2000);
    } else if (refreshTimer) {
      window.clearTimeout(refreshTimer);
      refreshTimer = null;
    }
  } catch (error) {
    title.textContent = `Run ${runId}`;
    setState(runState, error.message);
  }
}

feedbackForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  feedbackMessage.textContent = "Saving feedback...";
  try {
    const payload = await postJson(`/analysis/runs/${runId}/feedback`, {
      usefulness: feedbackForm.usefulness.value || null,
      correctness: feedbackForm.correctness.value || null,
      analyst_classification: feedbackForm.analyst_classification.value || null,
      comment: feedbackForm.comment.value || null,
    });
    fillFeedback(payload.feedback);
    feedbackMessage.textContent = "Feedback saved.";
  } catch (error) {
    feedbackMessage.textContent = error.message;
  }
});

runPayloads?.addEventListener("click", async (event) => {
  const copyButton = event.target.closest(".payload-copy-button");
  if (!copyButton) {
    return;
  }

  event.preventDefault();
  event.stopPropagation();

  const payloadBlock = copyButton.closest("details");
  const target = payloadBlock?.querySelector("pre");
  if (!target) {
    return;
  }

  try {
    await copyText(target.textContent || "");
    if (lastCopiedButton && lastCopiedButton !== copyButton) {
      setCopyButtonState(lastCopiedButton, false);
    }
    setCopyButtonState(copyButton, true);
    lastCopiedButton = copyButton;
    if (copyFeedbackTimer) {
      window.clearTimeout(copyFeedbackTimer);
    }
    copyFeedbackTimer = window.setTimeout(() => {
      setCopyButtonState(copyButton, false);
      if (lastCopiedButton === copyButton) {
        lastCopiedButton = null;
      }
    }, 1200);
  } catch (error) {
    feedbackMessage.textContent = error.message || "Copy failed.";
  }
});

loadRun();
