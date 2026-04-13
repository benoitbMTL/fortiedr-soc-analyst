# FortiEDR MCP And Analysis Backend

This repository now contains two product layers:

1. A read-only FortiEDR MCP server for incident and host retrieval.
2. A structured incident analysis backend built on top of the same retrieval layer.

The backend now also includes a persistent product service layer for:

- stored analysis runs
- audit history
- idempotent analysis execution
- stable HTTP endpoints for future portal and client use

The analysis backend is intended to be the reusable contract for later phases such as:

- a portal UI
- one or more LLM clients
- future skill-based workflows

The FortiEDR integration in this repository uses a narrow read-only client implemented in `src/fortiedr_mcp/fortiedr_client.py`. It talks directly to the FortiEDR API over HTTPS and intentionally exposes only the read-only endpoints needed for incident retrieval and analysis:

- `management-rest/events/list-events`
- `management-rest/events/list-raw-data-items`
- `management-rest/inventory/list-collectors`
- `management-rest/organizations/list-organizations`
- `api/forensics/get-events`

## Current Incident Model

FortiEDR currently exposes event-centric records through the API paths used by this project. For this MVP, MCP "incidents" map to FortiEDR event records.

`get_incident_details` enriches an event with:

- raw data items from `list-raw-data-items`
- optional host context from `list-collectors`
- related events discovered through a safe read-only pivot
- optional forensic event enrichment from `api/forensics/get-events`

The normalized analysis input and portal detail views now also derive curated context from the source payloads:

- matched FortiEDR rule labels
- violated policy names when present in raw alerts
- process lineage stacks rendered parent to child
- relevant command lines for shell/script processes when available
- conservative launch-context clues
- a light forensics summary for certificate state, script-module context, host state, and related execution context

## Setup

1. Create or activate a Python environment.
2. Install the package:

```bash
pip install -e .
```

3. Create `.env` from `.env.example`, or reuse the existing `.env`.

Expected environment variables:

- `FORTIEDR_HOST`
- `FORTIEDR_ORG`
- `FORTIEDR_USER`
- `FORTIEDR_PASS`

Compatibility aliases also supported because the current repository already uses them:

- `FORTIEDR_API_USER`
- `FORTIEDR_API_PASSWORD`

Optional settings:

- `FORTIEDR_VERIFY_SSL` default: `true`
- `FORTIEDR_TIMEOUT_SECONDS` default: `30`
- `FORTIEDR_ANALYSIS_DB_PATH` default: `./data/analysis_runs.sqlite3`
- `FORTIEDR_BACKEND_HOST` default: `127.0.0.1`
- `FORTIEDR_BACKEND_PORT` default: `8080`

Optional LLM settings for the structured analysis CLI:

- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_BASE_URL` default: `https://api.openai.com/v1`
- `OPENAI_MAX_TOKENS` default: `4096`
- `OPENAI_TIMEOUT_SECONDS` default: `120`
- `OPENAI_TEMPERATURE` default: `0`
- `OPENAI_MAX_RETRIES` default: `2`
- `OPENAI_AVAILABLE_MODELS` optional comma-separated list for portal model selector

Anthropic remains supported as an alternate provider:

- `ANTHROPIC_API_KEY`
- `ANTHROPIC_MODEL`
- `ANTHROPIC_BASE_URL` default: `https://api.anthropic.com`
- `ANTHROPIC_MAX_TOKENS` default: `4096`
- `ANTHROPIC_TIMEOUT_SECONDS` default: `120`
- `ANTHROPIC_AVAILABLE_MODELS` optional comma-separated list for portal model selector
- `FORTIEDR_LLM_SERVER_PROVIDER` optional remote LLM provider identifier, currently `ollama`
- `FORTIEDR_LLM_SERVER_URL` optional remote LLM server base URL, for example `http://10.163.3.76:11434/`
- `OLLAMA_BASE_URL` optional compatibility alias for the configured Ollama server URL
- `OLLAMA_MODEL` optional default Ollama model when no explicit model is selected
- `OLLAMA_AVAILABLE_MODELS` optional comma-separated fallback list for portal model selector
- `OLLAMA_MAX_TOKENS` default: `4096`
- `OLLAMA_TIMEOUT_SECONDS` default: `120`
- `OLLAMA_TEMPERATURE` default: `0`
- `FORTIEDR_ANALYSIS_CONCURRENCY` default: `2`

## MCP Server

Default startup uses streamable HTTP:

```bash
fortiedr-mcp
```

Or directly:

```bash
python -m fortiedr_mcp.server
```

Default endpoint:

```text
http://127.0.0.1:8000/mcp
```

To force stdio instead:

```bash
fortiedr-mcp --transport stdio
```

The server uses the official Python MCP SDK and supports `streamable-http`, `stdio`, and `sse`.

## Exposed Tools

- `list_incidents`
- `get_incident`
- `get_incident_details`
- `search_incidents_by_host`
- `search_incidents_by_hash`
- `search_incidents_by_process`
- `search_incidents_by_user`
- `get_host_context`
- `get_related_events`
- `get_forensics_events`

## Structured Analysis Layer

The first formal skill is `incident_senior_soc_v1`.

It is implemented as a versioned contract with:

- a skill definition in `src/fortiedr_mcp/skills/incident_senior_soc_v1.py`
- a registry in `src/fortiedr_mcp/skills/registry.py`
- typed input and output models in `src/fortiedr_mcp/analysis/context.py` and `src/fortiedr_mcp/analysis/models.py`
- packaged JSON schemas in `src/fortiedr_mcp/schemas/`
- orchestration in `src/fortiedr_mcp/services/incident_analysis.py`

### Facts, Hypotheses, And Evidence

The analysis backend treats these as separate first-class concepts:

- `observed_facts`: must cite evidence from the prepared evidence catalog
- `hypotheses`: may infer, but must include confidence and rationale
- `missing_information`: must name important gaps instead of guessing

Traceability is carried through `EvidenceReference` objects containing:

- `evidence_id`
- `tool`
- `path`
- `value`

The service validates that evidence cited by the LLM actually exists in the prepared input catalog before accepting the result.

### Analysis Flow

The analysis service does the following:

1. Retrieve canonical incident data from the shared incident-data service.
2. Build a normalized analysis input object plus evidence catalog.
   The normalized context now includes `derived_context` with curated process lineage, matched rules, violated policies, relevant command lines, launch clues, and a lightweight forensic summary.
3. Load the requested skill definition from the registry.
4. Call the configured LLM provider through a provider abstraction.
5. Validate the returned JSON against the typed output model.
6. Validate that cited evidence exists in the input catalog.
7. Return a canonical result object ready to store or render later.

## Persistent Backend Service

The repository now includes a persistent backend API on top of the existing analysis engine.

Persistence is implemented with SQLite in `src/fortiedr_mcp/repositories/analysis_runs.py`.
Each analysis run stores:

- incident identifier
- skill name and skill version
- provider and model name
- source fingerprint
- timestamps
- runtime timing metrics
- token usage when available
- estimated cost placeholder
- source-context inclusion flags
- normalized analysis input
- raw LLM output
- validated final output
- validation status and validation errors
- analyst feedback placeholder fields

The stored record is immutable per run and version-aware. History is retained as append-only records.

### Idempotent Execution

`POST /incidents/{id}/analyze` uses a simple cache policy by default:

- it always fetches and normalizes current source data before deciding on cache reuse
- it computes a deterministic `source_fingerprint` from the normalized analysis input JSON
- it reuses the latest successful run only when both the request-shape key and the `source_fingerprint` match
- it does not reuse failed runs
- pass `{"force": true}` in the request body to force a fresh run

This policy is intentionally simple and explicit. It is now source-data fingerprint aware at the normalized input layer.

### Backend Endpoints

The backend API exposes:

- `GET /incidents`
- `GET /incidents/{id}`
- `POST /incidents/{id}/analyze`
- `GET /incidents/{id}/analysis/latest`
- `GET /incidents/{id}/analysis/history`
- `GET /analysis/runs/{run_id}`
- `GET /analysis/runs/{run_id}/feedback`
- `POST /analysis/runs/{run_id}/feedback`

`GET /incidents/{id}` returns the current incident details payload, including raw data, host context, and related events according to query parameters.

`POST /incidents/{id}/analyze` runs the current structured analysis pipeline, persists the run, and returns:

- `from_cache`
- `run`

When the run fails, the endpoint still persists the failed run and returns a structured error body with the persisted run metadata.

`GET /incidents/{id}/analysis/latest` returns the latest successful persisted analysis for the incident.

`GET /incidents/{id}/analysis/history` returns the stored run history for the incident. By default, it omits `normalized_input` and `llm_output` to keep the response practical. Add query params `include_input=true` or `include_llm_output=true` when full audit payloads are needed.

`GET /analysis/runs/{run_id}` returns the full stored run detail for audit and future portal drill-down. By default it includes both `normalized_input` and `llm_output`.

`GET /analysis/runs/{run_id}/feedback` returns the current feedback record for the run, or `null` if no analyst feedback has been submitted yet.

`POST /analysis/runs/{run_id}/feedback` upserts one current feedback record embedded in the persisted run. The current MVP stores feedback inside the run record rather than in a separate feedback table.

Feedback fields are:

- `usefulness`: `useful` or `not_useful`
- `correctness`: `correct`, `partially_correct`, or `incorrect`
- `analyst_classification`: `benign`, `false_positive`, `red_team`, `malicious`, or `needs_validation`
- `comment`
- `updated_at`

### Analysis Run Lifecycle

For a fresh run:

1. Fetch incident source data from FortiEDR.
2. Normalize the input for the requested skill.
3. Call the configured LLM provider.
4. Validate schema and evidence references.
5. Persist the run with timings, metadata, and outputs.
6. Return the canonical stored result.

If the LLM returns a near-valid payload, the backend performs one narrow repair before schema validation:

- it preserves the required `skill_version`
- it normalizes `incident_id` to string form
- it moves zero-evidence statements about unavailable data out of `observed_facts` and into `missing_information`

All other schema or evidence mismatches still fail validation and are stored as failed runs with detailed validation errors.

For a cache hit:

1. Fetch and normalize current source data.
2. Match on request-shape key plus source fingerprint.
3. Return the stored successful run without re-calling the LLM.

For portal use:

- latest analysis provides the current analyst-facing answer for an incident
- history provides the run timeline for the incident
- run detail provides the full audit/debug payload for one run
- embedded feedback allows a lightweight portal MVP to capture analyst judgement without a separate review service

## Run Structured Analysis

Run a real structured analysis with LLM credentials configured. The CLI now uses `--provider auto` by default and prefers OpenAI when `OPENAI_API_KEY` is present:

```bash
fortiedr-analyze-incident 5440222 --skill incident_senior_soc_v1
```

Force a specific provider if needed:

```bash
fortiedr-analyze-incident 5440222 --skill incident_senior_soc_v1 --provider openai
```

Write the result to a file:

```bash
fortiedr-analyze-incident 5440222 --skill incident_senior_soc_v1 --save analysis-5440222.json
```

Dump the normalized skill input without calling the LLM:

```bash
fortiedr-analyze-incident 5440222 --skill incident_senior_soc_v1 --dump-input analysis-input.json --input-only
```

## Run The Backend API

Start the HTTP backend service:

```bash
fortiedr-backend
```

Or bind a custom host, port, or database path:

```bash
fortiedr-backend --host 0.0.0.0 --port 8080 --db-path ./data/analysis_runs.sqlite3
```

The same backend process now also serves a lightweight portal MVP at:

```text
http://127.0.0.1:8080/portal
```

The portal is a validation UI, not a production frontend. It uses only the existing backend endpoints and lets an analyst:

- list incidents
- see whether an incident already has a stored analysis run
- select multiple incidents and trigger analysis in bulk from the list
- choose the configured analysis model from a selector backed by the backend
- open one incident
- trigger analysis or force a fresh analysis
- start analysis in the background and keep navigating while the run is executing
- view the latest structured analysis
- browse analysis history
- open full run detail
- submit analyst feedback for a run

The incident detail layout is optimized for readability rather than density:

- source metadata appears near the top in responsive cards
- the latest executive summary is shown early on the page
- the full structured analysis is rendered below in a wide full-width section
- timestamps are formatted consistently in UTC for analyst readability
- long values such as process paths wrap safely inside their cards

Example analysis request:

```bash
curl -X POST http://127.0.0.1:8080/incidents/5440222/analyze \
  -H 'content-type: application/json' \
  -d '{"force": false}'
```

Fetch latest successful analysis:

```bash
curl http://127.0.0.1:8080/incidents/5440222/analysis/latest
```

Fetch history:

```bash
curl http://127.0.0.1:8080/incidents/5440222/analysis/history
```

Fetch one run in full detail:

```bash
curl http://127.0.0.1:8080/analysis/runs/<run_id>
```

Submit analyst feedback:

```bash
curl -X POST http://127.0.0.1:8080/analysis/runs/<run_id>/feedback \
  -H 'content-type: application/json' \
  -d '{
    "usefulness": "useful",
    "correctness": "partially_correct",
    "analyst_classification": "needs_validation",
    "comment": "Needs validation against endpoint logs."
  }'
```

Read feedback back:

```bash
curl http://127.0.0.1:8080/analysis/runs/<run_id>/feedback
```

## Schemas And Tests

Schema files are generated by:

```bash
.venv/bin/python scripts/export_schemas.py
```

Local tests:

```bash
.venv/bin/pytest -q
```

The current tests cover:

- skill registry loading
- schema-backed model validation
- packaged schema file generation
- fixture-based incident analysis orchestration
- evidence traceability enforcement
- persistent analysis run storage and cache reuse
- backend API analysis, latest, and history flows
- source-fingerprint-aware cache invalidation
- per-run detail and feedback endpoints
- portal route serving and static assets

## Limitations

- Read-only only. No remediation, isolation, policy, delete, or update tools are exposed.
- FortiEDR event records are used as the current incident unit because a separate incident API was not available in the cloned project.
- `get_related_events` uses a read-only pivot derived from the incident details. It prefers host context when present and falls back to user or process when needed.
- `search_incidents_by_user` accepts either `user` or `DOMAIN\user`. The server normalizes the FortiEDR query to the username segment because that is what the current API accepts.
- Hash metadata is left null unless a trustworthy source field is available; the analysis layer does not infer hash values from filenames or ambiguous strings.
- The structured analysis CLI currently ships with OpenAI, Anthropic, and mock-backed test coverage. The CLI prefers OpenAI automatically when both providers are configured.
- Feedback is currently stored as one embedded record per analysis run. There is not yet a multi-review history model or analyst identity tracking.
- The source fingerprint is derived from the normalized analysis input, not from a lower-level raw FortiEDR snapshot archive.
- The portal MVP is intentionally lightweight. It has no authentication, multi-user support, advanced filtering, or live updates.
- Threat hunting workflows are still not implemented.
