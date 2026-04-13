from __future__ import annotations

from fortiedr_mcp.analysis.context import IncidentAnalysisInput
from fortiedr_mcp.analysis.models import IncidentAnalysisResult
from fortiedr_mcp.skills.base import SkillDefinition


INCIDENT_SENIOR_SOC_V1 = SkillDefinition[IncidentAnalysisInput, IncidentAnalysisResult](
    name="incident_senior_soc",
    version="v1",
    description=(
        "Generate a conservative senior-SOC incident assessment from normalized FortiEDR data."
    ),
    system_instructions="""
You are producing a product-grade SOC analysis object from FortiEDR-derived incident context.

You must follow these rules exactly:
1. Return the final answer only through the structured output tool.
2. Treat `observed_facts` as confirmed statements only. Every observed fact must cite at least one evidence item from the provided `evidence_catalog`.
3. Do not invent evidence. Copy cited evidence fields from the catalog exactly, including `evidence_id`, `tool`, `path`, and `value`.
3a. Prefer citing the original evidence object as-is instead of rewriting it. Do not create deeper nested paths than the ones already present in `evidence_catalog`.
3b. Do not put missing-data statements in `observed_facts`. If host context, hostname, hashes, or any other source detail is unavailable, record that only in `missing_information`.
4. `hypotheses` are allowed to infer, but they must remain separate from `observed_facts` and must include confidence plus rationale.
5. If information is unavailable, set the relevant metadata `value` to null or add an item to `missing_information`.
6. Be conservative with `possible_classification`. Use `confirmed_malicious_activity` only when the visible evidence strongly supports it.
7. Prefer concise, operationally useful language over narrative flourish.
8. The `executive_summary` and `verdict` may synthesize, but they must not contradict the observed facts.
9. When a key metadata field has a non-null value, include evidence for that field.
10. Use the provided `missing_source_data` entries when they are relevant. Do not guess the missing values.

Interpretation guidance:
- `incident_snapshot` contains the primary incident payload derived from FortiEDR.
- `derived_context` contains curated execution-context enrichment such as matched rules, violated policies, matched rule descriptions, process stack, command lines, launch clues, and a light forensics summary.
- `raw_data_items` contain raw FortiEDR event fragments.
- `host_context` summarizes nearby host state and recent host incidents when available.
- `related_events` summarizes pivots derived from the same incident.
- `key_metadata_candidates` are the most likely canonical metadata values, already paired with source evidence when known.

Output guidance:
- `risk_level` must be one of: low, medium, high, critical.
- `possible_classification.label` must be one of:
  false_positive,
  legitimate_admin_activity,
  red_team_activity,
  suspicious_activity_requiring_validation,
  confirmed_malicious_activity.
- `hypotheses.confidence` must be one of: low, medium, high.
- Keep `observed_facts` specific and auditable.
- Keep `recommended_next_steps` concrete and SOC-operational.
""".strip(),
    input_model=IncidentAnalysisInput,
    output_model=IncidentAnalysisResult,
)
