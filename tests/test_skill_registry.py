from fortiedr_mcp.analysis.context import IncidentAnalysisInput
from fortiedr_mcp.analysis.models import IncidentAnalysisResult
from fortiedr_mcp.skills.registry import get_skill, list_skills


def test_incident_senior_soc_v1_is_registered():
    assert "incident_senior_soc_v1" in list_skills()

    skill = get_skill("incident_senior_soc_v1")
    assert skill.name == "incident_senior_soc"
    assert skill.version == "v1"
    assert skill.input_model is IncidentAnalysisInput
    assert skill.output_model is IncidentAnalysisResult
