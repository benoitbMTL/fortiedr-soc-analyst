from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortiedr_mcp.analysis.context import IncidentAnalysisInputBuilder
from fortiedr_mcp.models import IncidentDetailsResult


@pytest.fixture()
def sample_incident_details() -> IncidentDetailsResult:
    fixture_path = Path(__file__).parent / "fixtures" / "sample_incident_details.json"
    return IncidentDetailsResult.model_validate(json.loads(fixture_path.read_text()))


@pytest.fixture()
def sample_analysis_input(sample_incident_details: IncidentDetailsResult):
    return IncidentAnalysisInputBuilder().build(sample_incident_details)
