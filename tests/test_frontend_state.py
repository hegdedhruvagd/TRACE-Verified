"""Regression checks for frontend analysis replacement and stale async work."""

from pathlib import Path


def _app_source():
    return (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(encoding="utf-8")


def _web_source(name):
    return (Path(__file__).resolve().parents[1] / "web" / name).read_text(encoding="utf-8")


def test_new_analysis_clears_incident_and_explanation_state_before_fetching():
    source = _app_source()
    run_analysis = source.split("async function runAnalysis()", 1)[1].split("// 7. Render Analysis", 1)[0]

    assert "resetAnalysisStateForNewRun();" in run_analysis
    assert run_analysis.index("resetAnalysisStateForNewRun();") < run_analysis.index("await fetch(")

    reset = source.split("function resetAnalysisStateForNewRun()", 1)[1].split("// 7. Render Analysis", 1)[0]
    for expected in (
        "state.analysisGeneration++",
        "state.currentAnalysis = null",
        "window.currentAnalysis = null",
        "state.selectedIncidentId = null",
        "state.supportingEventsMap.clear()",
        "state.findingsMap.clear()",
        "state.explanationMap.clear()",
        "state.explanationJobStatus = 'idle'",
        "clearInterval(state.explanationPollingTimer)",
        "clearInterval(state.explanationElapsedTimer)",
        "state.filterSeverity = 'all'",
        "state.searchTerm = ''",
        "state.sortOrder = 'score_desc'",
        "elements.incidentSearchInput.value = ''",
        "pill.classList.toggle('active', pill.dataset.severity === 'all')",
        "elements.navIncidentBadge.textContent = '0'",
        "elements.analysisIdTag.textContent = 'No analysis loaded'",
        "elements.metricTotalRows.textContent = '0'",
        "renderDetectorCoverageGrid([])",
        "renderSourceProvenance([])",
        "renderWarnings([])",
        "closeEventModal()",
        "filterAndRenderIncidents()",
    ):
        assert expected in reset


def test_explanation_poll_is_bound_to_the_analysis_that_started_it():
    source = _app_source()
    polling_setup = source.split("function startExplanationPolling()", 1)[1].split("function renderExplanationTab", 1)[0]
    assert "const analysisId = state.currentAnalysis.analysis_id" in polling_setup
    assert "const generation = state.analysisGeneration" in polling_setup
    assert "pollExplanationStatus(analysisId, generation)" in polling_setup
    assert "pollExplanationStatus(analysisId, generation)" in polling_setup
    assert "state.analysisGeneration !== generation" in polling_setup
    assert "state.currentAnalysis.analysis_id !== analysisId" in polling_setup


def test_explanation_queue_response_cannot_update_a_replaced_analysis():
    source = _app_source()
    request = source.split("async function requestExplanation()", 1)[1].split("function startExplanationPolling()", 1)[0]
    assert "const analysisId = state.currentAnalysis.analysis_id" in request
    assert "const generation = state.analysisGeneration" in request
    assert "state.analysisGeneration !== generation" in request
    assert "state.currentAnalysis.analysis_id !== analysisId" in request


def test_untrusted_user_and_host_values_are_escaped_in_incident_cards():
    source = _app_source()
    preview = source.split("function renderIncidentsPreview(incidents)", 1)[1].split("function renderDetectorCoverageGrid", 1)[0]
    cards = source.split("// Render Incident Cards", 1)[1].split("// MILESTONE 3: INCIDENT DETAIL VIEW CONTROLLER", 1)[0]
    assert "(inc.affected_users || []).map(escapeHtml).join(', ')" in preview
    assert "(inc.affected_users || []).map(escapeHtml).join(', ')" in cards
    assert "(inc.affected_hosts || []).map(escapeHtml).join(', ')" in cards


def test_zero_incident_ui_distinguishes_incomplete_coverage_from_clean_baseline():
    source = _app_source()
    coverage = source.split("function hasCompleteAnalysisCoverage(report)", 1)[1].split("// 7. Render Analysis", 1)[0]
    assert "coverage.every(item => item.executed)" in coverage
    assert "requiredDetectors.every(id => executedIds.has(id))" in coverage
    assert "ingestion.accepted_rows" in coverage
    assert "ingestion.malformed_rows" in coverage
    assert "const completion = hasCompleteAnalysisCoverage(report)" in source
    assert "coverage is incomplete" in source
    assert "Review detector coverage and ingestion warnings" in source


def test_privilege_event_roles_are_separately_visible_in_incident_evidence_and_inspector():
    app = _app_source()
    page = _web_source("index.html")

    evidence = app.split("function renderEvidenceTab(incident)", 1)[1].split("// TAB 4:", 1)[0]
    for field in ("actor", "target_member", "target_group"):
        assert f"escapeHtml(evt.{field} || '-')" in evidence
        assert f'id="modal-{field.replace("_", "-")}"' in page
        assert f"elements.modal{field.title().replace('_', '')}.textContent = evt.{field}" in app
    assert "<th>Actor</th>" in page
    assert "<th>Target Member</th>" in page
    assert "<th>Target Group</th>" in page
    assert "CANONICAL USER" in page
