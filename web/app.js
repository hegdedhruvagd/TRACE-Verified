/**
 * TRACE-Verified SOC Dashboard - Milestone 3 Controller
 * Incident Explorer, Severity Analysis & Attack Timeline
 * Vanilla ES JavaScript - Offline-first, Zero external dependencies
 */

(function () {
  'use strict';

  // Global State
  const state = {
    stagedFiles: [],           // Array of File objects
    selectedSampleId: null,
    currentAnalysis: null,     // Authoritative backend response
    analysisGeneration: 0,     // Invalidates async work from replaced analyses
    isAnalyzing: false,

    // Milestone 3 State
    selectedIncidentId: null,
    filterSeverity: 'all',
    searchTerm: '',
    sortOrder: 'score_desc',
    supportingEventsMap: new Map(), // event_id -> CanonicalEvent
    findingsMap: new Map(),         // finding_id -> Finding

    // Milestone 4: Local SLM Explanation State
    explanationPollingTimer: null,
    explanationElapsedTimer: null,
    explanationElapsedSeconds: 0,
    explanationJobStatus: 'idle',   // 'idle' | 'queued' | 'running' | 'completed' | 'failed'
    explanationJobError: null,
    explanationMap: new Map(),      // incident_id -> ExplanationItem
  };

  // DOM Elements
  const elements = {
    // Navigation
    navItems: document.querySelectorAll('.sidebar-nav .nav-item'),
    sections: document.querySelectorAll('.soc-section'),
    navIncidentBadge: document.getElementById('nav-incident-badge'),
    clockDisplay: document.getElementById('clock-display'),

    // Live Status
    backendDot: document.getElementById('backend-dot'),
    backendStatusText: document.getElementById('backend-status-text'),
    ollamaDot: document.getElementById('ollama-dot'),
    ollamaStatusText: document.getElementById('ollama-status-text'),
    btnRefreshOllama: document.getElementById('btn-refresh-ollama'),

    // Alert Banner
    globalAlert: document.getElementById('global-alert'),
    alertMessage: document.getElementById('alert-message'),
    alertClose: document.getElementById('alert-close'),

    // Ingestion
    samplesContainer: document.getElementById('samples-container'),
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    btnBrowse: document.getElementById('btn-browse'),
    stagedFilesList: document.getElementById('staged-files-list'),
    stagedCountBadge: document.getElementById('staged-count-badge'),
    btnClearStaged: document.getElementById('btn-clear-staged'),
    btnRunAnalysis: document.getElementById('btn-run-analysis'),

    // Advanced Config
    cfgAuthWindow: document.getElementById('cfg-auth-window'),
    cfgBruteThreshold: document.getElementById('cfg-brute-threshold'),
    cfgSprayThreshold: document.getElementById('cfg-spray-threshold'),
    cfgSuccessThreshold: document.getElementById('cfg-success-threshold'),
    cfgCorrWindow: document.getElementById('cfg-corr-window'),
    cfgMaxDuration: document.getElementById('cfg-max-duration'),
    cfgApprovedIds: document.getElementById('cfg-approved-ids'),

    // Overview Metrics
    analysisIdTag: document.getElementById('analysis-id-tag'),
    metricTotalRows: document.getElementById('metric-total-rows'),
    metricSourcesCount: document.getElementById('metric-sources-count'),
    badgeIntegrity: document.getElementById('badge-integrity'),
    metricAcceptedRows: document.getElementById('metric-accepted-rows'),
    metricMalformedRows: document.getElementById('metric-malformed-rows'),
    metricMalformedRate: document.getElementById('metric-malformed-rate'),
    badgeIncidents: document.getElementById('badge-incidents'),
    metricIncidentsCount: document.getElementById('metric-incidents-count'),
    metricSeverityPills: document.getElementById('metric-severity-pills'),
    badgeCoverage: document.getElementById('badge-coverage'),
    metricCoverageRate: document.getElementById('metric-coverage-rate'),
    metricCoverageDetail: document.getElementById('metric-coverage-detail'),

    // Overview Grids
    incidentsPreviewCard: document.getElementById('incidents-preview-card'),
    incidentsPreviewList: document.getElementById('incidents-preview-list'),
    detectorGrid: document.getElementById('detector-grid'),
    sourceList: document.getElementById('source-list'),
    sectionWarningsCard: document.getElementById('section-warnings-card'),
    warningsCountBadge: document.getElementById('warnings-count-badge'),
    warningsList: document.getElementById('warnings-list'),

    // Milestone 3: Incidents Explorer View
    incidentsAnalysisId: document.getElementById('incidents-analysis-id'),
    incidentSearchInput: document.getElementById('incident-search-input'),
    severityFilterPills: document.querySelectorAll('#severity-filter-pills .filter-pill'),
    incidentSortSelect: document.getElementById('incident-sort-select'),
    incidentCardsContainer: document.getElementById('incident-cards-container'),
    incidentsListView: document.getElementById('incidents-list-view'),

    // Milestone 3: Incident Detail View
    incidentDetailView: document.getElementById('incident-detail-view'),
    btnBackToIncidents: document.getElementById('btn-back-to-incidents'),
    detailBreadcrumbId: document.getElementById('detail-breadcrumb-id'),
    detailSeverityBadge: document.getElementById('detail-severity-badge'),
    detailIncidentId: document.getElementById('detail-incident-id'),
    detailTimeSpan: document.getElementById('detail-time-span'),
    detailTitle: document.getElementById('detail-title'),
    detailScoringNotice: document.getElementById('detail-scoring-notice'),
    detailScoreVal: document.getElementById('detail-score-val'),
    detailScoreFill: document.getElementById('detail-score-fill'),
    detailUsersList: document.getElementById('detail-users-list'),
    detailHostsList: document.getElementById('detail-hosts-list'),
    detailCountsSummary: document.getElementById('detail-counts-summary'),

    // Detail Sub-tabs
    subtabBtns: document.querySelectorAll('.subtab-btn'),
    subtabContents: document.querySelectorAll('.subtab-content'),
    timelineListContainer: document.getElementById('timeline-list-container'),
    stagesStepperContainer: document.getElementById('stages-stepper-container'),
    evidenceCountBadge: document.getElementById('evidence-count-badge'),
    evidenceTableBody: document.getElementById('evidence-table-body'),
    scoreTableBody: document.getElementById('score-table-body'),
    detailNextStepsList: document.getElementById('detail-next-steps-list'),
    detailRationaleList: document.getElementById('detail-rationale-list'),
    detailLimitationsList: document.getElementById('detail-limitations-list'),

    // Milestone 4: Local SLM Explanation Elements
    subtabBtnExplanation: document.getElementById('subtab-btn-explanation'),
    explanationSubtabBadge: document.getElementById('explanation-subtab-badge'),
    explanationModelBadge: document.getElementById('explanation-model-badge'),
    explanationStatusBadge: document.getElementById('explanation-status-badge'),
    explanationModelName: document.getElementById('explanation-model-name'),
    explanationStatusDesc: document.getElementById('explanation-status-desc'),
    cfgExplainTimeout: document.getElementById('cfg-explain-timeout'),
    btnRequestExplanation: document.getElementById('btn-request-explanation'),
    btnRequestExplanationText: document.getElementById('btn-request-explanation-text'),
    explanationBodyContent: document.getElementById('explanation-body-content'),

    // Milestone 3: Forensic Event Modal
    eventModal: document.getElementById('event-modal'),
    modalEventId: document.getElementById('modal-event-id'),
    modalTimestamp: document.getElementById('modal-timestamp'),
    modalEventType: document.getElementById('modal-event-type'),
    modalUser: document.getElementById('modal-user'),
    modalActor: document.getElementById('modal-actor'),
    modalTargetMember: document.getElementById('modal-target-member'),
    modalTargetGroup: document.getElementById('modal-target-group'),
    modalHost: document.getElementById('modal-host'),
    modalSourceIp: document.getElementById('modal-source-ip'),
    modalSourceFile: document.getElementById('modal-source-file'),
    modalCommandBlock: document.getElementById('modal-command-block'),
    modalCommandLine: document.getElementById('modal-command-line'),
    modalDecodedBlock: document.getElementById('modal-decoded-block'),
    modalDecodedCommand: document.getElementById('modal-decoded-command'),
    modalRawSha256: document.getElementById('modal-raw-sha256'),
    modalRawRecord: document.getElementById('modal-raw-record'),
    btnCloseEventModal: document.getElementById('btn-close-event-modal'),
    btnModalCloseAction: document.getElementById('btn-modal-close-action'),
    btnCopyRawJson: document.getElementById('btn-copy-raw-json'),

    // Loading Modal
    loadingOverlay: document.getElementById('loading-overlay'),
    loadingDesc: document.getElementById('loading-desc'),
  };

  // Utility: Format File Size
  function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  // Utility: Escape HTML
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  // Utility: Format Timestamp
  function formatTimestamp(isoStr) {
    if (!isoStr) return '(missing timestamp)';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return String(isoStr);
      return d.toISOString().replace('T', ' ').replace('.000Z', ' UTC').replace('Z', ' UTC');
    } catch {
      return String(isoStr);
    }
  }

  // Utility: Format Duration
  function formatDuration(startIso, endIso) {
    if (!startIso || !endIso) return 'Single observation';
    try {
      const s = new Date(startIso).getTime();
      const e = new Date(endIso).getTime();
      if (isNaN(s) || isNaN(e)) return 'N/A';
      const diffSec = Math.max(0, Math.round((e - s) / 1000));
      if (diffSec === 0) return 'Instantaneous';
      if (diffSec < 60) return `${diffSec}s span`;
      const mins = Math.floor(diffSec / 60);
      const remSec = diffSec % 60;
      return `${mins}m ${remSec}s span`;
    } catch {
      return 'N/A';
    }
  }

  // Show Alert Banner
  function showAlert(message, type = 'info', durationMs = 5000) {
    elements.globalAlert.className = `alert-banner alert-${type}`;
    elements.alertMessage.textContent = message;
    elements.globalAlert.style.display = 'flex';
    if (durationMs > 0) {
      setTimeout(() => {
        if (elements.globalAlert.style.display === 'flex') {
          elements.globalAlert.style.display = 'none';
        }
      }, durationMs);
    }
  }

  // Live Clock
  function updateClock() {
    const now = new Date();
    elements.clockDisplay.textContent = now.toTimeString().split(' ')[0];
  }
  setInterval(updateClock, 1000);
  updateClock();

  // Navigation Controller
  function initNavigation() {
    elements.navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = item.getAttribute('href').replace('#', '');
        activateSection(targetId);
      });
    });
  }

  function activateSection(targetId) {
    elements.navItems.forEach(item => {
      if (item.getAttribute('href') === `#${targetId}`) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    if (targetId === 'coverage' || targetId === 'provenance') {
      elements.sections.forEach(sec => sec.classList.remove('active'));
      document.getElementById('section-overview').classList.add('active');
      const targetCard = document.getElementById(`section-${targetId}-card`);
      if (targetCard) {
        targetCard.scrollIntoView({ behavior: 'smooth' });
      }
    } else {
      elements.sections.forEach(sec => {
        if (sec.id === `section-${targetId}`) {
          sec.classList.add('active');
        } else {
          sec.classList.remove('active');
        }
      });
    }
  }

  // 1. Health Check
  async function checkBackendHealth() {
    try {
      const res = await fetch('/api/v1/health');
      if (res.ok) {
        const data = await res.json();
        elements.backendDot.className = 'status-indicator-dot dot-emerald';
        elements.backendStatusText.textContent = `v${data.version} Ready`;
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (err) {
      elements.backendDot.className = 'status-indicator-dot dot-crimson';
      elements.backendStatusText.textContent = 'Disconnected';
      showAlert(`Cannot connect to local TRACE-Verified backend: ${err.message}`, 'error', 0);
    }
  }

  // 2. Ollama Status Check
  async function checkOllamaStatus() {
    elements.ollamaDot.className = 'status-indicator-dot dot-amber';
    elements.ollamaStatusText.textContent = 'Probing...';
    try {
      const res = await fetch('/api/v1/ollama');
      if (res.ok) {
        const data = await res.json();
        if (data.available) {
          elements.ollamaDot.className = 'status-indicator-dot dot-emerald';
          elements.ollamaStatusText.textContent = data.model_installed ? 'Online (phi4-mini)' : 'Online (no model)';
        } else {
          elements.ollamaDot.className = 'status-indicator-dot dot-amber';
          elements.ollamaStatusText.textContent = 'Offline (Fallback active)';
        }
      }
    } catch (err) {
      elements.ollamaDot.className = 'status-indicator-dot dot-amber';
      elements.ollamaStatusText.textContent = 'Offline';
    }
  }

  // 3. Load Sample Catalog
  async function loadSamplesCatalog() {
    try {
      const res = await fetch('/api/v1/samples');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      renderSamples(data.samples || []);
    } catch (err) {
      elements.samplesContainer.innerHTML = `<span class="empty-coverage-state">Failed to load demo scenarios: ${escapeHtml(err.message)}</span>`;
    }
  }

  function renderSamples(samples) {
    elements.samplesContainer.innerHTML = '';
    samples.forEach(sample => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'sample-pill-btn';
      btn.title = sample.description;
      btn.innerHTML = `
        <span class="sample-icon-tag">${sample.id.replace('_', ' ')}</span>
        <span>${escapeHtml(sample.name)}</span>
      `;
      btn.addEventListener('click', () => selectSampleScenario(sample, btn));
      elements.samplesContainer.appendChild(btn);
    });
  }

  function selectSampleScenario(sample, btnElement) {
    state.stagedFiles = [];
    state.selectedSampleId = sample.id;

    document.querySelectorAll('.sample-pill-btn').forEach(b => b.classList.remove('active'));
    btnElement.classList.add('active');

    elements.stagedFilesList.innerHTML = '';
    sample.files.forEach(filename => {
      const item = document.createElement('div');
      item.className = 'staged-file-item';
      item.innerHTML = `
        <div class="staged-file-info">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          </svg>
          <span class="staged-file-name">${escapeHtml(filename)}</span>
          <span class="badge badge-subtle">Verified Fixture</span>
        </div>
      `;
      elements.stagedFilesList.appendChild(item);
    });

    elements.stagedCountBadge.textContent = sample.files.length;
    elements.btnClearStaged.style.display = 'inline-block';
    elements.btnRunAnalysis.disabled = false;
    showAlert(`Selected sample scenario: "${sample.name}". Click "Run Deterministic Analysis" to execute.`, 'info', 4000);
  }

  // 4. File Drag & Drop
  function initDragAndDrop() {
    const dropZone = elements.dropZone;

    ['dragenter', 'dragover'].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      dropZone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('dragover');
      });
    });

    dropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      handleFilesAdded(dt.files);
    });

    elements.btnBrowse.addEventListener('click', (e) => {
      e.stopPropagation();
      elements.fileInput.click();
    });

    dropZone.addEventListener('click', () => {
      elements.fileInput.click();
    });

    elements.fileInput.addEventListener('change', () => {
      handleFilesAdded(elements.fileInput.files);
      elements.fileInput.value = '';
    });

    elements.btnClearStaged.addEventListener('click', () => {
      state.stagedFiles = [];
      state.selectedSampleId = null;
      document.querySelectorAll('.sample-pill-btn').forEach(b => b.classList.remove('active'));
      renderStagedFiles();
    });
  }

  function handleFilesAdded(fileList) {
    if (!fileList || fileList.length === 0) return;
    state.selectedSampleId = null;
    document.querySelectorAll('.sample-pill-btn').forEach(b => b.classList.remove('active'));

    const allowedExtensions = ['.csv', '.json', '.jsonl', '.ndjson'];
    let addedCount = 0;

    Array.from(fileList).forEach(file => {
      const name = file.name.toLowerCase();
      const isAllowed = allowedExtensions.some(ext => name.endsWith(ext));
      if (isAllowed) {
        if (!state.stagedFiles.some(f => f.name === file.name)) {
          state.stagedFiles.push(file);
          addedCount++;
        }
      } else {
        showAlert(`Skipped "${file.name}": Unsupported format. Allowed: CSV, JSON, JSONL, NDJSON.`, 'warning', 4000);
      }
    });

    if (addedCount > 0) {
      renderStagedFiles();
    }
  }

  function renderStagedFiles() {
    const list = elements.stagedFilesList;
    list.innerHTML = '';

    if (state.stagedFiles.length === 0 && !state.selectedSampleId) {
      list.innerHTML = `
        <div class="empty-staged-state">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p>No log files staged yet.</p>
          <span>Select a sample scenario above or drop log files into the upload box.</span>
        </div>
      `;
      elements.stagedCountBadge.textContent = '0';
      elements.btnClearStaged.style.display = 'none';
      elements.btnRunAnalysis.disabled = true;
      return;
    }

    state.stagedFiles.forEach((file, index) => {
      const item = document.createElement('div');
      item.className = 'staged-file-item';
      item.innerHTML = `
        <div class="staged-file-info">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          </svg>
          <span class="staged-file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
          <span class="staged-file-size">${formatBytes(file.size)}</span>
        </div>
        <button type="button" class="btn-remove-staged" title="Remove file" data-index="${index}">&times;</button>
      `;

      item.querySelector('.btn-remove-staged').addEventListener('click', (e) => {
        e.stopPropagation();
        state.stagedFiles.splice(index, 1);
        renderStagedFiles();
      });

      list.appendChild(item);
    });

    elements.stagedCountBadge.textContent = state.stagedFiles.length;
    elements.btnClearStaged.style.display = 'inline-block';
    elements.btnRunAnalysis.disabled = state.stagedFiles.length === 0;
  }

  // 5. Gather Analysis Options
  function getAnalysisOptions() {
    const approvedRaw = elements.cfgApprovedIds.value.trim();
    const approvedIds = approvedRaw ? approvedRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

    return {
      auth_window_minutes: parseFloat(elements.cfgAuthWindow.value) || 10,
      brute_force_threshold: parseInt(elements.cfgBruteThreshold.value, 10) || 5,
      spray_account_threshold: parseInt(elements.cfgSprayThreshold.value, 10) || 5,
      success_threshold: parseInt(elements.cfgSuccessThreshold.value, 10) || 5,
      correlation_window_minutes: parseFloat(elements.cfgCorrWindow.value) || 30,
      max_incident_duration_minutes: parseFloat(elements.cfgMaxDuration.value) || 240,
      approved_finding_ids: approvedIds,
    };
  }

  // 6. Run Deterministic Analysis
  async function runAnalysis() {
    if (state.isAnalyzing) return;
    if (state.stagedFiles.length === 0 && !state.selectedSampleId) {
      showAlert('Please stage at least one log file or select a sample scenario.', 'warning');
      return;
    }

    state.isAnalyzing = true;
    resetAnalysisStateForNewRun();
    elements.btnRunAnalysis.disabled = true;
    elements.loadingOverlay.style.display = 'flex';
    elements.loadingDesc.textContent = 'Parsing canonical events & evaluating deterministic detectors...';

    const options = getAnalysisOptions();
    const startTime = performance.now();

    try {
      let response;
      if (state.selectedSampleId) {
        response = await fetch(`/api/v1/samples/${state.selectedSampleId}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ options }),
        });
      } else {
        const formData = new FormData();
        formData.append('options', JSON.stringify(options));
        state.stagedFiles.forEach(file => {
          formData.append('files', file, file.name);
        });

        response = await fetch('/api/v1/analyze', {
          method: 'POST',
          body: formData,
        });
      }

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || `Server responded with status ${response.status}`);
      }

      const report = await response.json();
      const elapsedMs = Math.round(performance.now() - startTime);

      // Save Authoritative Backend Result to State & Window
      state.currentAnalysis = report;
      window.currentAnalysis = report;

      // Populate lookup maps for O(1) forensic inspection
      state.supportingEventsMap.clear();
      (report.supporting_events || []).forEach(evt => {
        state.supportingEventsMap.set(evt.event_id, evt);
      });
      state.findingsMap.clear();
      (report.findings || []).forEach(fnd => {
        state.findingsMap.set(fnd.finding_id, fnd);
      });

      // Milestone 4: Explanation state initialization
      state.explanationMap.clear();
      if (state.explanationPollingTimer) {
        clearInterval(state.explanationPollingTimer);
        state.explanationPollingTimer = null;
      }
      if (state.explanationElapsedTimer) {
        clearInterval(state.explanationElapsedTimer);
        state.explanationElapsedTimer = null;
      }
      state.explanationJobStatus = report.job_status || 'idle';
      state.explanationJobError = report.job_error || null;
      state.explanationElapsedSeconds = 0;
      (report.ai_explanations || []).forEach(exp => {
        if (exp.incident_id) {
          state.explanationMap.set(exp.incident_id, exp);
        }
      });
      if (elements.btnRequestExplanation) {
        elements.btnRequestExplanation.disabled = false;
        elements.btnRequestExplanationText.textContent = state.explanationMap.size > 0 ? 'Re-generate Explanation' : 'Request Local Explanation';
      }

      // Render Overview Telemetry
      renderAnalysisReport(report, elapsedMs);

      // Render Incidents Explorer List
      filterAndRenderIncidents();

      // Show back list view if previously in detail
      showIncidentsListView();

      // Auto-navigate to Incidents Triage if incidents exist, else Overview
      if ((report.incidents || []).length > 0) {
        activateSection('incidents');
        showAlert(`Deterministic analysis completed in ${elapsedMs}ms: Found ${report.incidents.length} incident(s).`, 'success', 5000);
      } else {
        activateSection('overview');
        const completion = hasCompleteAnalysisCoverage(report)
          ? '0 incidents detected (clean baseline).'
          : '0 incidents detected, but coverage is incomplete; review ingestion warnings and detector coverage.';
        showAlert(`Deterministic analysis completed in ${elapsedMs}ms: ${completion}`,
          hasCompleteAnalysisCoverage(report) ? 'success' : 'warning', 5000);
      }

    } catch (err) {
      showAlert(`Analysis failed: ${err.message}`, 'error', 0);
    } finally {
      state.isAnalyzing = false;
      elements.btnRunAnalysis.disabled = false;
      elements.loadingOverlay.style.display = 'none';
    }
  }

  function resetAnalysisStateForNewRun() {
    // Invalidate in-flight explanation requests and polling responses first.
    state.analysisGeneration++;
    state.currentAnalysis = null;
    window.currentAnalysis = null;
    state.selectedIncidentId = null;
    state.supportingEventsMap.clear();
    state.findingsMap.clear();
    state.explanationMap.clear();

    if (state.explanationPollingTimer) {
      clearInterval(state.explanationPollingTimer);
      state.explanationPollingTimer = null;
    }
    if (state.explanationElapsedTimer) {
      clearInterval(state.explanationElapsedTimer);
      state.explanationElapsedTimer = null;
    }
    state.explanationJobStatus = 'idle';
    state.explanationJobError = null;
    state.explanationElapsedSeconds = 0;
    state.filterSeverity = 'all';
    state.searchTerm = '';
    state.sortOrder = 'score_desc';
    elements.incidentSearchInput.value = '';
    elements.incidentSortSelect.value = 'score_desc';
    elements.severityFilterPills.forEach(pill => {
      pill.classList.toggle('active', pill.dataset.severity === 'all');
    });

    if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = false;
    if (elements.btnRequestExplanationText) {
      elements.btnRequestExplanationText.textContent = 'Request Local Explanation';
    }

    elements.metricIncidentsCount.textContent = '0';
    elements.navIncidentBadge.textContent = '0';
    elements.navIncidentBadge.style.display = 'none';
    elements.badgeIncidents.className = 'metric-badge badge-neutral';
    elements.badgeIncidents.textContent = 'None Observed';
    elements.analysisIdTag.textContent = 'No analysis loaded';
    elements.incidentsAnalysisId.textContent = 'No analysis loaded';
    elements.metricTotalRows.textContent = '0';
    elements.metricSourcesCount.textContent = 'From 0 source file(s)';
    elements.metricAcceptedRows.textContent = '0';
    elements.metricMalformedRows.textContent = '0';
    elements.metricMalformedRate.textContent = '0.0% malformed rows';
    elements.badgeIntegrity.className = 'metric-badge badge-neutral';
    elements.badgeIntegrity.textContent = 'Waiting';
    elements.metricSeverityPills.innerHTML = `
      <span class="pill-mini pill-crit">0 Crit</span>
      <span class="pill-mini pill-high">0 High</span>
      <span class="pill-mini pill-med">0 Med</span>
      <span class="pill-mini pill-low">0 Low</span>
    `;
    elements.metricCoverageRate.textContent = '0%';
    elements.badgeCoverage.textContent = '0/4';
    elements.metricCoverageDetail.textContent = '0 active, 4 skipped';

    closeEventModal();
    showIncidentsListView();
    renderIncidentsPreview([]);
    renderDetectorCoverageGrid([]);
    renderSourceProvenance([]);
    renderWarnings([]);
    filterAndRenderIncidents();
  }

  function hasCompleteAnalysisCoverage(report) {
    const coverage = report.detector_coverage || [];
    const ingestion = report.ingestion || {};
    const requiredDetectors = [
      'authentication_failures', 'success_after_failures',
      'privilege_changes', 'suspicious_process',
    ];
    const executedIds = new Set(coverage.filter(item => item.executed).map(item => item.detector_id));
    return requiredDetectors.every(id => executedIds.has(id)) && coverage.every(item => item.executed) &&
      (ingestion.accepted_rows || 0) > 0 && (ingestion.malformed_rows || 0) === 0;
  }

  // 7. Render Analysis Telemetry (Overview)
  function renderAnalysisReport(report, elapsedMs) {
    const ingestion = report.ingestion || {};
    const incidents = report.incidents || [];
    const coverage = report.detector_coverage || [];
    const sources = report.source_ingestion || [];
    const warnings = [
      ...(ingestion.warnings || []),
      ...(report.approval_warnings || []),
    ];

    // Tags
    const tagHtml = `
      <span class="text-secondary">Analysis:</span> <strong>${escapeHtml(report.analysis_id)}</strong>
      <span class="text-secondary" style="margin-left:8px;">(${elapsedMs}ms)</span>
    `;
    elements.analysisIdTag.innerHTML = tagHtml;
    elements.incidentsAnalysisId.innerHTML = tagHtml;

    // Total Events
    elements.metricTotalRows.textContent = (ingestion.total_rows || 0).toLocaleString();
    elements.metricSourcesCount.textContent = `From ${sources.length} source file(s)`;

    // Integrity
    const accepted = ingestion.accepted_rows || 0;
    const malformed = ingestion.malformed_rows || 0;
    const total = ingestion.total_rows || 1;
    elements.metricAcceptedRows.textContent = accepted.toLocaleString();
    elements.metricMalformedRows.textContent = malformed.toLocaleString();
    const malformedRate = ((malformed / total) * 100).toFixed(1);
    elements.metricMalformedRate.textContent = `${malformedRate}% malformed rows`;
    if (malformed > 0) {
      elements.badgeIntegrity.className = 'metric-badge badge-amber';
      elements.badgeIntegrity.textContent = 'Partial Warnings';
    } else {
      elements.badgeIntegrity.className = 'metric-badge badge-emerald';
      elements.badgeIntegrity.textContent = '100% Valid';
    }

    // Incidents Metric
    elements.metricIncidentsCount.textContent = incidents.length.toString();
    elements.navIncidentBadge.textContent = incidents.length.toString();
    elements.navIncidentBadge.style.display = incidents.length > 0 ? 'inline-block' : 'none';

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    incidents.forEach(inc => {
      const sev = (inc.severity || 'low').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });

    elements.metricSeverityPills.innerHTML = `
      <span class="pill-mini pill-crit">${counts.critical} Crit</span>
      <span class="pill-mini pill-high">${counts.high} High</span>
      <span class="pill-mini pill-med">${counts.medium} Med</span>
      <span class="pill-mini pill-low">${counts.low} Low</span>
    `;

    if (counts.critical > 0) {
      elements.badgeIncidents.className = 'metric-badge badge-crimson';
      elements.badgeIncidents.textContent = 'Critical Action';
    } else if (counts.high > 0) {
      elements.badgeIncidents.className = 'metric-badge badge-amber';
      elements.badgeIncidents.textContent = 'High Priority';
    } else if (incidents.length > 0) {
      elements.badgeIncidents.className = 'metric-badge badge-emerald';
      elements.badgeIncidents.textContent = 'Triaged';
    } else {
      elements.badgeIncidents.className = 'metric-badge badge-neutral';
      elements.badgeIncidents.textContent = 'None Observed';
    }

    // Detector Coverage
    const executedCount = coverage.filter(c => c.executed).length;
    const totalDetectors = coverage.length || 4;
    const coveragePercent = Math.round((executedCount / totalDetectors) * 100);
    elements.metricCoverageRate.textContent = `${coveragePercent}%`;
    elements.badgeCoverage.textContent = `${executedCount}/${totalDetectors}`;
    elements.metricCoverageDetail.textContent = `${executedCount} active, ${totalDetectors - executedCount} skipped`;

    // Overview Incidents Preview List
    renderIncidentsPreview(incidents);

    // Detector Coverage Grid
    renderDetectorCoverageGrid(coverage);

    // Provenance List
    renderSourceProvenance(sources);

    // Warnings
    renderWarnings(warnings);
  }

  function renderIncidentsPreview(incidents) {
    elements.incidentsPreviewList.innerHTML = '';
    if (incidents.length === 0) {
      elements.incidentsPreviewCard.style.display = 'none';
      return;
    }

    elements.incidentsPreviewCard.style.display = 'block';
    incidents.slice(0, 5).forEach(inc => {
      const sev = (inc.severity || 'low').toLowerCase();
      const item = document.createElement('div');
      item.className = 'incident-preview-item';
      item.style.cursor = 'pointer';
      item.innerHTML = `
        <div class="incident-preview-info">
          <span class="pill-mini pill-${sev === 'critical' ? 'crit' : (sev === 'high' ? 'high' : (sev === 'medium' ? 'med' : 'low'))}">
            ${inc.severity.toUpperCase()}
          </span>
          <div>
            <div class="incident-preview-title">${escapeHtml(inc.title)}</div>
            <div class="incident-preview-id">ID: ${escapeHtml(inc.incident_id)} &bull; Affected: ${(inc.affected_users || []).map(escapeHtml).join(', ') || 'N/A'}</div>
          </div>
        </div>
        <div class="incident-preview-score font-mono text-cyan">
          Score: ${inc.score}/100 &rarr;
        </div>
      `;
      item.addEventListener('click', () => {
        activateSection('incidents');
        selectIncident(inc.incident_id);
      });
      elements.incidentsPreviewList.appendChild(item);
    });

    if (incidents.length > 5) {
      const more = document.createElement('div');
      more.className = 'empty-coverage-state';
      more.style.cursor = 'pointer';
      more.textContent = `+ View all ${incidents.length} correlated incidents in Incident Explorer &rarr;`;
      more.addEventListener('click', () => {
        activateSection('incidents');
        showIncidentsListView();
      });
      elements.incidentsPreviewList.appendChild(more);
    }
  }

  function renderDetectorCoverageGrid(coverage) {
    const grid = elements.detectorGrid;
    grid.innerHTML = '';

    if (!coverage || coverage.length === 0) {
      grid.innerHTML = '<div class="empty-coverage-state">No detector coverage data returned.</div>';
      return;
    }

    const detectorTitles = {
      authentication_failures: 'Repeated Authentication Failures',
      success_after_failures: 'Success After Repeated Failures',
      privilege_changes: 'Privilege & Group Membership Changes',
      suspicious_process: 'Suspicious Process & Script Host Execution',
    };

    coverage.forEach(det => {
      const title = detectorTitles[det.detector_id] || det.detector_id;
      const isExecuted = det.executed;
      const card = document.createElement('div');
      card.className = 'detector-item-card';
      card.innerHTML = `
        <div class="detector-item-header">
          <div>
            <div class="detector-item-name">${escapeHtml(title)}</div>
            <div class="detector-item-id">${escapeHtml(det.detector_id)}</div>
          </div>
          <span class="badge ${isExecuted ? 'badge-emerald' : 'badge-amber'}">
            ${isExecuted ? 'EXECUTED' : 'SKIPPED'}
          </span>
        </div>
        <div class="detector-item-reason">${escapeHtml(det.reason)}</div>
        <div class="detector-item-counts font-mono">
          <span>Candidates: <strong class="detector-count-val">${det.candidate_events ?? 0}</strong></span>
          <span>Skipped: <strong class="detector-count-val">${det.skipped_events ?? 0}</strong></span>
        </div>
      `;
      grid.appendChild(card);
    });
  }

  function renderSourceProvenance(sources) {
    const list = elements.sourceList;
    list.innerHTML = '';

    if (!sources || sources.length === 0) {
      list.innerHTML = '<div class="empty-coverage-state">No source files recorded.</div>';
      return;
    }

    sources.forEach(src => {
      const item = document.createElement('div');
      item.className = 'source-item';
      const fields = src.field_present_rows || {};
      const fieldTagsHtml = Object.entries(fields)
        .map(([k, count]) => `<span class="field-tag ${count > 0 ? 'present' : ''}">${escapeHtml(k)}: ${count}</span>`)
        .join('');

      item.innerHTML = `
        <div class="source-item-header">
          <span class="source-name">${escapeHtml(src.source)}</span>
          <span class="badge ${src.error ? 'badge-crimson' : 'badge-emerald'}">
            ${src.error ? 'ERROR' : 'PARSED'}
          </span>
        </div>
        <div class="source-stats-row font-mono">
          <span>Total: <strong>${src.total_rows || 0}</strong></span>
          <span>Accepted: <strong class="text-emerald">${src.accepted_rows || 0}</strong></span>
          <span>Malformed: <strong class="text-crimson">${src.malformed_rows || 0}</strong></span>
        </div>
        <div class="source-fields-tags">
          ${fieldTagsHtml || '<span class="field-tag">No recognized canonical fields</span>'}
        </div>
      `;
      list.appendChild(item);
    });
  }

  function renderWarnings(warnings) {
    const card = elements.sectionWarningsCard;
    const list = elements.warningsList;
    list.innerHTML = '';

    if (!warnings || warnings.length === 0) {
      card.style.display = 'none';
      return;
    }

    card.style.display = 'block';
    elements.warningsCountBadge.textContent = `${warnings.length} Warning(s)`;
    warnings.forEach(warn => {
      const li = document.createElement('li');
      li.className = 'warning-item';
      li.textContent = warn;
      list.appendChild(li);
    });
  }

  // =========================================================================
  // MILESTONE 3: INCIDENT EXPLORER CONTROLLER
  // =========================================================================

  function initIncidentExplorer() {
    // Search input
    elements.incidentSearchInput.addEventListener('input', (e) => {
      state.searchTerm = e.target.value.toLowerCase().trim();
      filterAndRenderIncidents();
    });

    // Severity filter pills
    elements.severityFilterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        elements.severityFilterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        state.filterSeverity = pill.dataset.severity;
        filterAndRenderIncidents();
      });
    });

    // Sort select
    elements.incidentSortSelect.addEventListener('change', (e) => {
      state.sortOrder = e.target.value;
      filterAndRenderIncidents();
    });

    // Back to incidents button
    elements.btnBackToIncidents.addEventListener('click', showIncidentsListView);

    // Detail Sub-tabs
    elements.subtabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.dataset.tab;
        elements.subtabBtns.forEach(b => b.classList.remove('active'));
        elements.subtabContents.forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        const contentPanel = document.getElementById(targetTab);
        if (contentPanel) contentPanel.classList.add('active');
      });
    });

    // Copy Incident ID click
    elements.detailIncidentId.addEventListener('click', () => {
      const id = elements.detailIncidentId.textContent;
      navigator.clipboard.writeText(id).then(() => {
        showAlert(`Copied Incident ID: ${id}`, 'info', 2500);
      });
    });

    // Modal Close
    elements.btnCloseEventModal.addEventListener('click', closeEventModal);
    elements.btnModalCloseAction.addEventListener('click', closeEventModal);
    elements.eventModal.addEventListener('click', (e) => {
      if (e.target === elements.eventModal) closeEventModal();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && elements.eventModal.style.display === 'flex') {
        closeEventModal();
      }
    });
  }

  function showIncidentsListView() {
    elements.incidentDetailView.style.display = 'none';
    elements.incidentsListView.style.display = 'block';
    state.selectedIncidentId = null;
  }

  function filterAndRenderIncidents() {
    const container = elements.incidentCardsContainer;
    container.innerHTML = '';

    if (!state.currentAnalysis) {
      container.innerHTML = `
        <div class="empty-state-box">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <div class="empty-state-title">No Incident Analysis Available</div>
          <div class="empty-state-desc">Select a sample scenario in Log Ingestion or upload log files to correlate deterministic security incidents.</div>
        </div>
      `;
      return;
    }

    const allIncidents = state.currentAnalysis.incidents || [];
    if (allIncidents.length === 0) {
      const completeCoverage = hasCompleteAnalysisCoverage(state.currentAnalysis);
      const emptyDescription = completeCoverage
        ? 'No suspicious multi-stage attack patterns were detected in the accepted logs. All available deterministic detectors completed without findings.'
        : 'No incident was formed, but one or more detectors were skipped or source rows were malformed. Review detector coverage and ingestion warnings before treating this as a clean baseline.';
      container.innerHTML = `
        <div class="empty-state-box">
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.75">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
          <div class="empty-state-title text-emerald">0 Incidents Correlated</div>
          <div class="empty-state-desc">${escapeHtml(emptyDescription)}</div>
        </div>
      `;
      return;
    }

    // Filter by Severity
    let filtered = allIncidents.filter(inc => {
      if (state.filterSeverity === 'all') return true;
      return (inc.severity || '').toLowerCase() === state.filterSeverity;
    });

    // Filter by Search Query
    if (state.searchTerm) {
      const q = state.searchTerm;
      filtered = filtered.filter(inc => {
        const titleMatch = (inc.title || '').toLowerCase().includes(q);
        const idMatch = (inc.incident_id || '').toLowerCase().includes(q);
        const usersMatch = (inc.affected_users || []).some(u => u.toLowerCase().includes(q));
        const hostsMatch = (inc.affected_hosts || []).some(h => h.toLowerCase().includes(q));
        const stagesMatch = (inc.attack_stages || []).some(s => s.stage_id.toLowerCase().includes(q));
        return titleMatch || idMatch || usersMatch || hostsMatch || stagesMatch;
      });
    }

    // Sort
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0, unknown: 0 };
    filtered.sort((a, b) => {
      if (state.sortOrder === 'score_desc') return b.score - a.score;
      if (state.sortOrder === 'score_asc')  return a.score - b.score;
      if (state.sortOrder === 'time_desc')  return (b.first_observed || '').localeCompare(a.first_observed || '');
      if (state.sortOrder === 'time_asc')   return (a.first_observed || '').localeCompare(b.first_observed || '');
      if (state.sortOrder === 'severity')   return (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
      return 0;
    });

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state-box">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <div class="empty-state-title">No Matching Incidents</div>
          <div class="empty-state-desc">No incidents match the active search term "${escapeHtml(state.searchTerm)}" and severity filter "${escapeHtml(state.filterSeverity)}".</div>
        </div>
      `;
      return;
    }

    // Render Incident Cards
    filtered.forEach(inc => {
      const sev = (inc.severity || 'low').toLowerCase();
      const card = document.createElement('div');
      card.className = `incident-card sev-${sev}`;

      const stagesPillsHtml = (inc.attack_stages || [])
        .map(s => `<span class="stage-pill">${escapeHtml(s.stage_id.replace('_', ' '))}</span>`)
        .join('');

      card.innerHTML = `
        <div class="incident-card-header">
          <div class="incident-card-title" title="${escapeHtml(inc.title)}">${escapeHtml(inc.title)}</div>
          <div class="incident-card-score">
            <span class="card-score-num text-${sev === 'critical' ? 'crimson' : (sev === 'high' ? 'amber' : 'cyan')}">${inc.score}</span>
            <span class="card-score-label">Score</span>
          </div>
        </div>

        <div class="incident-card-meta">
          <span class="pill-mini pill-${sev === 'critical' ? 'crit' : (sev === 'high' ? 'high' : (sev === 'medium' ? 'med' : 'low'))}">
            ${inc.severity.toUpperCase()}
          </span>
          <span class="incident-card-id font-mono">${escapeHtml(inc.incident_id)}</span>
          <span>&bull; ${formatDuration(inc.first_observed, inc.last_observed)}</span>
        </div>

        <div class="incident-card-entities font-mono">
          <div class="entity-row">
            <span class="entity-row-label">USERS:</span>
            <span class="entity-row-val text-cyan">${(inc.affected_users || []).map(escapeHtml).join(', ') || 'N/A'}</span>
          </div>
          <div class="entity-row">
            <span class="entity-row-label">HOSTS:</span>
            <span class="entity-row-val text-cyan">${(inc.affected_hosts || []).map(escapeHtml).join(', ') || 'N/A'}</span>
          </div>
        </div>

        <div class="incident-card-stages">
          ${stagesPillsHtml || '<span class="stage-pill">single stage</span>'}
        </div>
      `;

      card.addEventListener('click', () => selectIncident(inc.incident_id));
      container.appendChild(card);
    });
  }

  // =========================================================================
  // MILESTONE 3: INCIDENT DETAIL VIEW CONTROLLER
  // =========================================================================

  function selectIncident(incidentId) {
    if (!state.currentAnalysis) return;
    const incidents = state.currentAnalysis.incidents || [];
    const incident = incidents.find(i => i.incident_id === incidentId);
    if (!incident) return;

    state.selectedIncidentId = incidentId;

    // Switch view
    elements.incidentsListView.style.display = 'none';
    elements.incidentDetailView.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // Hero Meta
    const sev = (incident.severity || 'low').toLowerCase();
    elements.detailBreadcrumbId.textContent = incident.incident_id;
    elements.detailIncidentId.textContent = incident.incident_id;
    elements.detailTitle.textContent = incident.title;
    elements.detailScoringNotice.textContent = incident.scoring_notice || 'Heuristic score for investigation prioritization; not a validated risk model.';
    elements.detailTimeSpan.textContent = `${formatTimestamp(incident.first_observed)} — ${formatTimestamp(incident.last_observed)} (${formatDuration(incident.first_observed, incident.last_observed)})`;

    elements.detailSeverityBadge.className = `pill-mini pill-${sev === 'critical' ? 'crit' : (sev === 'high' ? 'high' : (sev === 'medium' ? 'med' : 'low'))}`;
    elements.detailSeverityBadge.textContent = incident.severity.toUpperCase();

    // Score widget
    elements.detailScoreVal.textContent = incident.score.toString();
    elements.detailScoreFill.style.width = `${Math.min(100, Math.max(0, incident.score))}%`;

    // Affected Entities
    elements.detailUsersList.innerHTML = (incident.affected_users || [])
      .map(u => `<span class="entity-pill text-cyan">${escapeHtml(u)}</span>`)
      .join('') || '<span class="text-muted">None recognized</span>';

    elements.detailHostsList.innerHTML = (incident.affected_hosts || [])
      .map(h => `<span class="entity-pill text-cyan">${escapeHtml(h)}</span>`)
      .join('') || '<span class="text-muted">None recognized</span>';

    elements.detailCountsSummary.textContent = `${(incident.finding_ids || []).length} Findings &bull; ${(incident.supporting_event_ids || []).length} Supporting Events`;

    // Render Sub-tabs
    renderTimelineTab(incident);
    renderStagesTab(incident);
    renderEvidenceTab(incident);
    renderScoreTab(incident);
    renderGuidanceTab(incident);
    renderExplanationTab(incident);

    // Reset active subtab to Timeline by default
    elements.subtabBtns.forEach(b => b.classList.remove('active'));
    elements.subtabContents.forEach(c => c.classList.remove('active'));
    document.querySelector('.subtab-btn[data-tab="tab-timeline"]').classList.add('active');
    document.getElementById('tab-timeline').classList.add('active');
  }

  // TAB 1: Render Attack Timeline
  function renderTimelineTab(incident) {
    const container = elements.timelineListContainer;
    container.innerHTML = '';
    const timeline = incident.timeline || [];

    if (timeline.length === 0) {
      container.innerHTML = '<div class="empty-coverage-state">No timeline events recorded for this incident.</div>';
      return;
    }

    timeline.forEach(item => {
      const row = document.createElement('div');
      row.className = 'timeline-row';

      // Category detection for node dot
      const desc = (item.description || '').toLowerCase();
      let nodeClass = '';
      if (desc.includes('4625') || desc.includes('fail') || desc.includes('denied')) {
        nodeClass = 'node-crit';
      } else if (desc.includes('4624') || desc.includes('success')) {
        nodeClass = 'node-success';
      } else if (desc.includes('4728') || desc.includes('4732') || desc.includes('privilege') || desc.includes('member')) {
        nodeClass = 'node-priv';
      } else if (desc.includes('4688') || desc.includes('mshta') || desc.includes('powershell') || desc.includes('process')) {
        nodeClass = 'node-proc';
      }

      // Supporting event badges
      const eventButtonsHtml = (item.event_ids || []).map(id => `
        <button type="button" class="btn-inspect-event" data-event-id="${escapeHtml(id)}">
          ${escapeHtml(id)} &rarr;
        </button>
      `).join('');

      row.innerHTML = `
        <div class="timeline-node ${nodeClass}"></div>
        <div class="timeline-card">
          <div class="timeline-card-header">
            <span class="timeline-time">${formatTimestamp(item.timestamp)}</span>
            <span class="badge badge-subtle font-mono">${escapeHtml(item.description)}</span>
          </div>
          <div class="timeline-desc">Evidence Event Action: ${escapeHtml(item.description)}</div>
          <div class="timeline-meta-row">
            <div class="timeline-event-links">
              <span class="text-muted" style="font-size:0.72rem;">Evidence:</span>
              ${eventButtonsHtml || '<span class="text-muted">None</span>'}
            </div>
            <div class="font-mono text-muted" style="font-size:0.7rem;">
              Findings: ${(item.finding_ids || []).join(', ') || 'N/A'}
            </div>
          </div>
        </div>
      `;

      // Attach inspect event clicks
      row.querySelectorAll('.btn-inspect-event').forEach(btn => {
        btn.addEventListener('click', () => {
          openEventModal(btn.dataset.eventId);
        });
      });

      container.appendChild(row);
    });
  }

  // TAB 2: Render Attack Stages
  function renderStagesTab(incident) {
    const container = elements.stagesStepperContainer;
    container.innerHTML = '';
    const stages = incident.attack_stages || [];

    if (stages.length === 0) {
      container.innerHTML = '<div class="empty-coverage-state">No attack stages interpreted for this incident.</div>';
      return;
    }

    stages.forEach((stage, idx) => {
      const card = document.createElement('div');
      card.className = 'stage-step-card';

      const eventsBadgesHtml = (stage.event_ids || []).map(id => `
        <button type="button" class="btn-inspect-event" data-event-id="${escapeHtml(id)}">${escapeHtml(id)}</button>
      `).join('');

      card.innerHTML = `
        <div class="stage-step-num">${idx + 1}</div>
        <div class="stage-step-body">
          <div class="stage-step-top">
            <span class="stage-step-title text-cyan">${escapeHtml(stage.stage_id.replace(/_/g, ' '))}</span>
            <span class="stage-step-time">${formatTimestamp(stage.observed_at)}</span>
          </div>
          <div class="stage-step-rationale">${escapeHtml(stage.rationale)}</div>
          <div class="stage-step-badges">
            <span class="text-muted" style="font-size:0.72rem; align-self:center;">Stage Evidence:</span>
            ${eventsBadgesHtml || '<span class="text-muted font-mono" style="font-size:0.72rem;">No event IDs</span>'}
          </div>
        </div>
      `;

      card.querySelectorAll('.btn-inspect-event').forEach(btn => {
        btn.addEventListener('click', () => {
          openEventModal(btn.dataset.eventId);
        });
      });

      container.appendChild(card);
    });
  }

  // TAB 3: Render Supporting Events Table
  function renderEvidenceTab(incident) {
    const tbody = elements.evidenceTableBody;
    tbody.innerHTML = '';
    const supportIds = incident.supporting_event_ids || [];
    elements.evidenceCountBadge.textContent = `${supportIds.length} Events`;

    if (supportIds.length === 0) {
      tbody.innerHTML = '<tr><td colspan="11" class="empty-coverage-state">No supporting event records referenced.</td></tr>';
      return;
    }

    supportIds.forEach(id => {
      const evt = state.supportingEventsMap.get(id);
      const tr = document.createElement('tr');

      if (!evt) {
        tr.innerHTML = `
          <td class="font-mono text-muted">Unknown</td>
          <td class="font-mono text-cyan">${escapeHtml(id)}</td>
          <td colspan="8" class="text-muted">Event record not present in payload support set</td>
          <td>-</td>
        `;
      } else {
        const cmd = evt.command_line || (evt.process ? `Process: ${evt.process}` : '-');
        tr.innerHTML = `
          <td class="font-mono">${formatTimestamp(evt.timestamp)}</td>
          <td class="font-mono text-cyan">${escapeHtml(evt.event_id)}</td>
          <td><span class="badge badge-subtle font-mono">${escapeHtml(evt.event_type || '-')}</span></td>
          <td class="font-mono">${escapeHtml(evt.user || '-')}</td>
          <td class="font-mono">${escapeHtml(evt.actor || '-')}</td>
          <td class="font-mono">${escapeHtml(evt.target_member || '-')}</td>
          <td class="font-mono">${escapeHtml(evt.target_group || '-')}</td>
          <td class="font-mono">${escapeHtml(evt.host || '-')}</td>
          <td class="font-mono">${escapeHtml(evt.source_ip || '-')}</td>
          <td class="font-mono" style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(cmd)}">
            ${escapeHtml(cmd)}
          </td>
          <td>
            <button type="button" class="btn-inspect-event" data-event-id="${escapeHtml(evt.event_id)}">Inspect</button>
          </td>
        `;

        tr.querySelector('.btn-inspect-event').addEventListener('click', () => {
          openEventModal(evt.event_id);
        });
      }

      tbody.appendChild(tr);
    });
  }

  // TAB 4: Render Score Breakdown Table
  function renderScoreTab(incident) {
    const tbody = elements.scoreTableBody;
    tbody.innerHTML = '';
    const breakdown = incident.score_breakdown || [];

    if (breakdown.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-coverage-state">No score breakdown items returned.</td></tr>';
      return;
    }

    breakdown.forEach(item => {
      const tr = document.createElement('tr');
      const pts = item.points || 0;
      let ptsColor = 'text-secondary';
      if (pts > 0) ptsColor = 'text-emerald';
      if (pts < 0) ptsColor = 'text-crimson';

      tr.innerHTML = `
        <td><span class="badge badge-subtle font-mono">${escapeHtml(item.category)}</span></td>
        <td class="font-mono font-bold ${ptsColor}">${pts > 0 ? '+' : ''}${pts}</td>
        <td class="font-mono text-muted">${escapeHtml(item.code)}</td>
        <td>${escapeHtml(item.explanation)}</td>
        <td class="font-mono text-muted">${(item.finding_ids || []).join(', ') || '-'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // TAB 5: Render Investigative Guidance & Limitations
  function renderGuidanceTab(incident) {
    // Next Steps
    const stepsList = elements.detailNextStepsList;
    stepsList.innerHTML = '';
    const steps = incident.recommended_next_steps || [];
    if (steps.length === 0) {
      stepsList.innerHTML = '<li class="text-muted">No deterministic next steps specified.</li>';
    } else {
      steps.forEach(step => {
        const li = document.createElement('li');
        li.className = 'step-checklist-item';
        li.innerHTML = `
          <svg class="step-check-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <span>${escapeHtml(step)}</span>
        `;
        stepsList.appendChild(li);
      });
    }

    // Correlation Rationale
    const ratList = elements.detailRationaleList;
    ratList.innerHTML = '';
    const rationales = incident.correlation_rationale || [];
    if (rationales.length === 0) {
      ratList.innerHTML = '<li class="text-muted">No correlation rationale records available.</li>';
    } else {
      rationales.forEach(r => {
        const li = document.createElement('li');
        li.className = 'guidance-item';
        li.innerHTML = `<strong>${escapeHtml(r.finding_id)}:</strong> ${escapeHtml(r.reason)}`;
        ratList.appendChild(li);
      });
    }

    // Limitations & Missing Evidence
    const limList = elements.detailLimitationsList;
    limList.innerHTML = '';
    const limits = [
      ...(incident.missing_evidence || []).map(m => `[Missing Evidence] ${m}`),
      ...(incident.limitations || []),
      ...(incident.correlation_warnings || []).map(w => `[Chronology Warning] ${w}`),
    ];

    if (limits.length === 0) {
      limList.innerHTML = '<li class="text-muted">No explicit limitations or warnings noted for this incident.</li>';
    } else {
      limits.forEach(item => {
        const li = document.createElement('li');
        li.className = 'guidance-item';
        li.textContent = item;
        limList.appendChild(li);
      });
    }
  }

  // =========================================================================
  // MILESTONE 3: FORENSIC EVENT INSPECTOR MODAL
  // =========================================================================

  function openEventModal(eventId) {
    const evt = state.supportingEventsMap.get(eventId);
    if (!evt) {
      showAlert(`Supporting event '${eventId}' is not available in the current payload.`, 'warning');
      return;
    }

    elements.modalEventId.textContent = evt.event_id;
    elements.modalTimestamp.textContent = formatTimestamp(evt.timestamp);
    elements.modalEventType.textContent = evt.event_type || '(none)';
    elements.modalUser.textContent = evt.user || '(unspecified)';
    elements.modalActor.textContent = evt.actor || '(none)';
    elements.modalTargetMember.textContent = evt.target_member || '(none)';
    elements.modalTargetGroup.textContent = evt.target_group || '(none)';
    elements.modalHost.textContent = evt.host || '(unspecified)';
    elements.modalSourceIp.textContent = evt.source_ip || '(none)';
    elements.modalSourceFile.textContent = `${evt.source || 'unknown'} (Row ${evt.source_row ?? 'N/A'})`;

    // Process & Command Line
    if (evt.command_line || evt.process) {
      elements.modalCommandBlock.style.display = 'flex';
      elements.modalCommandLine.textContent = evt.command_line || `Process: ${evt.process}`;
    } else {
      elements.modalCommandBlock.style.display = 'none';
    }

    // Check if any finding links to this event with decoded command
    let decodedCommand = null;
    state.findingsMap.forEach(fnd => {
      if ((fnd.supporting_event_ids || []).includes(eventId) && fnd.decoded_command_line) {
        decodedCommand = fnd.decoded_command_line;
      }
    });

    if (decodedCommand) {
      elements.modalDecodedBlock.style.display = 'flex';
      elements.modalDecodedCommand.textContent = decodedCommand;
    } else {
      elements.modalDecodedBlock.style.display = 'none';
    }

    // Raw forensic record
    elements.modalRawSha256.textContent = `SHA-256: ${evt.raw_sha256 || 'N/A'}`;
    const formattedRawJson = JSON.stringify(evt.raw_record || {}, null, 2);
    elements.modalRawRecord.textContent = formattedRawJson;

    // Copy action
    elements.btnCopyRawJson.onclick = () => {
      navigator.clipboard.writeText(formattedRawJson).then(() => {
        const prev = elements.btnCopyRawJson.textContent;
        elements.btnCopyRawJson.textContent = 'Copied!';
        setTimeout(() => { elements.btnCopyRawJson.textContent = prev; }, 2000);
      });
    };

    elements.eventModal.style.display = 'flex';
  }

  function closeEventModal() {
    elements.eventModal.style.display = 'none';
  }

  // =========================================================================
  // MILESTONE 4: LOCAL SLM EXPLANATION CONTROLLER
  // =========================================================================

  async function requestExplanation() {
    if (!state.currentAnalysis || !state.currentAnalysis.analysis_id) {
      showAlert('No active analysis to explain. Ingest logs and run analysis first.', 'warning');
      return;
    }

    if (state.explanationJobStatus === 'queued' || state.explanationJobStatus === 'running') {
      showAlert('An explanation job is already in progress.', 'info');
      return;
    }

    const analysisId = state.currentAnalysis.analysis_id;
    const generation = state.analysisGeneration;

    const timeoutSec = Math.max(5, parseFloat(elements.cfgExplainTimeout?.value || 180));
    if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = true;
    if (elements.btnRequestExplanationText) elements.btnRequestExplanationText.textContent = 'Enqueuing...';

    try {
      const resp = await fetch(`/api/v1/analyses/${analysisId}/explanations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          max_explain: 3,
          explain_timeout: timeoutSec,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `Server returned HTTP ${resp.status}`);
      }

      const data = await resp.json();
      if (state.analysisGeneration !== generation ||
          !state.currentAnalysis || state.currentAnalysis.analysis_id !== analysisId) return;
      state.explanationJobStatus = data.job_status || 'queued';
      state.explanationElapsedSeconds = 0;

      // Start elapsed seconds counter
      if (state.explanationElapsedTimer) clearInterval(state.explanationElapsedTimer);
      state.explanationElapsedTimer = setInterval(() => {
        state.explanationElapsedSeconds++;
        if (state.explanationJobStatus === 'running' || state.explanationJobStatus === 'queued') {
          if (elements.btnRequestExplanationText) {
            elements.btnRequestExplanationText.textContent = `Generating (${state.explanationElapsedSeconds}s)...`;
          }
          const timerEl = document.getElementById('slm-loading-timer-val');
          if (timerEl) {
            timerEl.textContent = `${state.explanationElapsedSeconds}s`;
          }
        }
      }, 1000);

      // Start polling
      startExplanationPolling();

      // Update current selected incident tab if viewing it
      if (state.selectedIncidentId && state.currentAnalysis) {
        const inc = (state.currentAnalysis.incidents || []).find(i => i.incident_id === state.selectedIncidentId);
        if (inc) renderExplanationTab(inc);
      }

      showAlert('Local explanation queued in background. Ollama inference running asynchronously on loopback.', 'info', 4000);
    } catch (err) {
      if (state.analysisGeneration !== generation ||
          !state.currentAnalysis || state.currentAnalysis.analysis_id !== analysisId) return;
      if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = false;
      if (elements.btnRequestExplanationText) elements.btnRequestExplanationText.textContent = 'Request Local Explanation';
      showAlert(`Failed to queue explanation: ${err.message}`, 'error');
    }
  }

  function startExplanationPolling() {
    if (state.explanationPollingTimer) clearInterval(state.explanationPollingTimer);
    if (!state.currentAnalysis || !state.currentAnalysis.analysis_id) return;
    const analysisId = state.currentAnalysis.analysis_id;
    const generation = state.analysisGeneration;
    // Poll immediately once
    pollExplanationStatus(analysisId, generation);
    // Then poll every 2.5 seconds
    state.explanationPollingTimer = setInterval(() => {
      pollExplanationStatus(analysisId, generation);
    }, 2500);
  }

  async function pollExplanationStatus(analysisId, generation) {
    if (state.analysisGeneration !== generation || !state.currentAnalysis ||
        state.currentAnalysis.analysis_id !== analysisId) {
      return;
    }

    try {
      const resp = await fetch(`/api/v1/analyses/${analysisId}/explanations`);
      if (state.analysisGeneration !== generation || !state.currentAnalysis ||
          state.currentAnalysis.analysis_id !== analysisId) return;
      if (!resp.ok) return;

      const data = await resp.json();
      if (state.analysisGeneration !== generation || !state.currentAnalysis ||
          state.currentAnalysis.analysis_id !== analysisId) return;
      state.explanationJobStatus = data.job_status || 'idle';
      state.explanationJobError = data.job_error || null;

      if (Array.isArray(data.ai_explanations)) {
        data.ai_explanations.forEach(exp => {
          if (exp.incident_id) {
            state.explanationMap.set(exp.incident_id, exp);
          }
        });
        state.currentAnalysis.ai_explanations = data.ai_explanations;
      }

      // Check if job finished
      if (state.explanationJobStatus === 'completed' || state.explanationJobStatus === 'failed') {
        if (state.explanationPollingTimer) {
          clearInterval(state.explanationPollingTimer);
          state.explanationPollingTimer = null;
        }
        if (state.explanationElapsedTimer) {
          clearInterval(state.explanationElapsedTimer);
          state.explanationElapsedTimer = null;
        }

        if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = false;
        if (elements.btnRequestExplanationText) elements.btnRequestExplanationText.textContent = 'Re-generate Explanation';

        if (state.explanationJobStatus === 'completed') {
          showAlert('Local explanation generation completed and verified.', 'success', 4000);
        } else {
          showAlert(`Explanation job completed with fallback: ${state.explanationJobError || 'Diagnostic notice'}`, 'warning', 5000);
        }
      }

      // Re-render currently selected incident explanation tab
      if (state.selectedIncidentId && state.currentAnalysis) {
        const inc = (state.currentAnalysis.incidents || []).find(i => i.incident_id === state.selectedIncidentId);
        if (inc) renderExplanationTab(inc);
      }
    } catch {
      // Polling network blip on loopback: keep waiting
    }
  }

  function renderExplanationTab(incident) {
    const container = elements.explanationBodyContent;
    if (!container) return;
    container.innerHTML = '';

    const exp = state.explanationMap.get(incident.incident_id);
    const isJobActive = (state.explanationJobStatus === 'queued' || state.explanationJobStatus === 'running');

    // Update Subtab Pill Indicator
    if (elements.explanationSubtabBadge) {
      if (isJobActive) {
        elements.explanationSubtabBadge.style.display = 'inline-block';
        elements.explanationSubtabBadge.className = 'subtab-status-pill status-generating';
      } else if (exp) {
        elements.explanationSubtabBadge.style.display = 'inline-block';
        const st = exp.status;
        const cls = st === 'local_model' ? 'status-verified' : (st === 'deterministic_fallback' ? 'status-fallback' : 'status-rejected');
        elements.explanationSubtabBadge.className = `subtab-status-pill ${cls}`;
      } else {
        elements.explanationSubtabBadge.style.display = 'none';
      }
    }

    // STATE 1: Generating / In Progress
    if (isJobActive) {
      if (elements.explanationStatusBadge) {
        elements.explanationStatusBadge.className = 'badge badge-blue';
        elements.explanationStatusBadge.textContent = state.explanationJobStatus === 'queued' ? 'Queued' : 'Generating...';
      }
      if (elements.explanationStatusDesc) {
        elements.explanationStatusDesc.textContent = `Running local Ollama inference (${state.explanationElapsedSeconds}s elapsed)...`;
      }
      if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = true;
      if (elements.btnRequestExplanationText) {
        elements.btnRequestExplanationText.textContent = `Generating (${state.explanationElapsedSeconds}s)...`;
      }

      container.innerHTML = `
        <div class="slm-loading-state">
          <div class="slm-radar-spinner"></div>
          <div class="slm-loading-title">Synthesizing Local SLM Triage Explanation</div>
          <div class="slm-loading-timer">Elapsed Time: <span id="slm-loading-timer-val" class="font-mono">${state.explanationElapsedSeconds}s</span></div>
          <div class="slm-loading-note">
            Querying local <code>phi4-mini:latest</code> on loopback (<code>127.0.0.1:11434</code>). CPU inference can take up to 180 seconds. All deterministic incident scores and timelines remain completely accessible.
          </div>
        </div>
      `;
      return;
    }

    // STATE 2: Not Yet Requested or not available for this incident
    if (!exp) {
      if (elements.explanationStatusBadge) {
        elements.explanationStatusBadge.className = 'badge badge-neutral';
        elements.explanationStatusBadge.textContent = 'Not Requested';
      }
      if (elements.explanationModelBadge) {
        elements.explanationModelBadge.textContent = 'phi4-mini:latest';
      }
      if (elements.explanationStatusDesc) {
        elements.explanationStatusDesc.textContent = 'Advisory local SLM summary has not been requested for this incident yet.';
      }
      if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = false;
      if (elements.btnRequestExplanationText) elements.btnRequestExplanationText.textContent = 'Request Local Explanation';

      container.innerHTML = `
        <div class="slm-empty-state">
          <div class="slm-empty-icon">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
              <line x1="12" y1="22.08" x2="12" y2="12"/>
            </svg>
          </div>
          <div class="slm-empty-title">Generate Local SLM Incident Triage Summary</div>
          <div class="slm-empty-desc">
            Request an offline natural language interpretation of this incident using the local Ollama <code>phi4-mini:latest</code> model.
            Strict verification ensures only grounded event records and deterministic facts are presented.
          </div>
        </div>
      `;
      return;
    }

    // STATE 3: Explanation Available (Verified local_model, deterministic_fallback, or rejected_by_verification)
    const st = exp.status;
    let badgeClass = 'badge-fallback';
    let badgeText = 'DETERMINISTIC FALLBACK';
    if (st === 'local_model') {
      badgeClass = 'badge-verified';
      badgeText = 'VERIFIED LOCAL MODEL';
    } else if (st === 'rejected_by_verification') {
      badgeClass = 'badge-rejected';
      badgeText = 'REJECTED BY VERIFICATION';
    }

    if (elements.explanationStatusBadge) {
      elements.explanationStatusBadge.className = `badge ${badgeClass}`;
      elements.explanationStatusBadge.textContent = badgeText;
    }
    if (elements.explanationModelBadge) {
      elements.explanationModelBadge.textContent = exp.model || (st === 'local_model' ? 'phi4-mini:latest' : 'Rule Engine');
    }
    if (elements.explanationStatusDesc) {
      elements.explanationStatusDesc.textContent = exp.label || 'Triage summary available.';
    }
    if (elements.btnRequestExplanation) elements.btnRequestExplanation.disabled = false;
    if (elements.btnRequestExplanationText) elements.btnRequestExplanationText.textContent = 'Re-generate Explanation';

    // Build Evidence Pills Html
    const evidenceIds = exp.explanation?.evidence_ids || [];
    let evidencePillsHtml = '';
    if (evidenceIds.length === 0) {
      evidencePillsHtml = '<span class="text-muted font-mono" style="font-size:0.75rem;">(No specific canonical events cited)</span>';
    } else {
      evidencePillsHtml = evidenceIds.map(eid => `
        <button type="button" class="evidence-cite-pill" data-event-id="${escapeHtml(eid)}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          <span>${escapeHtml(eid)}</span>
          <span style="opacity:0.6;">&rarr;</span>
        </button>
      `).join('');
    }

    // Build Hypotheses Html
    const altExps = exp.explanation?.alternative_explanations || [];
    let hypothesesHtml = '';
    if (altExps.length === 0) {
      hypothesesHtml = '<li class="text-muted" style="font-size:0.8rem;">No alternative benign hypotheses offered.</li>';
    } else {
      hypothesesHtml = altExps.map(h => `
        <li class="slm-bullet-item">
          <svg class="slm-bullet-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>${escapeHtml(h)}</span>
        </li>
      `).join('');
    }

    // Build Advisory Next Steps Html
    const advActions = exp.explanation?.recommended_actions || [];
    let actionsHtml = '';
    if (advActions.length === 0) {
      actionsHtml = '<li class="text-muted" style="font-size:0.8rem;">No advisory actions generated.</li>';
    } else {
      actionsHtml = advActions.map(a => `
        <li class="slm-bullet-item">
          <svg class="slm-bullet-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          <div>
            <span class="slm-advisory-badge">Advisory</span>
            <span>${escapeHtml(a)}</span>
          </div>
        </li>
      `).join('');
    }

    // Build Limitations Html
    const limitations = exp.explanation?.limitations || [];
    let limitationsHtml = '';
    if (limitations.length === 0) {
      limitationsHtml = '<li class="text-muted" style="font-size:0.8rem;">No explicit model limitations recorded.</li>';
    } else {
      limitationsHtml = limitations.map(l => `
        <li class="slm-bullet-item">
          <svg class="slm-bullet-icon text-amber" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
          <span>${escapeHtml(l)}</span>
        </li>
      `).join('');
    }

    // Error banner html if present
    let errorBannerHtml = '';
    if (exp.error || exp.error_kind) {
      errorBannerHtml = `
        <div class="slm-error-banner">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; margin-top:2px;">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
          </svg>
          <div>
            <strong>Fallback Condition (${escapeHtml(exp.error_kind || 'diagnostic')}):</strong> ${escapeHtml(exp.error || 'The model did not return a verified output; deterministic fallback explanation active.')}
          </div>
        </div>
      `;
    }

    // Assemble Full Template
    container.innerHTML = `
      <!-- Verdict Banner -->
      <div class="slm-verdict-banner">
        <div class="verdict-left">
          <span class="badge ${badgeClass}">${badgeText}</span>
          <span class="verdict-label">${escapeHtml(exp.label || '')}</span>
        </div>
        <div class="font-mono text-muted" style="font-size:0.75rem;">
          Model: <span class="text-cyan">${escapeHtml(exp.model || 'none')}</span>
        </div>
      </div>

      ${errorBannerHtml}

      <!-- Explanation Sections Grid -->
      <div class="slm-sections-grid">
        <!-- Section 1: Summary & Interpretation -->
        <div class="slm-section-card">
          <div class="slm-section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            <span>Incident Summary & Attack Interpretation</span>
          </div>
          <div class="slm-prose" style="margin-bottom:0.75rem; font-weight:600; color:#f8fafc;">
            ${escapeHtml(exp.explanation?.incident_summary || '(No summary provided)')}
          </div>
          <div class="slm-prose">
            ${escapeHtml(exp.explanation?.attack_interpretation || '')}
          </div>
        </div>

        <!-- Section 2: Grounded Evidence Citations -->
        <div class="slm-section-card">
          <div class="slm-section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Cited Canonical Evidence Records (Click to Inspect)</span>
          </div>
          <div class="evidence-pills-row">
            ${evidencePillsHtml}
          </div>
        </div>

        <!-- Section 3: Alternative Hypotheses -->
        <div class="slm-section-card">
          <div class="slm-section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>Alternative Benign Hypotheses & Explanations</span>
          </div>
          <ul class="slm-bullet-list">
            ${hypothesesHtml}
          </ul>
        </div>

        <!-- Section 4: Advisory Next Steps -->
        <div class="slm-section-card">
          <div class="slm-section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
            <span>Advisory Investigative Next Steps (AI Suggested)</span>
          </div>
          <ul class="slm-bullet-list">
            ${actionsHtml}
          </ul>
        </div>

        <!-- Section 5: Model Boundaries & Limitations -->
        <div class="slm-section-card">
          <div class="slm-section-title text-amber">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>Model Caveats & Ingestion Boundaries</span>
          </div>
          <ul class="slm-bullet-list">
            ${limitationsHtml}
          </ul>
        </div>
      </div>
    `;

    // Attach click events to cited evidence pills to open the forensic inspector
    container.querySelectorAll('.evidence-cite-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        const eid = btn.dataset.eventId;
        if (eid) openEventModal(eid);
      });
    });
  }

  // =========================================================================
  // INITIAL STARTUP & BOOTSTRAP
  // =========================================================================

  function init() {
    initNavigation();
    initDragAndDrop();
    initIncidentExplorer();

    elements.btnRunAnalysis.addEventListener('click', runAnalysis);
    elements.btnRefreshOllama.addEventListener('click', checkOllamaStatus);
    if (elements.btnRequestExplanation) {
      elements.btnRequestExplanation.addEventListener('click', requestExplanation);
    }
    elements.alertClose.addEventListener('click', () => {
      elements.globalAlert.style.display = 'none';
    });

    checkBackendHealth();
    checkOllamaStatus();
    loadSamplesCatalog();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
