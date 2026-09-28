import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle,
  ChevronLeft,
  ChevronRight,
  FileSearch,
  FileText,
  Fingerprint,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Terminal,
  Wifi,
  XCircle,
} from "lucide-react";

import "./Analysis.css";

const API_BASE_URL = "http://127.0.0.1:8000";
const PAGE_SIZE = 15;

/* ============================================================
   HELPERS
============================================================ */

const asObject = (value) => {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value)
    ? value
    : {};
};

const asArray = (value) => {
  return Array.isArray(value) ? value : [];
};

const formatNumber = (value) => {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "0";
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return String(value);
  }

  return number.toLocaleString();
};

const formatPercentage = (value) => {
  const number = Number(value);

  if (Number.isNaN(number)) {
    return "0%";
  }

  return `${number.toFixed(2)}%`;
};

const getRiskClass = (risk) => {
  const value = String(risk || "").toUpperCase();

  if (
    value === "HIGH" ||
    value === "CRITICAL"
  ) {
    return "risk-high";
  }

  if (value === "MEDIUM") {
    return "risk-medium";
  }

  return "risk-low";
};

const getSeverityClass = (severity) => {
  const value = String(
    severity || ""
  ).toUpperCase();

  if (
    value === "HIGH" ||
    value === "CRITICAL"
  ) {
    return "severity-high";
  }

  if (value === "MEDIUM") {
    return "severity-medium";
  }

  return "severity-low";
};

const getEventDescription = (event) => {
  if (!event) {
    return "Forensic event detected.";
  }

  if (event.description) {
    return event.description;
  }

  if (event.message) {
    return event.message;
  }

  if (event.command) {
    return `Command: ${event.command}`;
  }

  if (event.process_name) {
    return `Process: ${event.process_name}`;
  }

  if (event.raw_data) {
    return String(event.raw_data);
  }

  if (event.evidence?.raw_data) {
    return String(event.evidence.raw_data);
  }

  const rawData = event.evidence?.raw_data;

  if (
    rawData &&
    typeof rawData === "object"
  ) {
    if (rawData.CommandLine) {
      return `Command: ${rawData.CommandLine}`;
    }

    if (rawData.ImageFileName) {
      return `Process: ${rawData.ImageFileName}`;
    }

    if (rawData.ImageName) {
      return `Process: ${rawData.ImageName}`;
    }

    if (rawData.name) {
      return `Process: ${rawData.name}`;
    }
  }

  return (
    event.event_type ||
    event.type ||
    "Forensic event detected"
  );
};

const getEvidenceId = (item) => {
  return (
    item?.evidence_id ||
    item?.evidenceId ||
    ""
  );
};

const getPluginStatusClass = (value) => {
  const status = String(
    value || ""
  ).toLowerCase();

  if (status === "completed") {
    return "plugin-completed";
  }

  if (
    status === "failed" ||
    status === "error"
  ) {
    return "plugin-failed";
  }

  return "plugin-pending";
};

/* ============================================================
   PAGINATION
============================================================ */

function Pagination({
  currentPage,
  totalPages,
  onPrevious,
  onNext,
}) {
  if (totalPages <= 1) {
    return null;
  }

  return (
    <div className="pagination">
      <button
        className="pagination-button"
        onClick={onPrevious}
        disabled={currentPage <= 1}
      >
        <ChevronLeft size={16} />
        Previous
      </button>

      <span className="pagination-info">
        Page {currentPage} of {totalPages}
      </span>

      <button
        className="pagination-button"
        onClick={onNext}
        disabled={currentPage >= totalPages}
      >
        Next
        <ChevronRight size={16} />
      </button>
    </div>
  );
}

/* ============================================================
   MAIN COMPONENT
============================================================ */

function Analysis() {
  const { evidenceId: routeEvidenceId } =
    useParams();

  const navigate = useNavigate();

  /* ==========================================================
     STATE
  ========================================================== */

  const [evidenceId, setEvidenceId] =
    useState(routeEvidenceId || "");

  const [
    availableEvidence,
    setAvailableEvidence,
  ] = useState([]);

  const [loadingEvidence, setLoadingEvidence] =
    useState(false);

  const [status, setStatus] = useState(null);
  const [result, setResult] = useState(null);

  const [loading, setLoading] =
    useState(false);

  const [runningAnalysis, setRunningAnalysis] =
    useState(false);

  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] =
    useState("");

  const [eventFilter, setEventFilter] =
    useState("ALL");

  const [eventSearch, setEventSearch] =
    useState("");

  const [currentPage, setCurrentPage] =
    useState(1);

  /* ==========================================================
     LOAD EVIDENCE
  ========================================================== */

  const fetchAvailableEvidence = async () => {
    try {
      setLoadingEvidence(true);

      const response = await fetch(
        `${API_BASE_URL}/evidence`
      );

      if (!response.ok) {
        throw new Error(
          "Unable to load evidence records."
        );
      }

      const data = await response.json();

      const evidence = Array.isArray(data)
        ? data
        : Array.isArray(data?.evidence)
        ? data.evidence
        : Array.isArray(data?.results)
        ? data.results
        : [];

      setAvailableEvidence(evidence);

      if (
        !routeEvidenceId &&
        evidence.length > 0
      ) {
        const firstId =
          getEvidenceId(evidence[0]);

        if (firstId) {
          navigate(
            `/analysis/${firstId}`,
            { replace: true }
          );
        }
      }
    } catch (err) {
      console.error(
        "Evidence loading error:",
        err
      );

      setError(
        err.message ||
          "Unable to load evidence records."
      );
    } finally {
      setLoadingEvidence(false);
    }
  };

  useEffect(() => {
    fetchAvailableEvidence();

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeEvidenceId]);

  /* ==========================================================
     SYNC ROUTE
  ========================================================== */

  useEffect(() => {
    if (routeEvidenceId) {
      setEvidenceId(routeEvidenceId);
    }
  }, [routeEvidenceId]);

  /* ==========================================================
     RESET WHEN EVIDENCE CHANGES
  ========================================================== */

  useEffect(() => {
    setError("");
    setSuccessMessage("");
    setStatus(null);
    setResult(null);
    setCurrentPage(1);
    setEventFilter("ALL");
    setEventSearch("");
  }, [routeEvidenceId]);

  /* ==========================================================
     FETCH STATUS
  ========================================================== */

  const fetchStatus = async (
    id = evidenceId
  ) => {
    if (!id) {
      return;
    }

    try {
      const response = await fetch(
        `${API_BASE_URL}/analysis/status/${id}`
      );

      if (!response.ok) {
        throw new Error(
          "Unable to load analysis status."
        );
      }

      const data = await response.json();

      setStatus(data);
    } catch (err) {
      console.error(
        "Status loading error:",
        err
      );

      setError(
        err.message ||
          "Unable to load analysis status."
      );
    }
  };

  /* ==========================================================
     FETCH RESULTS
  ========================================================== */

  const fetchResult = async (
    id = evidenceId
  ) => {
    if (!id) {
      return;
    }

    try {
      const response = await fetch(
        `${API_BASE_URL}/analysis/results/${id}`
      );

      if (response.status === 404) {
        setResult(null);
        return;
      }

      if (!response.ok) {
        throw new Error(
          "Unable to load analysis results."
        );
      }

      const data = await response.json();

      setResult(data);
    } catch (err) {
      console.error(
        "Result loading error:",
        err
      );

      setError(
        err.message ||
          "Unable to load analysis results."
      );
    }
  };

  /* ==========================================================
     LOAD CURRENT ANALYSIS
  ========================================================== */

  const loadEvidenceAnalysis = async (
    id = evidenceId
  ) => {
    if (!id) {
      return;
    }

    try {
      setLoading(true);
      setError("");

      await fetchStatus(id);
      await fetchResult(id);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (evidenceId) {
      loadEvidenceAnalysis(evidenceId);
    }

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceId]);

  /* ==========================================================
     RUN FULL ANALYSIS
  ========================================================== */

  const runFullAnalysis = async () => {
    if (!evidenceId) {
      setError(
        "Please select an evidence record first."
      );
      return;
    }

    try {
      setRunningAnalysis(true);
      setError("");
      setSuccessMessage("");

      const response = await fetch(
        `${API_BASE_URL}/analysis/full/${evidenceId}`,
        {
          method: "POST",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            "Full forensic analysis failed."
        );
      }

      setResult(data);

      await fetchStatus(evidenceId);
      await fetchResult(evidenceId);

      setSuccessMessage(
        "Full forensic analysis completed successfully."
      );

      setCurrentPage(1);
    } catch (err) {
      console.error(
        "Full analysis error:",
        err
      );

      setError(
        err.message ||
          "Full forensic analysis failed."
      );
    } finally {
      setRunningAnalysis(false);
    }
  };

  /* ==========================================================
     REFRESH
  ========================================================== */

  const refreshAnalysis = async () => {
    setError("");
    setSuccessMessage("");

    if (!evidenceId) {
      await fetchAvailableEvidence();
      return;
    }

    await loadEvidenceAnalysis(
      evidenceId
    );
  };

  /* ==========================================================
     NORMALIZED RESULT DATA
  ========================================================== */

  const safeResult = asObject(result);

  const evidence = asObject(
    safeResult.evidence
  );

  const forensics = asObject(
    safeResult.forensics
  );

  const features = asObject(
    safeResult.features
  );

  const risk = asObject(
    safeResult.risk
  );

  /* FIXED ML SELECTION */

  const mlData = asObject(
    safeResult.ml
  );

  const mlPredictionData = asObject(
    safeResult.ml_prediction
  );

  const ml =
    Object.keys(mlData).length > 0
      ? mlData
      : mlPredictionData;

  const mlProbabilities = asObject(
    ml.probabilities
  );

  const timeline = asArray(
    safeResult.timeline
  );

  const correlations = asArray(
    safeResult.correlations
  );

  const analyzedEvents = asArray(
    safeResult.analyzed_events
  );

  const yaraData = asObject(
    safeResult.yara
  );

  const yaraMatches = asArray(
    yaraData.matches
  );

  const yaraFindings = asArray(
    yaraData.findings
  );

  const volatility = asObject(
    safeResult.volatility
  );

  /* ==========================================================
     EVIDENCE INFORMATION
  ========================================================== */

  const evidenceFilename =
    evidence?.filename ||
    status?.filename ||
    "Not Available";

  const evidenceCaseId =
    evidence?.case_id ||
    evidence?.caseId ||
    status?.case_id ||
    "Not Available";

  const evidenceHash =
    evidence?.sha256 ||
    evidence?.hash ||
    "Not Available";

  const evidenceStatus =
    evidence?.status ||
    status?.status ||
    "Not Available";

  const evidenceIntegrity =
    evidence?.integrity ||
    safeResult?.integrity ||
    "Not Available";

  /* ==========================================================
     VOLATILITY PLUGINS
  ========================================================== */

  const plugins = asObject(
    status?.plugins ||
      volatility?.plugins
  );

  const pluginEntries =
    Object.entries(plugins);

  /* ==========================================================
     FORENSIC STATISTICS
  ========================================================== */

  const totalEvents =
    features.total_events ??
    analyzedEvents.length;

  const processEvents =
    features.process_events ?? 0;

  const processScanEvents =
    features.process_scan_events ?? 0;

  const networkEvents =
    features.network_events ?? 0;

  const commandEvents =
    features.command_events ?? 0;

  const relationshipEvents =
    features.relationship_events ?? 0;

  const suspiciousEvents =
    features.suspicious_events ??
    analyzedEvents.filter(
      (event) =>
        Number(
          event?.rule_score || 0
        ) > 0
    ).length;

  const highRiskEvents =
    features.high_risk_events ?? 0;

  const mediumRiskEvents =
    features.medium_risk_events ?? 0;

  const correlationCount =
    features.correlation_count ??
    correlations.length;

  const highSeverityCorrelations =
    features.high_severity_correlations ??
    0;

  const totalRuleScore =
    features.total_rule_score ?? 0;

  const maximumRuleScore =
    features.maximum_rule_score ?? 0;

  /* ==========================================================
     RISK
  ========================================================== */

  const riskLevel =
    risk.risk_level ||
    risk.level ||
    safeResult.risk_level ||
    "LOW";

  const riskScore =
    risk.risk_score ??
    risk.score ??
    0;

  const riskReason =
    risk.reason ||
    risk.description ||
    "No additional risk explanation available.";

  /* ==========================================================
     ML
  ========================================================== */

  const mlClassification =
    ml.classification ||
    ml.label ||
    "Not Available";

  /* ==========================================================
     YARA
  ========================================================== */

  const yaraCount = Math.max(
    yaraMatches.length,
    yaraFindings.length
  );

  const yaraStatus =
    yaraData.status ||
    (yaraCount > 0
      ? "Matches Detected"
      : "No Matches");

  /* ==========================================================
     EVENT FILTERING
  ========================================================== */

  const filteredEvents = useMemo(() => {
    let events = analyzedEvents;

    if (eventFilter !== "ALL") {
      events = events.filter(
        (event) =>
          String(
            event?.event_type || ""
          ).toUpperCase() ===
          eventFilter
      );
    }

    if (eventSearch.trim()) {
      const search =
        eventSearch
          .toLowerCase()
          .trim();

      events = events.filter(
        (event) => {
          const text = [
            event?.event_type,
            event?.description,
            event?.message,
            event?.command,
            event?.process_name,
            JSON.stringify(
              event?.evidence?.raw_data ||
                event?.raw_data ||
                ""
            ),
          ]
            .join(" ")
            .toLowerCase();

          return text.includes(search);
        }
      );
    }

    return events;
  }, [
    analyzedEvents,
    eventFilter,
    eventSearch,
  ]);

  const totalPages = Math.max(
    1,
    Math.ceil(
      filteredEvents.length /
        PAGE_SIZE
    )
  );

  const paginatedEvents =
    useMemo(() => {
      const start =
        (currentPage - 1) *
        PAGE_SIZE;

      return filteredEvents.slice(
        start,
        start + PAGE_SIZE
      );
    }, [
      filteredEvents,
      currentPage,
    ]);

  useEffect(() => {
    if (
      currentPage > totalPages
    ) {
      setCurrentPage(totalPages);
    }
  }, [
    currentPage,
    totalPages,
  ]);

  /* ==========================================================
     IMPORTANT TIMELINE EVENTS
  ========================================================== */

  const importantTimelineEvents =
    useMemo(() => {
      const important =
        timeline.filter(
          (event) => {
            const score = Number(
              event?.rule_score || 0
            );

            const riskValue =
              String(
                event?.risk_level || ""
              ).toUpperCase();

            return (
              score > 0 ||
              riskValue === "HIGH" ||
              riskValue === "CRITICAL" ||
              riskValue === "MEDIUM"
            );
          }
        );

      if (important.length > 0) {
        return important.slice(0, 12);
      }

      return timeline.slice(0, 8);
    }, [timeline]);

  /* ==========================================================
     SELECT EVIDENCE
  ========================================================== */

  const handleEvidenceChange = (
    event
  ) => {
    const selectedId =
      event.target.value;

    if (!selectedId) {
      return;
    }

    setEvidenceId(selectedId);

    navigate(
      `/analysis/${selectedId}`
    );
  };

  /* ==========================================================
     RENDER
  ========================================================== */

  return (
    <div className="analysis-page">

      {/* ======================================================
          HEADER
      ====================================================== */}

      <header className="analysis-header">

        <div className="analysis-heading">

          <div className="heading-icon">
            <Shield size={25} />
          </div>

          <div>
            <div className="eyebrow">
              FORENSIC INVESTIGATION
            </div>

            <h1>
              Memory Analysis
            </h1>

            <p>
              Digital forensic examination,
              detection and AI-assisted
              ransomware analysis.
            </p>
          </div>

        </div>

        <div className="header-actions">

          <button
            className="btn btn-secondary"
            onClick={refreshAnalysis}
            disabled={
              loading ||
              loadingEvidence ||
              runningAnalysis
            }
          >
            <RefreshCw
              size={16}
              className={
                loading
                  ? "spin"
                  : ""
              }
            />

            Refresh
          </button>

          <button
            className="btn btn-primary"
            onClick={
              runFullAnalysis
            }
            disabled={
              !evidenceId ||
              runningAnalysis
            }
          >
            <Activity size={16} />

            {runningAnalysis
              ? "Analyzing..."
              : "Run Full Analysis"}
          </button>

          <button
            className="btn btn-secondary"
            onClick={() =>
              navigate(
                `/report/${evidenceId}`
              )
            }
            disabled={!evidenceId}
          >
            <FileSearch size={16} />
            Report
          </button>

        </div>
      </header>

      {/* ======================================================
          ALERTS
      ====================================================== */}

      {error && (
        <div className="alert alert-error">
          <AlertTriangle size={18} />

          <span>{error}</span>

          <button
            className="alert-close"
            onClick={() =>
              setError("")
            }
          >
            ×
          </button>
        </div>
      )}

      {successMessage && (
        <div className="alert alert-success">
          <CheckCircle size={18} />

          <span>
            {successMessage}
          </span>

          <button
            className="alert-close"
            onClick={() =>
              setSuccessMessage("")
            }
          >
            ×
          </button>
        </div>
      )}

      {/* ======================================================
          EVIDENCE BAR
      ====================================================== */}

      <section className="evidence-panel">

        <div className="evidence-panel-main">

          <div className="section-icon">
            <FileText size={20} />
          </div>

          <div>
            <span className="section-label">
              ACTIVE EVIDENCE
            </span>

            <h2>
              {evidenceId ||
                "No Evidence Selected"}
            </h2>

            <p>
              {evidenceFilename}
            </p>
          </div>

        </div>

        <div className="evidence-selector">

          <label>
            Evidence Record
          </label>

          <select
            value={evidenceId}
            onChange={
              handleEvidenceChange
            }
            disabled={
              loadingEvidence ||
              availableEvidence.length ===
                0
            }
          >
            <option value="">
              {loadingEvidence
                ? "Loading evidence..."
                : availableEvidence.length ===
                  0
                ? "No evidence available"
                : "Select evidence"}
            </option>

            {availableEvidence.map(
              (item) => {
                const id =
                  getEvidenceId(item);

                return (
                  <option
                    key={id}
                    value={id}
                  >
                    {id} —{" "}
                    {item.filename ||
                      "Unnamed Evidence"}
                  </option>
                );
              }
            )}
          </select>

        </div>

      </section>

      {/* ======================================================
          EVIDENCE STATUS
      ====================================================== */}

      <section className="status-strip">

        <div className="status-item">
          <Fingerprint size={18} />

          <div>
            <span>
              Evidence ID
            </span>

            <strong>
              {evidenceId ||
                "Not Available"}
            </strong>
          </div>
        </div>

        <div className="status-item">
          <FileText size={18} />

          <div>
            <span>
              Case
            </span>

            <strong>
              {evidenceCaseId}
            </strong>
          </div>
        </div>

        <div className="status-item">
          <Shield size={18} />

          <div>
            <span>
              Status
            </span>

            <strong>
              {evidenceStatus}
            </strong>
          </div>
        </div>

        <div className="status-item">
          <CheckCircle size={18} />

          <div>
            <span>
              Integrity
            </span>

            <strong>
              {evidenceIntegrity}
            </strong>
          </div>
        </div>

      </section>

      {/* ======================================================
          TOP METRICS
      ====================================================== */}

      <section className="metric-grid">

        <div className="metric-card">
          <div className="metric-icon">
            <Activity size={21} />
          </div>

          <div>
            <span>
              Total Events
            </span>

            <strong>
              {formatNumber(
                totalEvents
              )}
            </strong>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">
            <Terminal size={21} />
          </div>

          <div>
            <span>
              Processes
            </span>

            <strong>
              {formatNumber(
                processEvents
              )}
            </strong>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon warning">
            <AlertTriangle size={21} />
          </div>

          <div>
            <span>
              Suspicious
            </span>

            <strong>
              {formatNumber(
                suspiciousEvents
              )}
            </strong>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon danger">
            <ShieldAlert size={21} />
          </div>

          <div>
            <span>
              High Risk
            </span>

            <strong>
              {formatNumber(
                highRiskEvents
              )}
            </strong>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">
            <Wifi size={21} />
          </div>

          <div>
            <span>
              Network Events
            </span>

            <strong>
              {formatNumber(
                networkEvents
              )}
            </strong>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">
            <Search size={21} />
          </div>

          <div>
            <span>
              Correlations
            </span>

            <strong>
              {formatNumber(
                correlationCount
              )}
            </strong>
          </div>
        </div>

      </section>

      {/* ======================================================
          MAIN TWO COLUMN AREA
      ====================================================== */}

      <div className="analysis-columns">

        {/* LEFT COLUMN */}

        <div className="analysis-main-column">

          {/* VOLATILITY */}

          <section className="analysis-card">

            <div className="card-header">

              <div className="card-heading">
                <div className="card-icon">
                  <Terminal size={18} />
                </div>

                <div>
                  <h2>
                    Volatility Analysis
                  </h2>

                  <p>
                    Memory forensic plugin
                    execution status
                  </p>
                </div>
              </div>

              <span className="card-count">
                {pluginEntries.length}
              </span>

            </div>

            <div className="plugin-grid">

              {pluginEntries.length ===
              0 ? (
                <div className="empty-state">
                  No plugin status available.
                </div>
              ) : (
                pluginEntries.map(
                  ([
                    plugin,
                    pluginStatus,
                  ]) => {

                    const completed =
                      String(
                        pluginStatus
                      ).toLowerCase() ===
                      "completed";

                    return (
                      <div
                        className="plugin-item"
                        key={plugin}
                      >

                        <div className="plugin-name">
                          <strong>
                            {plugin}
                          </strong>

                          <span
                            className={getPluginStatusClass(
                              pluginStatus
                            )}
                          >
                            {pluginStatus}
                          </span>
                        </div>

                        {completed ? (
                          <CheckCircle
                            size={19}
                          />
                        ) : (
                          <XCircle
                            size={19}
                          />
                        )}

                      </div>
                    );
                  }
                )
              )}

            </div>

          </section>

          {/* DETECTION SUMMARY */}

          <section className="analysis-card">

            <div className="card-header">

              <div className="card-heading">
                <div className="card-icon">
                  <ShieldAlert size={18} />
                </div>

                <div>
                  <h2>
                    Detection Summary
                  </h2>

                  <p>
                    Rule-based forensic
                    indicators
                  </p>
                </div>
              </div>

            </div>

            <div className="summary-grid">

              <div className="summary-item">
                <span>
                  Command Events
                </span>

                <strong>
                  {formatNumber(
                    commandEvents
                  )}
                </strong>
              </div>

              <div className="summary-item">
                <span>
                  Process Scan
                </span>

                <strong>
                  {formatNumber(
                    processScanEvents
                  )}
                </strong>
              </div>

              <div className="summary-item">
                <span>
                  Relationships
                </span>

                <strong>
                  {formatNumber(
                    relationshipEvents
                  )}
                </strong>
              </div>

              <div className="summary-item">
                <span>
                  Medium Risk
                </span>

                <strong>
                  {formatNumber(
                    mediumRiskEvents
                  )}
                </strong>
              </div>

              <div className="summary-item">
                <span>
                  Total Rule Score
                </span>

                <strong>
                  {formatNumber(
                    totalRuleScore
                  )}
                </strong>
              </div>

              <div className="summary-item">
                <span>
                  Maximum Score
                </span>

                <strong>
                  {formatNumber(
                    maximumRuleScore
                  )}
                </strong>
              </div>

            </div>

          </section>

          {/* CORRELATION */}

          <section className="analysis-card">

            <div className="card-header">

              <div className="card-heading">
                <div className="card-icon">
                  <Activity size={18} />
                </div>

                <div>
                  <h2>
                    Evidence Correlation
                  </h2>

                  <p>
                    Relationships between
                    forensic artifacts
                  </p>
                </div>
              </div>

              <span className="card-count">
                {correlations.length}
              </span>

            </div>

            {correlations.length ===
            0 ? (
              <div className="empty-state">
                No evidence correlations
                detected.
              </div>
            ) : (
              <div className="correlation-list">

                {correlations.map(
                  (
                    correlation,
                    index
                  ) => {

                    const severity =
                      correlation.severity ||
                      "LOW";

                    return (
                      <div
                        className="correlation-item"
                        key={
                          correlation.id ||
                          index
                        }
                      >

                        <div className="correlation-dot">
                          <AlertTriangle
                            size={16}
                          />
                        </div>

                        <div className="correlation-main">

                          <div className="correlation-title">

                            <strong>
                              {correlation.title ||
                                correlation.type ||
                                "Evidence Correlation"}
                            </strong>

                            <span
                              className={`severity-badge ${getSeverityClass(
                                severity
                              )}`}
                            >
                              {severity}
                            </span>

                          </div>

                          <p>
                            {correlation.description ||
                              correlation.message ||
                              "No description available."}
                          </p>

                        </div>

                      </div>
                    );
                  }
                )}

              </div>
            )}

          </section>

          {/* YARA */}

          <section className="analysis-card">

            <div className="card-header">

              <div className="card-heading">
                <div className="card-icon">
                  <Search size={18} />
                </div>

                <div>
                  <h2>
                    YARA Detection
                  </h2>

                  <p>
                    Malware signature
                    analysis
                  </p>
                </div>
              </div>

              <span className="card-count">
                {yaraCount}
              </span>

            </div>

            <div className="yara-summary">

              <div className="yara-stat">
                <span>
                  Findings
                </span>

                <strong>
                  {formatNumber(
                    yaraCount
                  )}
                </strong>
              </div>

              <div className="yara-stat">
                <span>
                  Status
                </span>

                <strong>
                  {yaraStatus}
                </strong>
              </div>

            </div>

            {yaraFindings.length >
            0 ? (
              <div className="finding-list">

                {yaraFindings.map(
                  (
                    finding,
                    index
                  ) => (
                    <div
                      className="finding-item"
                      key={index}
                    >

                      <div className="finding-icon">
                        <AlertTriangle
                          size={17}
                        />
                      </div>

                      <div>
                        <strong>
                          {finding.rule ||
                            finding.rule_name ||
                            finding.name ||
                            "YARA Rule"}
                        </strong>

                        <p>
                          {finding.description ||
                            finding.message ||
                            "YARA rule matched a forensic artifact."}
                        </p>
                      </div>

                    </div>
                  )
                )}

              </div>
            ) : (
              <div className="empty-state">
                No YARA matches detected.
              </div>
            )}

          </section>

        </div>

        {/* RIGHT COLUMN */}

        <aside className="analysis-side-column">

          {/* ML */}

          <section className="analysis-card">

            <div className="card-heading">

              <div className="card-icon">
                <Brain size={18} />
              </div>

              <div>
                <h2>
                  AI Classification
                </h2>

                <p>
                  Machine-learning
                  assessment
                </p>
              </div>

            </div>

            <div className="ml-result">

              <span>
                Classification
              </span>

              <strong>
                {mlClassification}
              </strong>

              {ml.prediction !==
                undefined && (
                <small>
                  Prediction class:{" "}
                  {ml.prediction}
                </small>
              )}

            </div>

            <div className="probability-list">

              <div>
                <span>
                  Normal
                </span>

                <strong>
                  {formatPercentage(
                    mlProbabilities.Normal
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Suspicious
                </span>

                <strong>
                  {formatPercentage(
                    mlProbabilities.Suspicious
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Ransomware
                </span>

                <strong>
                  {formatPercentage(
                    mlProbabilities.Ransomware
                  )}
                </strong>
              </div>

            </div>

          </section>

          {/* RISK */}

          <section className="analysis-card">

            <div className="card-heading">

              <div className="card-icon">
                <ShieldAlert size={18} />
              </div>

              <div>
                <h2>
                  Risk Assessment
                </h2>

                <p>
                  Combined forensic
                  evaluation
                </p>
              </div>

            </div>

            <div className="risk-result">

              <div
                className={`risk-level ${getRiskClass(
                  riskLevel
                )}`}
              >
                {riskLevel}
              </div>

              <div className="risk-score-value">
                <span>
                  Risk Score
                </span>

                <strong>
                  {formatNumber(
                    riskScore
                  )}
                </strong>
              </div>

            </div>

            <div className="risk-reason">
              <span>
                Assessment
              </span>

              <p>
                {riskReason}
              </p>
            </div>

          </section>

          {/* FEATURES */}

          <section className="analysis-card">

            <div className="card-heading">

              <div className="card-icon">
                <Brain size={18} />
              </div>

              <div>
                <h2>
                  Forensic Features
                </h2>

                <p>
                  ML input characteristics
                </p>
              </div>

            </div>

            <div className="feature-list">

              <div>
                <span>
                  PowerShell Events
                </span>

                <strong>
                  {formatNumber(
                    features.powershell_events
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Encoded Commands
                </span>

                <strong>
                  {formatNumber(
                    features.encoded_command_events
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Suspicious Tools
                </span>

                <strong>
                  {formatNumber(
                    features.suspicious_tool_events
                  )}
                </strong>
              </div>

              <div>
                <span>
                  High Correlations
                </span>

                <strong>
                  {formatNumber(
                    highSeverityCorrelations
                  )}
                </strong>
              </div>

              <div>
                <span>
                  Suspicious Ratio
                </span>

                <strong>
                  {formatPercentage(
                    Number(
                      features.suspicious_event_ratio ||
                        0
                    ) * 100
                  )}
                </strong>
              </div>

            </div>

          </section>

          {/* INTEGRITY */}

          <section className="analysis-card">

            <div className="card-heading">

              <div className="card-icon">
                <Fingerprint size={18} />
              </div>

              <div>
                <h2>
                  Evidence Integrity
                </h2>

                <p>
                  Cryptographic verification
                </p>
              </div>

            </div>

            <div className="integrity-status">

              <CheckCircle size={20} />

              <div>
                <strong>
                  {evidenceIntegrity}
                </strong>

                <span>
                  Evidence integrity
                  status
                </span>
              </div>

            </div>

            <div className="hash-block">

              <span>
                SHA-256
              </span>

              <code>
                {evidenceHash}
              </code>

            </div>

            <div className="integrity-row">
              <span>
                Evidence Status
              </span>

              <strong>
                {evidenceStatus}
              </strong>
            </div>

          </section>

        </aside>

      </div>

      {/* ======================================================
          TIMELINE
      ====================================================== */}

      <section className="analysis-card">

        <div className="card-header">

          <div className="card-heading">
            <div className="card-icon">
              <Activity size={18} />
            </div>

            <div>
              <h2>
                Important Forensic Timeline
              </h2>

              <p>
                Suspicious and significant
                forensic events
              </p>
            </div>
          </div>

          <span className="card-count">
            {timeline.length}
          </span>

        </div>

        {importantTimelineEvents.length ===
        0 ? (
          <div className="empty-state">
            No timeline events available.
          </div>
        ) : (
          <div className="timeline">

            {importantTimelineEvents.map(
              (event, index) => {

                const eventRisk =
                  event.risk_level ||
                  "LOW";

                return (
                  <div
                    className="timeline-item"
                    key={
                      event.id ||
                      index
                    }
                  >

                    <div className="timeline-marker" />

                    <div className="timeline-content">

                      <div className="timeline-top">

                        <strong>
                          {event.event_type ||
                            event.type ||
                            "Forensic Event"}
                        </strong>

                        <span
                          className={`risk-badge ${getRiskClass(
                            eventRisk
                          )}`}
                        >
                          {eventRisk}
                        </span>

                      </div>

                      <p>
                        {getEventDescription(
                          event
                        )}
                      </p>

                    </div>

                  </div>
                );
              }
            )}

          </div>
        )}

      </section>

      {/* ======================================================
          ANALYZED EVENTS
      ====================================================== */}

      <section className="analysis-card">

        <div className="card-header">

          <div className="card-heading">
            <div className="card-icon">
              <FileSearch size={18} />
            </div>

            <div>
              <h2>
                Analyzed Events
              </h2>

              <p>
                Detailed forensic event
                analysis
              </p>
            </div>
          </div>

          <span className="card-count">
            {filteredEvents.length}
          </span>

        </div>

        {/* TOOLBAR */}

        <div className="event-toolbar">

          <div className="event-search">

            <Search size={16} />

            <input
              type="text"
              placeholder="Search forensic events..."
              value={eventSearch}
              onChange={(event) => {
                setEventSearch(
                  event.target.value
                );
                setCurrentPage(1);
              }}
            />

          </div>

          <div className="filter-buttons">

            {[
              "ALL",
              "PROCESS_DETECTED",
              "PROCESS_SCAN",
              "COMMAND_EXECUTION",
              "PROCESS_RELATIONSHIP",
              "NETWORK_CONNECTION",
            ].map(
              (filter) => (
                <button
                  key={filter}
                  className={
                    eventFilter ===
                    filter
                      ? "filter-button active"
                      : "filter-button"
                  }
                  onClick={() => {
                    setEventFilter(
                      filter
                    );
                    setCurrentPage(1);
                  }}
                >
                  {filter ===
                  "ALL"
                    ? "All"
                    : filter
                        .replace(
                          /_/g,
                          " "
                        )
                        .replace(
                          /\b\w/g,
                          (letter) =>
                            letter.toUpperCase()
                        )}
                </button>
              )
            )}

          </div>

        </div>

        {/* TABLE */}

        {paginatedEvents.length ===
        0 ? (
          <div className="empty-state">
            No analyzed events found.
          </div>
        ) : (
          <div className="table-wrapper">

            <table className="events-table">

              <thead>
                <tr>
                  <th>#</th>
                  <th>Event</th>
                  <th>Description</th>
                  <th>Risk</th>
                  <th>Score</th>
                  <th>Indicators</th>
                </tr>
              </thead>

              <tbody>

                {paginatedEvents.map(
                  (
                    event,
                    index
                  ) => {

                    const eventRisk =
                      event.risk_level ||
                      "LOW";

                    const ruleScore =
                      Number(
                        event.rule_score ||
                          0
                      );

                    const indicators =
                      asArray(
                        event.indicators
                      );

                    return (
                      <tr
                        key={
                          event.id ||
                          `${currentPage}-${index}`
                        }
                      >

                        <td>
                          {(
                            (currentPage -
                              1) *
                              PAGE_SIZE
                          ) +
                            index +
                            1}
                        </td>

                        <td>
                          <span className="event-type">
                            {event.event_type ||
                              "Unknown"}
                          </span>
                        </td>

                        <td className="event-description">
                          {getEventDescription(
                            event
                          )}
                        </td>

                        <td>
                          <span
                            className={`risk-badge ${getRiskClass(
                              eventRisk
                            )}`}
                          >
                            {eventRisk}
                          </span>
                        </td>

                        <td>
                          {formatNumber(
                            ruleScore
                          )}
                        </td>

                        <td>

                          {indicators.length ===
                          0 ? (
                            <span className="muted">
                              None
                            </span>
                          ) : (
                            <div className="indicator-list">

                              {indicators
                                .slice(
                                  0,
                                  3
                                )
                                .map(
                                  (
                                    indicator,
                                    indicatorIndex
                                  ) => (
                                    <span
                                      key={
                                        indicatorIndex
                                      }
                                      className="indicator-tag"
                                    >
                                      {
                                        indicator
                                      }
                                    </span>
                                  )
                                )}

                            </div>
                          )}

                        </td>

                      </tr>
                    );
                  }
                )}

              </tbody>

            </table>

          </div>
        )}

        <Pagination
          currentPage={
            currentPage
          }
          totalPages={
            totalPages
          }
          onPrevious={() =>
            setCurrentPage(
              (page) =>
                Math.max(
                  1,
                  page - 1
                )
            )
          }
          onNext={() =>
            setCurrentPage(
              (page) =>
                Math.min(
                  totalPages,
                  page + 1
                )
            )
          }
        />

      </section>

      {/* ======================================================
          FOOTER
      ====================================================== */}

      <footer className="analysis-footer">

        <div>
          <Shield size={16} />

          <span>
            ForensiRansom AI
            <small>
              Digital Forensic
              Investigation Platform
            </small>
          </span>
        </div>

        <span>
          Evidence:{" "}
          {evidenceId ||
            "Not Available"}
        </span>

      </footer>

    </div>
  );
}

export default Analysis;