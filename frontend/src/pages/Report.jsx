import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ShieldCheck,
  FileText,
  Search,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Activity,
  Brain,
  Network,
  Terminal,
  Clock3,
  RefreshCw,
  Printer,
  ArrowLeft,
  Database,
  LockKeyhole,
  Fingerprint,
} from "lucide-react";

import "./Report.css";
import { API_BASE_URL } from "../config";

function formatNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "0";
  }

  return number.toLocaleString();
}

function formatDate(value) {
  if (!value) {
    return "Not recorded";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatFileSize(bytes) {
  const size = Number(bytes);

  if (!Number.isFinite(size) || size < 0) {
    return "Not recorded";
  }

  if (size < 1024) {
    return `${size} B`;
  }

  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(2)} KB`;
  }

  if (size < 1024 * 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  }

  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function firstValue(...values) {
  for (const value of values) {
    if (
      value !== undefined &&
      value !== null &&
      String(value).trim() !== ""
    ) {
      return value;
    }
  }

  return null;
}

function getCompleteAnalysis(data) {
  if (!data) {
    return null;
  }

  /*
   * Current backend may return:
   *
   * {
   *   evidence_id,
   *   count,
   *   results: [...]
   * }
   *
   * Or it may return the complete result directly.
   */

  if (Array.isArray(data.results)) {
    const completeResults = data.results.filter(
      (item) =>
        item &&
        item.analysis_type === "complete" &&
        item.result
    );

    if (completeResults.length > 0) {
      const latest =
        completeResults[completeResults.length - 1];

      return latest.result;
    }

    if (data.results.length > 0) {
      const latest =
        data.results[data.results.length - 1];

      return latest.result || latest;
    }
  }

  if (data.result && typeof data.result === "object") {
    return data.result;
  }

  if (
    data.evidence ||
    data.forensics ||
    data.features ||
    data.risk ||
    data.ml ||
    data.ml_prediction
  ) {
    return data;
  }

  return null;
}

function normalizeRiskLevel(value) {
  if (!value) {
    return "UNKNOWN";
  }

  return String(value).toUpperCase();
}

function getRiskClass(level) {
  const normalized = normalizeRiskLevel(level);

  if (normalized === "CRITICAL") {
    return "risk-critical";
  }

  if (normalized === "HIGH") {
    return "risk-high";
  }

  if (normalized === "MEDIUM") {
    return "risk-medium";
  }

  if (normalized === "LOW") {
    return "risk-low";
  }

  return "risk-unknown";
}

function getIntegrityText(value) {
  const normalized = String(value || "").toUpperCase();

  if (
    normalized === "INTACT" ||
    normalized === "VERIFIED"
  ) {
    return "Verified";
  }

  if (
    normalized === "MODIFIED" ||
    normalized === "FAILED" ||
    normalized === "COMPROMISED"
  ) {
    return "Compromised";
  }

  return "Not Verified";
}

function getIntegrityClass(value) {
  const normalized = String(value || "").toUpperCase();

  if (
    normalized === "INTACT" ||
    normalized === "VERIFIED"
  ) {
    return "status-success";
  }

  if (
    normalized === "MODIFIED" ||
    normalized === "FAILED" ||
    normalized === "COMPROMISED"
  ) {
    return "status-danger";
  }

  return "status-warning";
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function AppStatus({ children, type = "success" }) {
  return (
    <span className={`report-status ${type}`}>
      {type === "success" && <CheckCircle2 size={15} />}
      {type === "warning" && <AlertTriangle size={15} />}
      {type === "danger" && <XCircle size={15} />}
      {children}
    </span>
  );
}

function MetricCard({
  icon,
  label,
  value,
  description,
}) {
  return (
    <div className="report-metric-card">
      <div className="metric-icon">{icon}</div>

      <div className="metric-content">
        <span>{label}</span>
        <strong>{value}</strong>

        {description && (
          <small>{description}</small>
        )}
      </div>
    </div>
  );
}

function InfoRow({ label, value }) {
  return (
    <div className="report-info-row">
      <span>{label}</span>
      <strong>{value || "Not recorded"}</strong>
    </div>
  );
}

function SectionHeader({
  number,
  title,
  description,
  icon,
}) {
  return (
    <div className="report-section-header">
      <div className="section-number">{number}</div>

      <div className="section-title-area">
        <div className="section-title-line">
          {icon}
          <h2>{title}</h2>
        </div>

        {description && (
          <p>{description}</p>
        )}
      </div>
    </div>
  );
}

export default function Report() {
  const { evidenceId: routeEvidenceId } = useParams();
  const navigate = useNavigate();

  const [evidenceList, setEvidenceList] = useState([]);
  const [cases, setCases] = useState([]);

  const [selectedEvidenceId, setSelectedEvidenceId] =
    useState(routeEvidenceId || "");

  const [analysis, setAnalysis] = useState(null);

  const [loading, setLoading] = useState(true);
  const [analysisLoading, setAnalysisLoading] =
    useState(false);

  const [error, setError] = useState("");

  /*
   * ---------------------------------------------------------
   * LOAD EVIDENCE + CASES
   * ---------------------------------------------------------
   *
   * This is important:
   *
   * Evidence:
   * MEM-001 -> FRA-001
   *
   * Cases:
   * FRA-001 -> Case Name + Investigator
   *
   * Therefore the report can always identify the correct case.
   */

  const loadMetadata = async () => {
    try {
      setLoading(true);
      setError("");

      const [evidenceResponse, casesResponse] =
        await Promise.all([
          fetch(`${API_BASE_URL}/evidence`),
          fetch(`${API_BASE_URL}/cases`),
        ]);

      const evidenceData =
        await evidenceResponse.json();

      const casesData =
        await casesResponse.json();

      if (!evidenceResponse.ok) {
        throw new Error(
          evidenceData.detail ||
            "Unable to load evidence"
        );
      }

      if (!casesResponse.ok) {
        throw new Error(
          casesData.detail ||
            "Unable to load cases"
        );
      }

      const evidenceArray = Array.isArray(
        evidenceData
      )
        ? evidenceData
        : [];

      const caseArray = Array.isArray(casesData)
        ? casesData
        : [];

      setEvidenceList(evidenceArray);
      setCases(caseArray);

      if (!selectedEvidenceId && evidenceArray.length) {
        setSelectedEvidenceId(
          evidenceArray[0].evidence_id
        );
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMetadata();
  }, []);

  /*
   * ---------------------------------------------------------
   * SELECTED EVIDENCE
   * ---------------------------------------------------------
   */

  const selectedEvidence = useMemo(() => {
    return evidenceList.find(
      (item) =>
        item.evidence_id === selectedEvidenceId
    );
  }, [evidenceList, selectedEvidenceId]);

  /*
   * ---------------------------------------------------------
   * LINK EVIDENCE -> CASE
   * ---------------------------------------------------------
   */

  const selectedCase = useMemo(() => {
    if (!selectedEvidence) {
      return null;
    }

    return cases.find(
      (item) =>
        item.case_id === selectedEvidence.case_id
    );
  }, [cases, selectedEvidence]);

  /*
   * ---------------------------------------------------------
   * LOAD ANALYSIS FOR EXACT EVIDENCE
   * ---------------------------------------------------------
   */

  const loadAnalysis = async (id) => {
    if (!id) {
      setAnalysis(null);
      return;
    }

    try {
      setAnalysisLoading(true);
      setError("");

      const response = await fetch(
        `${API_BASE_URL}/analysis/results/${id}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to load analysis result"
        );
      }

      const completeResult =
        getCompleteAnalysis(data);

      setAnalysis(completeResult);
    } catch (err) {
      setAnalysis(null);
      setError(err.message);
    } finally {
      setAnalysisLoading(false);
    }
  };

  useEffect(() => {
    if (selectedEvidenceId) {
      loadAnalysis(selectedEvidenceId);
    }
  }, [selectedEvidenceId]);

  /*
   * ---------------------------------------------------------
   * SELECT EVIDENCE
   * ---------------------------------------------------------
   */

  const handleEvidenceChange = (event) => {
    const id = event.target.value;

    setSelectedEvidenceId(id);

    navigate(`/report/${id}`);
  };

  /*
   * ---------------------------------------------------------
   * NORMALIZED DATA
   * ---------------------------------------------------------
   */

  const evidenceFromAnalysis =
    analysis?.evidence || {};

  const forensics =
    analysis?.forensics || {};

  const features =
    analysis?.features || {};

  const risk =
    analysis?.risk || {};

  const volatility =
    analysis?.volatility || {};

  const ml =
    analysis?.ml ||
    analysis?.ml_prediction ||
    {};

  const yara =
    analysis?.yara || {};

  const correlations =
    safeArray(analysis?.correlations);

  const timeline =
    safeArray(analysis?.timeline);

  const analyzedEvents =
    safeArray(analysis?.analyzed_events);

  /*
   * ---------------------------------------------------------
   * EVIDENCE DETAILS
   * ---------------------------------------------------------
   */

  const evidenceId =
    selectedEvidence?.evidence_id ||
    evidenceFromAnalysis?.evidence_id ||
    selectedEvidenceId ||
    "Not recorded";

  const filename =
    selectedEvidence?.filename ||
    evidenceFromAnalysis?.filename ||
    "Not recorded";

  const evidenceType =
    selectedEvidence?.evidence_type ||
    evidenceFromAnalysis?.evidence_type ||
    "Memory Image";

  const fileSize =
    selectedEvidence?.file_size ||
    selectedEvidence?.size_bytes ||
    evidenceFromAnalysis?.file_size ||
    evidenceFromAnalysis?.size_bytes;

  const sha256 =
    selectedEvidence?.sha256 ||
    evidenceFromAnalysis?.sha256 ||
    "Not recorded";

  const acquisitionDate =
    selectedEvidence?.created_at ||
    selectedEvidence?.acquisition_date ||
    evidenceFromAnalysis?.created_at;

  const integrity =
    selectedEvidence?.status ||
    evidenceFromAnalysis?.integrity ||
    evidenceFromAnalysis?.integrity_status ||
    "Not Verified";

  /*
   * ---------------------------------------------------------
   * CASE DETAILS
   * ---------------------------------------------------------
   *
   * IMPORTANT:
   * These values come from /cases using evidence.case_id.
   */

  const caseId =
    selectedCase?.case_id ||
    selectedEvidence?.case_id ||
    evidenceFromAnalysis?.case_id ||
    "Not recorded";

  const caseName =
    selectedCase?.case_name ||
    evidenceFromAnalysis?.case_name ||
    "Not recorded";

  const investigator =
    selectedCase?.investigator ||
    evidenceFromAnalysis?.investigator ||
    "Not recorded";

  const caseStatus =
    selectedCase?.status ||
    "Not recorded";

  const caseDescription =
    selectedCase?.description ||
    "No investigation description available.";

  /*
   * ---------------------------------------------------------
   * FORENSIC METRICS
   * ---------------------------------------------------------
   */

  const totalEvents = Number(
    firstValue(
      features.total_events,
      analysis?.parsed_events,
      timeline.length,
      0
    )
  );

  const processEvents = Number(
    firstValue(
      features.process_events,
      forensics.process_events,
      analyzedEvents.filter(
        (event) =>
          String(
            event.event_type || ""
          ).toUpperCase() ===
          "PROCESS_DETECTED"
      ).length,
      0
    )
  );

  const commandEvents = Number(
    firstValue(
      features.command_events,
      forensics.command_events,
      analyzedEvents.filter(
        (event) =>
          String(
            event.event_type || ""
          ).toUpperCase() ===
          "COMMAND_EXECUTION"
      ).length,
      0
    )
  );

  const networkEvents = Number(
    firstValue(
      features.network_events,
      forensics.network_events,
      0
    )
  );

  const suspiciousEvents = Number(
    firstValue(
      features.suspicious_events,
      risk.suspicious_events,
      0
    )
  );

  const highRiskEvents = Number(
    firstValue(
      features.high_risk_events,
      risk.high_risk_events,
      0
    )
  );

  const mediumRiskEvents = Number(
    firstValue(
      features.medium_risk_events,
      risk.medium_risk_events,
      0
    )
  );

  const ruleScore = Number(
    firstValue(
      features.total_rule_score,
      risk.total_rule_score,
      0
    )
  );

  const maximumRuleScore = Number(
    firstValue(
      features.maximum_rule_score,
      risk.maximum_rule_score,
      0
    )
  );

  /*
   * YARA
   */

  const yaraFindings = safeArray(
    yara.findings ||
      yara.matches ||
      yara.results
  );

  const yaraMatchCount = Number(
    firstValue(
      yara.count,
      yara.matches_count,
      yaraFindings.length,
      features.yara_matches,
      0
    )
  );

  /*
   * Correlations
   */

  const correlationCount = Number(
    firstValue(
      features.correlation_count,
      correlations.length,
      0
    )
  );

  const highCorrelationCount = Number(
    firstValue(
      features.high_severity_correlations,
      0
    )
  );

  const mediumCorrelationCount = Number(
    firstValue(
      features.medium_severity_correlations,
      0
    )
  );

  /*
   * ---------------------------------------------------------
   * ML
   * ---------------------------------------------------------
   */

  const classification =
    firstValue(
      ml.classification,
      ml.label,
      ml.prediction,
      "Not Available"
    );

  const probabilities =
    ml.probabilities ||
    ml.probability_distribution ||
    {};

  const normalProbability = Number(
    firstValue(
      probabilities.Normal,
      probabilities.normal,
      0
    )
  );

  const suspiciousProbability = Number(
    firstValue(
      probabilities.Suspicious,
      probabilities.suspicious,
      0
    )
  );

  const ransomwareProbability = Number(
    firstValue(
      probabilities.Ransomware,
      probabilities.ransomware,
      0
    )
  );

  /*
   * ---------------------------------------------------------
   * RISK
   * ---------------------------------------------------------
   */

  const riskScore = Number(
    firstValue(
      risk.risk_score,
      risk.score,
      0
    )
  );

  const riskLevel = normalizeRiskLevel(
    firstValue(
      risk.risk_level,
      risk.level,
      "UNKNOWN"
    )
  );

  /*
   * ---------------------------------------------------------
   * NETWORK STATUS
   * ---------------------------------------------------------
   */

  const networkPluginStatus =
    volatility?.plugins?.[
      "windows.netscan"
    ];

  const networkStatus =
    networkPluginStatus ||
    (networkEvents > 0
      ? "Completed"
      : "Not Run / No Events");

  /*
   * ---------------------------------------------------------
   * VOLATILITY STATUS
   * ---------------------------------------------------------
   */

  const pluginStatuses =
    volatility?.plugins || {};

  const volatilityCompleted =
    Object.keys(pluginStatuses).length === 0
      ? Boolean(analysis)
      : Object.values(pluginStatuses).some(
          (status) =>
            String(status).toLowerCase() ===
            "completed"
        );

  /*
   * ---------------------------------------------------------
   * REPORT ACTIONS
   * ---------------------------------------------------------
   */

  const printReport = () => {
    window.print();
  };

  const refreshReport = async () => {
    await loadMetadata();

    if (selectedEvidenceId) {
      await loadAnalysis(
        selectedEvidenceId
      );
    }
  };

  /*
   * ---------------------------------------------------------
   * LOADING
   * ---------------------------------------------------------
   */

  if (loading) {
    return (
      <div className="report-page report-loading-page">
        <div className="report-loading-card">
          <RefreshCw
            size={32}
            className="loading-spin"
          />

          <h2>
            Loading Forensic Report
          </h2>

          <p>
            Retrieving cases, evidence and
            investigation results.
          </p>
        </div>
      </div>
    );
  }

  /*
   * ---------------------------------------------------------
   * ERROR / NO EVIDENCE
   * ---------------------------------------------------------
   */

  if (!evidenceList.length) {
    return (
      <div className="report-page">
        <div className="report-empty-card">
          <FileText size={42} />

          <h2>No Evidence Available</h2>

          <p>
            Upload evidence and complete the
            forensic analysis before generating
            a report.
          </p>

          <button
            onClick={() =>
              navigate("/evidence")
            }
            className="report-primary-button"
          >
            Go to Evidence
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="report-page">
      {/* =====================================================
          HEADER
      ====================================================== */}

      <div className="report-topbar">
        <button
          className="report-back-button no-print"
          onClick={() =>
            navigate("/analysis")
          }
        >
          <ArrowLeft size={17} />
          Back to Analysis
        </button>

        <div className="report-actions no-print">
          <button
            className="report-secondary-button"
            onClick={refreshReport}
          >
            <RefreshCw size={16} />
            Refresh
          </button>

          <button
            className="report-primary-button"
            onClick={printReport}
          >
            <Printer size={16} />
            Print / Save PDF
          </button>
        </div>
      </div>

      {/* =====================================================
          REPORT HEADER
      ====================================================== */}

      <header className="report-hero">
        <div className="hero-icon">
          <ShieldCheck size={34} />
        </div>

        <div className="hero-content">
          <p className="hero-kicker">
            FORENSIRANSOM AI
          </p>

          <h1>
            Digital Forensic Investigation Report
          </h1>

          <p>
            AI-Based Intelligent Ransomware Detection
            & Automated Digital Forensic Investigation
          </p>
        </div>

        <div className="hero-status">
          <span>REPORT STATUS</span>

          <strong>
            Generated
          </strong>
        </div>
      </header>

      {/* =====================================================
          EVIDENCE SELECTOR
      ====================================================== */}

      <div className="report-selector-card no-print">
        <div className="selector-icon">
          <Database size={21} />
        </div>

        <div className="selector-content">
          <label>
            Select Evidence
          </label>

          <select
            value={selectedEvidenceId}
            onChange={handleEvidenceChange}
          >
            {evidenceList.map((item) => (
              <option
                key={item.evidence_id}
                value={item.evidence_id}
              >
                {item.evidence_id} —{" "}
                {item.filename}
              </option>
            ))}
          </select>
        </div>

        <div className="selector-current">
          <span>ACTIVE EVIDENCE</span>
          <strong>{evidenceId}</strong>
        </div>
      </div>

      {error && (
        <div className="report-error no-print">
          <AlertTriangle size={18} />
          {error}
        </div>
      )}

      {/* =====================================================
          SUMMARY STRIP
      ====================================================== */}

      <div className="report-summary-grid">
        <MetricCard
          icon={<Fingerprint size={21} />}
          label="Evidence ID"
          value={evidenceId}
          description={filename}
        />

        <MetricCard
          icon={<Activity size={21} />}
          label="Forensic Events"
          value={formatNumber(totalEvents)}
          description="Events extracted"
        />

        <MetricCard
          icon={<Search size={21} />}
          label="YARA Matches"
          value={formatNumber(yaraMatchCount)}
          description="Detection findings"
        />

        <MetricCard
          icon={<AlertTriangle size={21} />}
          label="Risk Level"
          value={riskLevel}
          description={`Score ${riskScore}`}
        />
      </div>

      {/* =====================================================
          01 CASE INFORMATION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="01"
          title="Case Information"
          description="Investigation and case identification details."
          icon={<FileText size={20} />}
        />

        <div className="report-info-grid">
          <InfoRow
            label="Case ID"
            value={caseId}
          />

          <InfoRow
            label="Case Name"
            value={caseName}
          />

          <InfoRow
            label="Investigator"
            value={investigator}
          />

          <InfoRow
            label="Case Status"
            value={caseStatus}
          />

          <div className="report-info-row full-width">
            <span>
              Investigation Description
            </span>

            <strong>
              {caseDescription}
            </strong>
          </div>
        </div>
      </section>

      {/* =====================================================
          02 EVIDENCE INFORMATION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="02"
          title="Evidence Information"
          description="Identification, acquisition and integrity information for the selected evidence."
          icon={<Fingerprint size={20} />}
        />

        <div className="report-info-grid">
          <InfoRow
            label="Evidence ID"
            value={evidenceId}
          />

          <InfoRow
            label="Evidence Type"
            value={evidenceType}
          />

          <InfoRow
            label="File Name"
            value={filename}
          />

          <InfoRow
            label="File Size"
            value={formatFileSize(fileSize)}
          />

          <InfoRow
            label="Acquisition Date"
            value={formatDate(acquisitionDate)}
          />

          <InfoRow
            label="SHA-256"
            value={sha256}
          />
        </div>

        <div className="integrity-panel">
          <div className="integrity-icon">
            <LockKeyhole size={23} />
          </div>

          <div>
            <span>
              Evidence Integrity
            </span>

            <strong>
              {getIntegrityText(integrity)}
            </strong>
          </div>

          <AppStatus
            type={
              getIntegrityClass(integrity) ===
              "status-success"
                ? "success"
                : getIntegrityClass(integrity) ===
                  "status-danger"
                ? "danger"
                : "warning"
            }
          >
            {getIntegrityText(integrity)}
          </AppStatus>
        </div>

        <p className="report-note">
          The SHA-256 hash of the uploaded evidence
          is calculated and stored by the forensic
          system. Integrity status is based on the
          evidence verification result.
        </p>
      </section>

      {/* =====================================================
          03 FORENSIC ANALYSIS SUMMARY
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="03"
          title="Forensic Analysis Summary"
          description="Status of the automated forensic investigation pipeline."
          icon={<Activity size={20} />}
        />

        <div className="pipeline-grid">
          {[
            ["Evidence Verification", "Verified"],
            [
              "Volatility Analysis",
              volatilityCompleted
                ? "Completed"
                : "Not Available",
            ],
            [
              "Process Analysis",
              "Completed",
            ],
            [
              "Command Analysis",
              "Completed",
            ],
            [
              "Network Analysis",
              networkStatus,
            ],
            [
              "Timeline Analysis",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "YARA Analysis",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "Rule-Based Detection",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "Evidence Correlation",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "Feature Extraction",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "Machine Learning Analysis",
              analysis
                ? "Completed"
                : "Not Available",
            ],
            [
              "Risk Assessment",
              analysis
                ? "Completed"
                : "Not Available",
            ],
          ].map(([label, status]) => (
            <div
              className="pipeline-item"
              key={label}
            >
              <span>{label}</span>

              <AppStatus
                type={
                  String(status)
                    .toLowerCase()
                    .includes("not")
                    ? "warning"
                    : "success"
                }
              >
                {status}
              </AppStatus>
            </div>
          ))}
        </div>
      </section>

      {/* =====================================================
          04 FORENSIC FINDINGS
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="04"
          title="Forensic Findings"
          description="Summary of artifacts recovered and analyzed from the selected evidence."
          icon={<Search size={20} />}
        />

        <div className="finding-subsection">
          <div className="subsection-title">
            <Terminal size={18} />
            <h3>
              4.1 Process Analysis
            </h3>
          </div>

          <div className="finding-metric">
            <span>Total Process Events</span>
            <strong>
              {formatNumber(processEvents)}
            </strong>
          </div>

          <p>
            The system analyzed process-related
            artifacts extracted from the selected
            memory image and evaluated process activity
            and relationships.
          </p>

          <ul>
            <li>
              Process activity was extracted from
              the evidence.
            </li>

            <li>
              Process relationships were analyzed.
            </li>

            <li>
              Suspicious process behavior was evaluated
              using the forensic rule engine.
            </li>

            <li>
              Relevant process findings are included
              in the investigation analysis.
            </li>
          </ul>
        </div>

        <div className="finding-subsection">
          <div className="subsection-title">
            <Terminal size={18} />
            <h3>
              4.2 Command-Line Analysis
            </h3>
          </div>

          <div className="finding-metric">
            <span>Command Events</span>
            <strong>
              {formatNumber(commandEvents)}
            </strong>
          </div>

          <p>
            Command-line artifacts recovered from
            the selected evidence were examined for
            suspicious execution activity.
          </p>

          <div className="finding-status-box">
            <span>
              Suspicious Command Activity
            </span>

            <strong
              className={
                commandEvents > 0
                  ? "detected-text"
                  : "safe-text"
              }
            >
              {commandEvents > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>
        </div>

        <div className="finding-subsection">
          <div className="subsection-title">
            <Network size={18} />
            <h3>
              4.3 Network Analysis
            </h3>
          </div>

          <div className="finding-metric">
            <span>Network Events</span>
            <strong>
              {formatNumber(networkEvents)}
            </strong>
          </div>

          <p>
            Network-related artifacts were examined
            when the corresponding forensic analysis
            was available.
          </p>

          <div className="finding-status-box">
            <span>Network Finding</span>

            <strong>
              {networkEvents > 0
                ? "Network activity identified"
                : "No Network Events Available"}
            </strong>
          </div>
        </div>

        <div className="finding-subsection">
          <div className="subsection-title">
            <Clock3 size={18} />
            <h3>
              4.4 Timeline Analysis
            </h3>
          </div>

          <div className="finding-metric">
            <span>Total Timeline Events</span>
            <strong>
              {formatNumber(
                timeline.length ||
                  totalEvents
              )}
            </strong>
          </div>

          <p>
            A forensic timeline was generated from
            the available artifacts. The timeline
            provides a chronological representation
            of relevant forensic events.
          </p>
        </div>
      </section>

      {/* =====================================================
          05 YARA DETECTION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="05"
          title="YARA Detection"
          description="Detection results from the configured ransomware-related YARA rules."
          icon={<ShieldCheck size={20} />}
        />

        <div className="three-metric-grid">
          <MetricCard
            icon={<ShieldCheck size={20} />}
            label="YARA Rules Executed"
            value={
              yara.rules_executed ??
              yara.rule_count ??
              "Calculated"
            }
          />

          <MetricCard
            icon={<AlertTriangle size={20} />}
            label="YARA Matches"
            value={formatNumber(
              yaraMatchCount
            )}
          />

          <MetricCard
            icon={<Search size={20} />}
            label="Suspicious Findings"
            value={formatNumber(
              yaraFindings.length ||
                yaraMatchCount
            )}
          />
        </div>

        <div className="report-table-wrapper">
          <table className="report-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Description</th>
              </tr>
            </thead>

            <tbody>
              {yaraFindings.length > 0 ? (
                yaraFindings.map(
                  (finding, index) => (
                    <tr key={index}>
                      <td>
                        {firstValue(
                          finding.rule,
                          finding.rule_name,
                          finding.name,
                          "Unknown Rule"
                        )}
                      </td>

                      <td>
                        <span className="table-badge detected">
                          Detected
                        </span>
                      </td>

                      <td>
                        {firstValue(
                          finding.source,
                          finding.plugin,
                          "Not Available"
                        )}
                      </td>

                      <td>
                        {firstValue(
                          finding.description,
                          "Not Available"
                        )}
                      </td>
                    </tr>
                  )
                )
              ) : (
                <tr>
                  <td colSpan="4">
                    No YARA findings were identified
                    for this evidence.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* =====================================================
          06 RULE BASED DETECTION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="06"
          title="Rule-Based Detection"
          description="Suspicious behavior identified by the forensic rule engine."
          icon={<AlertTriangle size={20} />}
        />

        <div className="four-metric-grid">
          <MetricCard
            icon={<AlertTriangle size={20} />}
            label="Suspicious Events"
            value={formatNumber(
              suspiciousEvents
            )}
          />

          <MetricCard
            icon={<ShieldCheck size={20} />}
            label="High-Risk Events"
            value={formatNumber(
              highRiskEvents
            )}
          />

          <MetricCard
            icon={<Activity size={20} />}
            label="Medium-Risk Events"
            value={formatNumber(
              mediumRiskEvents
            )}
          />

          <MetricCard
            icon={<Terminal size={20} />}
            label="Total Rule Score"
            value={formatNumber(
              ruleScore
            )}
          />
        </div>

        <div className="score-summary">
          <span>
            Maximum Rule Score
          </span>

          <strong>
            {formatNumber(
              maximumRuleScore
            )}
          </strong>
        </div>

        <div className="report-message-box">
          <AlertTriangle size={18} />

          <div>
            <strong>
              Rule Findings
            </strong>

            <p>
              {suspiciousEvents > 0
                ? `${suspiciousEvents} suspicious forensic event(s) were identified by the rule engine.`
                : "No suspicious rule-based findings were identified for this evidence."}
            </p>
          </div>
        </div>
      </section>

      {/* =====================================================
          07 CORRELATION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="07"
          title="Evidence Correlation"
          description="Relationships identified between independent forensic artifacts."
          icon={<Network size={20} />}
        />

        <div className="three-metric-grid">
          <MetricCard
            icon={<Network size={20} />}
            label="Total Correlations"
            value={formatNumber(
              correlationCount
            )}
          />

          <MetricCard
            icon={<AlertTriangle size={20} />}
            label="High-Severity Correlations"
            value={formatNumber(
              highCorrelationCount
            )}
          />

          <MetricCard
            icon={<Activity size={20} />}
            label="Medium-Severity Correlations"
            value={formatNumber(
              mediumCorrelationCount
            )}
          />
        </div>

        <h3 className="subsection-heading">
          Important Correlations
        </h3>

        {correlations.length > 0 ? (
          <div className="correlation-list">
            {correlations.map(
              (item, index) => (
                <div
                  className="correlation-item"
                  key={index}
                >
                  <div className="correlation-number">
                    {index + 1}
                  </div>

                  <div>
                    <strong>
                      {firstValue(
                        item.description,
                        item.message,
                        "Forensic artifacts were correlated."
                      )}
                    </strong>

                    <span>
                      Severity:{" "}
                      {firstValue(
                        item.severity,
                        "Not Available"
                      )}
                    </span>
                  </div>
                </div>
              )
            )}
          </div>
        ) : (
          <div className="empty-finding">
            No evidence correlations were identified
            for this evidence.
          </div>
        )}
      </section>

      {/* =====================================================
          08 MACHINE LEARNING
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="08"
          title="AI / Machine Learning Assessment"
          description="Automated classification based on extracted forensic features."
          icon={<Brain size={20} />}
        />

        <div className="ml-classification-card">
          <div className="ml-icon">
            <Brain size={28} />
          </div>

          <div>
            <span>Classification</span>

            <strong>
              {String(
                classification
              ).toUpperCase()}
            </strong>
          </div>
        </div>

        <h3 className="subsection-heading">
          Probability Distribution
        </h3>

        <div className="probability-grid">
          <div className="probability-card">
            <span>Normal</span>
            <strong>
              {normalProbability.toFixed(1)}%
            </strong>

            <div className="probability-bar">
              <div
                style={{
                  width: `${Math.min(
                    normalProbability,
                    100
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="probability-card">
            <span>Suspicious</span>
            <strong>
              {suspiciousProbability.toFixed(
                1
              )}
              %
            </strong>

            <div className="probability-bar">
              <div
                style={{
                  width: `${Math.min(
                    suspiciousProbability,
                    100
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="probability-card">
            <span>Ransomware</span>
            <strong>
              {ransomwareProbability.toFixed(
                1
              )}
              %
            </strong>

            <div className="probability-bar">
              <div
                style={{
                  width: `${Math.min(
                    ransomwareProbability,
                    100
                  )}%`,
                }}
              />
            </div>
          </div>
        </div>

        <h3 className="subsection-heading">
          Extracted Feature Summary
        </h3>

        <div className="feature-grid">
          <InfoRow
            label="Total Events"
            value={formatNumber(
              totalEvents
            )}
          />

          <InfoRow
            label="Process Events"
            value={formatNumber(
              processEvents
            )}
          />

          <InfoRow
            label="Command Events"
            value={formatNumber(
              commandEvents
            )}
          />

          <InfoRow
            label="Network Events"
            value={formatNumber(
              networkEvents
            )}
          />

          <InfoRow
            label="Suspicious Events"
            value={formatNumber(
              suspiciousEvents
            )}
          />

          <InfoRow
            label="YARA Findings"
            value={formatNumber(
              yaraMatchCount
            )}
          />

          <InfoRow
            label="Correlations"
            value={formatNumber(
              correlationCount
            )}
          />

          <InfoRow
            label="Rule Score"
            value={formatNumber(
              ruleScore
            )}
          />
        </div>

        <p className="report-note">
          The ML result is an automated assessment
          based on the extracted forensic features and
          the trained model. It should be interpreted
          together with the underlying forensic findings.
        </p>
      </section>

      {/* =====================================================
          09 RISK ASSESSMENT
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="09"
          title="Risk Assessment"
          description="Risk calculated from the available forensic indicators."
          icon={<AlertTriangle size={20} />}
        />

        <div
          className={`risk-result-card ${getRiskClass(
            riskLevel
          )}`}
        >
          <div>
            <span>Risk Score</span>
            <strong>
              {formatNumber(riskScore)}
            </strong>
          </div>

          <div>
            <span>Risk Level</span>
            <strong>
              {riskLevel}
            </strong>
          </div>
        </div>

        <h3 className="subsection-heading">
          Risk Factors
        </h3>

        <div className="risk-factor-grid">
          <div>
            <span>Suspicious Events</span>
            <strong>
              {suspiciousEvents > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>

          <div>
            <span>YARA Findings</span>
            <strong>
              {yaraMatchCount > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>

          <div>
            <span>Rule-Based Findings</span>
            <strong>
              {ruleScore > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>

          <div>
            <span>Evidence Correlations</span>
            <strong>
              {correlationCount > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>

          <div>
            <span>ML Assessment</span>
            <strong>
              {String(classification)}
            </strong>
          </div>

          <div>
            <span>High-Risk Findings</span>
            <strong>
              {highRiskEvents > 0
                ? "Detected"
                : "Not Detected"}
            </strong>
          </div>
        </div>

        <p className="report-note">
          The final risk level is generated from the
          available forensic analysis results and
          corresponds only to the selected evidence.
        </p>
      </section>

      {/* =====================================================
          10 KEY FORENSIC FINDINGS
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="10"
          title="Key Forensic Findings"
          description="Most relevant findings identified during the investigation."
          icon={<AlertTriangle size={20} />}
        />

        <div className="key-findings">
          {yaraMatchCount > 0 && (
            <div className="key-finding">
              <div>1</div>

              <p>
                {formatNumber(
                  yaraMatchCount
                )}{" "}
                YARA finding(s) were identified
                during evidence scanning.
              </p>
            </div>
          )}

          {suspiciousEvents > 0 && (
            <div className="key-finding">
              <div>
                {yaraMatchCount > 0 ? "2" : "1"}
              </div>

              <p>
                {formatNumber(
                  suspiciousEvents
                )}{" "}
                suspicious forensic event(s) were
                identified.
              </p>
            </div>
          )}

          {correlationCount > 0 && (
            <div className="key-finding">
              <div>
                {yaraMatchCount > 0 &&
                suspiciousEvents > 0
                  ? "3"
                  : "2"}
              </div>

              <p>
                {formatNumber(
                  correlationCount
                )}{" "}
                evidence correlation(s) were
                identified between forensic artifacts.
              </p>
            </div>
          )}

          {yaraMatchCount === 0 &&
            suspiciousEvents === 0 &&
            correlationCount === 0 && (
              <div className="empty-finding">
                No significant forensic findings were
                identified for this evidence.
              </div>
            )}
        </div>

        <p className="report-note">
          Detailed raw forensic output remains
          available in the Analysis page. This report
          contains only the significant investigation
          findings.
        </p>
      </section>

      {/* =====================================================
          11 CONCLUSION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="11"
          title="Investigation Conclusion"
          description="Evidence-specific summary generated from the completed investigation."
          icon={<FileText size={20} />}
        />

        <div className="conclusion-box">
          <p>
            Based on the forensic artifacts,
            rule-based findings, YARA analysis,
            evidence correlations, machine-learning
            assessment, and calculated risk score,
            the system generated the following
            investigation summary for the selected
            evidence.
          </p>

          <div className="conclusion-grid">
            <div>
              <span>
                Investigation Classification
              </span>

              <strong>
                {String(
                  classification
                ).toUpperCase()}
              </strong>
            </div>

            <div>
              <span>Risk Level</span>

              <strong>
                {riskLevel}
              </strong>
            </div>

            <div>
              <span>Evidence Integrity</span>

              <strong>
                {getIntegrityText(
                  integrity
                )}
              </strong>
            </div>
          </div>

          <p>
            This conclusion is specific to Case{" "}
            <strong>{caseId}</strong> and Evidence{" "}
            <strong>{evidenceId}</strong>.
            Results from other investigations are not
            included.
          </p>
        </div>
      </section>

      {/* =====================================================
          12 INVESTIGATOR VERIFICATION
      ====================================================== */}

      <section className="report-section">
        <SectionHeader
          number="12"
          title="Investigator Verification"
          description="Final investigation identification and verification details."
          icon={<LockKeyhole size={20} />}
        />

        <div className="verification-grid">
          <InfoRow
            label="Case ID"
            value={caseId}
          />

          <InfoRow
            label="Evidence ID"
            value={evidenceId}
          />

          <InfoRow
            label="Investigator"
            value={investigator}
          />

          <InfoRow
            label="Analysis Status"
            value={
              analysis
                ? "Completed"
                : "Not Available"
            }
          />

          <InfoRow
            label="Report Status"
            value="Generated"
          />
        </div>

        <div className="signature-area">
          <div>
            <span>
              Investigator Signature
            </span>

            <div className="signature-line" />
          </div>

          <div>
            <span>Date</span>

            <div className="signature-line" />
          </div>
        </div>
      </section>

      {/* =====================================================
          FOOTER
      ====================================================== */}

      <footer className="report-footer">
        <div>
          <strong>
            ForensiRansom AI
          </strong>

          <span>
            AI-Based Intelligent Ransomware Detection
            & Automated Digital Forensic Investigation
          </span>
        </div>

        <div>
          Evidence:{" "}
          <strong>{evidenceId}</strong>
          {" | "}
          Case:{" "}
          <strong>{caseId}</strong>
        </div>
      </footer>
    </div>
  );
}