import React, { useEffect, useState } from "react";
import {
  RefreshCw,
  FolderOpen,
  FileText,
  ShieldCheck,
  Activity,
  Search,
  AlertTriangle,
  Database,
  CheckCircle,
  Circle,
  ShieldAlert,
  Fingerprint,
  BarChart3,
  Clock3,
} from "lucide-react";

import "./Dashboard.css";

const API_BASE = "http://127.0.0.1:8000";

function Dashboard() {
  const [statistics, setStatistics] = useState(null);
  const [cases, setCases] = useState([]);
  const [analysisStatus, setAnalysisStatus] = useState(null);
  const [riskData, setRiskData] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const evidenceId = "MEM-001";

  const fetchDashboardData = async () => {
    try {
      setError("");

      const [
        statisticsResponse,
        casesResponse,
        statusResponse,
        riskResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/dashboard/statistics`),
        fetch(`${API_BASE}/cases`),
        fetch(`${API_BASE}/analysis/status/${evidenceId}`),
        fetch(`${API_BASE}/analysis/risk/${evidenceId}`),
      ]);

      if (!statisticsResponse.ok) {
        throw new Error("Unable to load dashboard statistics");
      }

      if (!casesResponse.ok) {
        throw new Error("Unable to load cases");
      }

      const statisticsData = await statisticsResponse.json();
      const casesData = await casesResponse.json();

      let statusData = null;
      let riskResult = null;

      if (statusResponse.ok) {
        statusData = await statusResponse.json();
      }

      if (riskResponse.ok) {
        riskResult = await riskResponse.json();
      }

      setStatistics(statisticsData);
      setCases(Array.isArray(casesData) ? casesData : []);
      setAnalysisStatus(statusData);
      setRiskData(riskResult);
    } catch (err) {
      console.error(err);
      setError(err.message || "Unable to load dashboard");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchDashboardData();
  };

  const getRiskClass = (riskLevel) => {
    const level = String(riskLevel || "").toUpperCase();

    if (level === "CRITICAL") return "risk-critical";
    if (level === "HIGH") return "risk-high";
    if (level === "MEDIUM") return "risk-medium";
    if (level === "LOW") return "risk-low";

    return "risk-unknown";
  };

  const getIntegrityClass = (status) => {
    const value = String(status || "").toUpperCase();

    if (value === "VERIFIED" || value === "INTACT") {
      return "integrity-good";
    }

    if (value === "COMPROMISED") {
      return "integrity-danger";
    }

    return "integrity-unknown";
  };

  const formatIntegrityStatus = (status) => {
    const value = String(status || "").toUpperCase();

    if (value === "VERIFIED") {
      return "VERIFIED";
    }

    if (value === "INTACT") {
      return "INTACT";
    }

    if (value === "COMPROMISED") {
      return "COMPROMISED";
    }

    return status || "UNKNOWN";
  };

  const getPluginIcon = (status) => {
    if (status === "Completed") {
      return <CheckCircle size={18} />;
    }

    return <Circle size={18} />;
  };

  const getPluginClass = (status) => {
    return status === "Completed"
      ? "plugin-completed"
      : "plugin-pending";
  };

  const statsCards = [
    {
      title: "Total Cases",
      value: statistics?.total_cases ?? 0,
      icon: FolderOpen,
      className: "blue",
    },
    {
      title: "Total Evidence",
      value: statistics?.total_evidence ?? 0,
      icon: FileText,
      className: "purple",
    },
    {
      title: "Verified Evidence",
      value: statistics?.verified_evidence ?? 0,
      icon: ShieldCheck,
      className: "green",
    },
    {
      title: "Analyses Completed",
      value: statistics?.analyses_completed ?? 0,
      icon: Activity,
      className: "cyan",
    },
    {
      title: "YARA Matches",
      value: statistics?.yara_matches ?? 0,
      icon: Search,
      className: "orange",
    },
    {
      title: "Suspicious Events",
      value: statistics?.suspicious_events ?? 0,
      icon: AlertTriangle,
      className: "red",
    },
    {
      title: "High Risk Findings",
      value: statistics?.high_risk_findings ?? 0,
      icon: ShieldAlert,
      className: "pink",
    },
    {
      title: "Open Investigations",
      value: statistics?.open_investigations ?? 0,
      icon: Database,
      className: "indigo",
    },
  ];

  if (loading) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-loading">
          <RefreshCw className="loading-icon" size={28} />
          <p>Loading forensic dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-page">

      {/* ================= HEADER ================= */}
      <div className="dashboard-header">
        <div>
          <div className="dashboard-eyebrow">
            <Fingerprint size={17} />
            FORENSIC INVESTIGATION PLATFORM
          </div>

          <h1>ForensiRansom AI</h1>

          <p>
            Digital Forensic Investigation Dashboard
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          <RefreshCw
            size={17}
            className={refreshing ? "spin" : ""}
          />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {/* ================= ERROR ================= */}
      {error && (
        <div className="dashboard-error">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* ================= STATISTICS ================= */}
      <section className="dashboard-section">
        <div className="section-heading">
          <div>
            <h2>Investigation Overview</h2>
            <p>Current forensic investigation statistics</p>
          </div>

          <BarChart3 size={22} />
        </div>

        <div className="stats-grid">
          {statsCards.map((card) => {
            const Icon = card.icon;

            return (
              <div
                className={`stat-card ${card.className}`}
                key={card.title}
              >
                <div className="stat-card-top">
                  <div className="stat-icon">
                    <Icon size={20} />
                  </div>
                </div>

                <div className="stat-value">
                  {card.value}
                </div>

                <div className="stat-title">
                  {card.title}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ================= MAIN GRID ================= */}
      <div className="dashboard-main-grid">

        {/* ================= CASES ================= */}
        <section className="dashboard-panel investigations-panel">
          <div className="panel-header">
            <div>
              <h2>
                <FolderOpen size={20} />
                Current Investigations
              </h2>

              <p>
                Active forensic cases
              </p>
            </div>

            <span className="case-count">
              {cases.length} Cases
            </span>
          </div>

          {cases.length === 0 ? (
            <div className="empty-state">
              <FolderOpen size={30} />
              <p>No investigations found.</p>
            </div>
          ) : (
            <div className="case-list">
              {cases.map((item) => (
                <div
                  className="case-item"
                  key={item.case_id}
                >
                  <div className="case-icon">
                    <FolderOpen size={19} />
                  </div>

                  <div className="case-content">
                    <div className="case-top">
                      <span className="case-id">
                        {item.case_id}
                      </span>

                      <span
                        className={`case-status ${
                          String(item.status || "").toLowerCase()
                        }`}
                      >
                        {item.status}
                      </span>
                    </div>

                    <h3>{item.case_name}</h3>

                    <div className="case-meta">
                      <span>
                        <strong>Investigator:</strong>{" "}
                        {item.investigator || "N/A"}
                      </span>
                    </div>

                    <p>
                      {item.description || "No description available."}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* ================= VOLATILITY ================= */}
        <section className="dashboard-panel volatility-panel">
          <div className="panel-header">
            <div>
              <h2>
                <Activity size={20} />
                Volatility Analysis
              </h2>

              <p>
                Memory forensic analysis status
              </p>
            </div>
          </div>

          <div className="evidence-reference">
            <span>Evidence</span>
            <strong>{evidenceId}</strong>
          </div>

          {!analysisStatus ? (
            <div className="empty-state small">
              <Clock3 size={25} />
              <p>Analysis status unavailable.</p>
            </div>
          ) : (
            <div className="plugin-list">
              {Object.entries(
                analysisStatus.plugins || {}
              ).map(([plugin, status]) => (
                <div
                  className={`plugin-item ${getPluginClass(status)}`}
                  key={plugin}
                >
                  <div className="plugin-left">
                    {getPluginIcon(status)}

                    <span>
                      {plugin}
                    </span>
                  </div>

                  <span className="plugin-status">
                    {status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* ================= RISK & INTEGRITY ================= */}
      <section className="dashboard-panel risk-panel">

        <div className="panel-header risk-panel-header">
          <div>
            <h2>
              <ShieldCheck size={21} />
              Risk &amp; Evidence Integrity
            </h2>

            <p>
              Forensic evidence verification and analysis indicators
            </p>
          </div>

          {riskData?.analysis_available && (
            <span className="analysis-ready">
              <CheckCircle size={15} />
              Analysis Available
            </span>
          )}
        </div>

        {!riskData ? (
          <div className="empty-state">
            <ShieldCheck size={30} />
            <p>Risk information unavailable.</p>
          </div>
        ) : (
          <>
            {/* Evidence Identity */}
            <div className="evidence-card">

              <div className="evidence-card-header">
                <div className="evidence-file-icon">
                  <FileText size={22} />
                </div>

                <div>
                  <h3>{riskData.filename}</h3>

                  <p>
                    Evidence ID:{" "}
                    <strong>{riskData.evidence_id}</strong>
                  </p>
                </div>

                <div
                  className={`integrity-badge ${getIntegrityClass(
                    riskData.integrity_status
                  )}`}
                >
                  <ShieldCheck size={16} />
                  {formatIntegrityStatus(
                    riskData.integrity_status
                  )}
                </div>
              </div>

              <div className="hash-section">
                <div className="hash-label">
                  <Fingerprint size={15} />
                  SHA-256 Evidence Hash
                </div>

                <div className="hash-value">
                  {riskData.sha256 || "Not available"}
                </div>
              </div>
            </div>

            {/* Risk Metrics */}
            <div className="risk-metrics">

              <div className="risk-metric">
                <div className="metric-icon orange">
                  <Search size={19} />
                </div>

                <div>
                  <span>YARA Matches</span>
                  <strong>
                    {riskData.yara_matches ?? 0}
                  </strong>
                </div>
              </div>

              <div className="risk-metric">
                <div className="metric-icon red">
                  <AlertTriangle size={19} />
                </div>

                <div>
                  <span>Suspicious Events</span>
                  <strong>
                    {riskData.suspicious_events ?? 0}
                  </strong>
                </div>
              </div>

              <div className="risk-metric">
                <div className="metric-icon purple">
                  <Activity size={19} />
                </div>

                <div>
                  <span>Correlations</span>
                  <strong>
                    {riskData.correlations ?? 0}
                  </strong>
                </div>
              </div>

              <div className="risk-metric">
                <div className="metric-icon blue">
                  <BarChart3 size={19} />
                </div>

                <div>
                  <span>Rule Score</span>
                  <strong>
                    {riskData.rule_score ?? 0}
                  </strong>
                </div>
              </div>

            </div>

            {/* Risk Level */}
            <div className="risk-level-container">

              <div className="risk-level-label">
                <ShieldAlert size={19} />
                <span>Current Risk Level</span>
              </div>

              <div
                className={`risk-level-badge ${getRiskClass(
                  riskData.risk_level
                )}`}
              >
                {riskData.risk_level || "UNKNOWN"}
              </div>

            </div>
          </>
        )}
      </section>

      {/* ================= FOOTER ================= */}
      <div className="dashboard-footer">
        <div>
          <ShieldCheck size={16} />
          <span>
            ForensiRansom AI • Digital Forensic Investigation
          </span>
        </div>

        <span>
          Evidence-driven forensic analysis
        </span>
      </div>

    </div>
  );
}

export default Dashboard;