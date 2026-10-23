import React, { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  LogOut,
  User as UserIcon,
  Folder,
  FileText,
  ScanSearch,
  FileBarChart,
  Server,
  Cloud,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  SlidersHorizontal,
  X
} from "lucide-react";

import {
  API_BASE_URL,
  RENDER_PRODUCTION_URL,
  LOCAL_DEV_URL,
  getSavedBackendUrl,
  setSavedBackendUrl,
  getCurrentUser,
  clearAuthSession,
  authFetch
} from "../config";

function Sidebar() {
  const [backendHealthy, setBackendHealthy] = useState(null);
  const currentUser = getCurrentUser() || { username: "Investigator", role: "Investigator" };

  const handleLogout = async () => {
    try {
      const target = API_BASE_URL ? `${API_BASE_URL}/auth/logout` : "/auth/logout";
      await authFetch(target, { method: "POST" });
    } catch {
      // ignore
    }
    clearAuthSession();
    window.location.href = "/";
  };
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [customInput, setCustomInput] = useState("");

  const activeSaved = getSavedBackendUrl();
  const currentTargetLabel =
    activeSaved === LOCAL_DEV_URL
      ? "Local (127.0.0.1:8000)"
      : activeSaved
      ? "Custom Backend"
      : API_BASE_URL === LOCAL_DEV_URL
      ? "Local Dev"
      : "Render Cloud";

  const checkHealth = async () => {
    setCheckingHealth(true);
    try {
      const target = API_BASE_URL ? `${API_BASE_URL}/health` : "/health";
      const res = await fetch(target, { method: "GET" });
      if (res.ok) {
        setBackendHealthy(true);
      } else {
        setBackendHealthy(false);
      }
    } catch {
      setBackendHealthy(false);
    } finally {
      setCheckingHealth(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside className="sidebar">
      {/* =========================
          LOGO
      ========================== */}
      <div className="logo">
        <h2>ForensiRansom AI</h2>
        <p>Digital Forensic Platform</p>
      </div>

      {/* =========================
          NAVIGATION
      ========================== */}
      <nav>
        {/* Dashboard */}
        <NavLink to="/dashboard">
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </NavLink>

        {/* Cases */}
        <NavLink to="/cases">
          <Folder size={20} />
          <span>Cases</span>
        </NavLink>

        {/* Evidence */}
        <NavLink to="/evidence">
          <FileText size={20} />
          <span>Evidence</span>
        </NavLink>

        {/* Memory Analysis */}
        <NavLink to="/analysis">
          <ScanSearch size={20} />
          <span>Memory Analysis</span>
        </NavLink>

        {/* Reports */}
        <NavLink to="/report">
          <FileBarChart size={20} />
          <span>Reports</span>
        </NavLink>
      </nav>

      {/* =========================
          BACKEND STATUS & SWITCHER
      ========================== */}
      <div
        style={{
          margin: "12px 14px",
          padding: "10px 12px",
          background: "rgba(255, 255, 255, 0.04)",
          borderRadius: "8px",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          fontSize: "12px",
          color: "#94a3b8"
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "6px"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            {backendHealthy === true ? (
              <CheckCircle2 size={13} style={{ color: "#22c55e" }} />
            ) : backendHealthy === false ? (
              <AlertCircle size={13} style={{ color: "#ef4444" }} />
            ) : (
              <RefreshCw
                size={13}
                style={{ color: "#f59e0b", animation: "spin 1s linear infinite" }}
              />
            )}
            <span
              style={{
                fontWeight: 600,
                color: backendHealthy ? "#22c55e" : backendHealthy === false ? "#ef4444" : "#f59e0b"
              }}
            >
              {backendHealthy ? "Backend Online" : backendHealthy === false ? "Backend Offline" : "Connecting..."}
            </span>
          </div>

          <button
            onClick={() => setShowConfigModal(true)}
            title="Configure Backend Connection"
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              padding: "2px"
            }}
          >
            <SlidersHorizontal size={14} />
          </button>
        </div>

        <div
          style={{
            fontSize: "11px",
            color: "#64748b",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}
        >
          <span title={API_BASE_URL || "Same Origin"}>
            Target: <b>{currentTargetLabel}</b>
          </span>
          <button
            onClick={checkHealth}
            disabled={checkingHealth}
            title="Ping backend now"
            style={{
              background: "none",
              border: "none",
              color: "#38bdf8",
              fontSize: "10px",
              cursor: "pointer",
              textDecoration: "underline"
            }}
          >
            {checkingHealth ? "Checking..." : "Ping"}
          </button>
        </div>
      </div>

      {/* =========================
          CONFIG MODAL
      ========================== */}
      {showConfigModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999
          }}
        >
          <div
            style={{
              background: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "12px",
              padding: "20px",
              width: "420px",
              color: "#f8fafc",
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5)"
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "16px",
                borderBottom: "1px solid #1e293b",
                paddingBottom: "10px"
              }}
            >
              <h3 style={{ margin: 0, fontSize: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Server size={18} style={{ color: "#38bdf8" }} /> Backend Connection
              </h3>
              <button
                onClick={() => setShowConfigModal(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#94a3b8",
                  cursor: "pointer"
                }}
              >
                <X size={18} />
              </button>
            </div>

            <p style={{ fontSize: "13px", color: "#94a3b8", margin: "0 0 14px 0" }}>
              Select which backend service this application communicates with:
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {/* Option 1: Render Production */}
              <button
                onClick={() => {
                  setSavedBackendUrl("default");
                  setShowConfigModal(false);
                }}
                style={{
                  padding: "10px 14px",
                  borderRadius: "8px",
                  background: !activeSaved ? "#1e293b" : "#0b1329",
                  border: !activeSaved ? "1px solid #38bdf8" : "1px solid #1e293b",
                  color: "#f8fafc",
                  textAlign: "left",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "10px"
                }}
              >
                <Cloud size={18} style={{ color: "#38bdf8" }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Production Cloud (Render)</div>
                  <div style={{ fontSize: "11px", color: "#64748b" }}>
                    intelligent-ransomeware-detection-using-jmsr.onrender.com
                  </div>
                </div>
              </button>

              {/* Option 2: Local Server */}
              <button
                onClick={() => {
                  setSavedBackendUrl(LOCAL_DEV_URL);
                  setShowConfigModal(false);
                }}
                style={{
                  padding: "10px 14px",
                  borderRadius: "8px",
                  background: activeSaved === LOCAL_DEV_URL ? "#1e293b" : "#0b1329",
                  border: activeSaved === LOCAL_DEV_URL ? "1px solid #38bdf8" : "1px solid #1e293b",
                  color: "#f8fafc",
                  textAlign: "left",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "10px"
                }}
              >
                <Server size={18} style={{ color: "#22c55e" }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Local Forensic Backend</div>
                  <div style={{ fontSize: "11px", color: "#64748b" }}>http://127.0.0.1:8000</div>
                </div>
              </button>

              {/* Option 3: Custom URL */}
              <div
                style={{
                  marginTop: "8px",
                  padding: "10px",
                  background: "#0b1329",
                  borderRadius: "8px",
                  border: "1px solid #1e293b"
                }}
              >
                <label style={{ fontSize: "12px", color: "#94a3b8", display: "block", marginBottom: "6px" }}>
                  Custom Backend URL:
                </label>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    type="text"
                    value={customInput}
                    onChange={(e) => setCustomInput(e.target.value)}
                    placeholder="https://your-backend.example.com"
                    style={{
                      flex: 1,
                      padding: "6px 10px",
                      background: "#0f172a",
                      border: "1px solid #334155",
                      borderRadius: "6px",
                      color: "#f8fafc",
                      fontSize: "12px"
                    }}
                  />
                  <button
                    onClick={() => {
                      if (customInput.trim()) {
                        setSavedBackendUrl(customInput.trim());
                        setShowConfigModal(false);
                      }
                    }}
                    style={{
                      padding: "6px 12px",
                      background: "#2563eb",
                      border: "none",
                      borderRadius: "6px",
                      color: "#fff",
                      fontSize: "12px",
                      fontWeight: 600,
                      cursor: "pointer"
                    }}
                  >
                    Apply
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================
          AUTHENTICATED USER PROFILE & LOGOUT
      ========================== */}
      <div
        style={{
          margin: "12px 14px",
          padding: "10px 12px",
          background: "rgba(255, 255, 255, 0.04)",
          borderRadius: "8px",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          fontSize: "12px"
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginRight: "8px" }}>
            <div style={{ fontWeight: 600, color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
              <UserIcon size={14} style={{ color: "#38bdf8" }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{currentUser.username}</span>
            </div>
            <div style={{ fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
              {currentUser.role || "Investigator"}
            </div>
          </div>
          <button
            onClick={handleLogout}
            title="Log out from session"
            style={{
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid rgba(239, 68, 68, 0.35)",
              color: "#f87171",
              padding: "4px 8px",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "11px",
              fontWeight: 600,
              display: "flex",
              alignItems: "center",
              gap: "4px"
            }}
          >
            <LogOut size={12} /> Sign Out
          </button>
        </div>
      </div>

      {/* =========================
          SIDEBAR FOOTER
      ========================== */}
      <div className="sidebar-footer">
        <p>ForensiRansom AI v1.0</p>
      </div>
    </aside>
  );
}

export default Sidebar;
