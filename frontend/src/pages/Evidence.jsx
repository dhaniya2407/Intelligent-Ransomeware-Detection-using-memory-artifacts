import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

const API_BASE_URL = "http://127.0.0.1:8000";

function Evidence() {
  const navigate = useNavigate();

  const [evidenceList, setEvidenceList] = useState([]);
  const [cases, setCases] = useState([]);

  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [selectedFile, setSelectedFile] = useState(null);

  const [formData, setFormData] = useState({
    caseId: "",
    evidenceType: "Memory Image",
  });

  // =========================================================
  // LOAD CASES
  // =========================================================

  const fetchCases = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/cases`);

      if (!response.ok) {
        throw new Error("Failed to load cases.");
      }

      const data = await response.json();

      setCases(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error("Cases loading error:", error);
      setError("Unable to load investigation cases.");
    }
  };

  // =========================================================
  // LOAD EVIDENCE
  // =========================================================

  const fetchEvidence = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_BASE_URL}/evidence`);

      if (!response.ok) {
        throw new Error("Failed to load evidence.");
      }

      const data = await response.json();

      setEvidenceList(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error("Evidence loading error:", error);
      setError("Unable to load evidence records.");
    } finally {
      setLoading(false);
    }
  };

  // =========================================================
  // INITIAL LOAD
  // =========================================================

  useEffect(() => {
    fetchCases();
    fetchEvidence();
  }, []);

  // =========================================================
  // FORM CHANGE
  // =========================================================

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  // =========================================================
  // FILE SELECTION
  // =========================================================

  const handleFileChange = (e) => {
    const file = e.target.files[0];

    if (!file) {
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setError("");
    setSuccess("");
  };

  // =========================================================
  // UPLOAD EVIDENCE
  // =========================================================

  const handleSubmit = async (e) => {
    e.preventDefault();

    setError("");
    setSuccess("");

    if (!formData.caseId) {
      setError("Please select a Case.");
      return;
    }

    if (!selectedFile) {
      setError("Please select an evidence file.");
      return;
    }

    try {
      setUploading(true);

      const uploadData = new FormData();

      /*
       * IMPORTANT:
       * Evidence ID is NOT entered here.
       *
       * Backend automatically generates:
       * MEM-001
       * MEM-002
       * MEM-003
       * ...
       */

      uploadData.append("case_id", formData.caseId);
      uploadData.append("file", selectedFile);

      const response = await fetch(
        `${API_BASE_URL}/evidence/upload?case_id=${encodeURIComponent(
          formData.caseId
        )}`,
        {
          method: "POST",
          body: uploadData,
        }
      );

      if (!response.ok) {
        let errorMessage = "Failed to upload evidence.";

        try {
          const errorData = await response.json();

          if (errorData.detail) {
            errorMessage = errorData.detail;
          }
        } catch {
          // Ignore JSON parsing error
        }

        throw new Error(errorMessage);
      }

      const result = await response.json();

      setSuccess(
        `Evidence ${result.evidence_id} uploaded successfully.`
      );

      // Reset form
      setFormData({
        caseId: "",
        evidenceType: "Memory Image",
      });

      setSelectedFile(null);

      // Reset file input
      const fileInput = document.getElementById(
        "evidence-file-input"
      );

      if (fileInput) {
        fileInput.value = "";
      }

      // Reload evidence list
      await fetchEvidence();
    } catch (error) {
      console.error("Evidence upload error:", error);

      setError(
        error.message || "Unable to upload evidence."
      );
    } finally {
      setUploading(false);
    }
  };

  // =========================================================
  // OPEN ANALYSIS
  // =========================================================

  const openMemoryAnalysis = (evidenceId, evidenceType) => {
    if (evidenceType !== "Memory Image") {
      setError(
        "Memory Analysis is currently available only for Memory Image evidence."
      );

      return;
    }

    /*
     * Dynamic navigation.
     *
     * Example:
     * /analysis/MEM-001
     * /analysis/MEM-002
     * /analysis/MEM-003
     */

    navigate(`/analysis/${evidenceId}`);
  };

  // =========================================================
  // FORMAT FILE SIZE
  // =========================================================

  const formatFileSize = (size) => {
    if (!size || Number(size) === 0) {
      return "0 Bytes";
    }

    const bytes = Number(size);

    if (bytes < 1024) {
      return `${bytes} Bytes`;
    }

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    return `${(
      bytes /
      (1024 * 1024 * 1024)
    ).toFixed(2)} GB`;
  };

  // =========================================================
  // RENDER
  // =========================================================

  return (
    <div className="evidence-page">

      {/* =====================================================
          PAGE HEADER
      ===================================================== */}

      <div className="page-header">
        <div>
          <h1>Evidence Management</h1>

          <p>
            Add, verify and manage digital forensic evidence.
          </p>
        </div>
      </div>

      {/* =====================================================
          SUCCESS MESSAGE
      ===================================================== */}

      {success && (
        <div
          style={{
            padding: "12px 16px",
            marginBottom: "20px",
            borderRadius: "8px",
            background: "#ecfdf5",
            color: "#047857",
            border: "1px solid #a7f3d0",
          }}
        >
          ✓ {success}
        </div>
      )}

      {/* =====================================================
          ERROR MESSAGE
      ===================================================== */}

      {error && (
        <div
          style={{
            padding: "12px 16px",
            marginBottom: "20px",
            borderRadius: "8px",
            background: "#fef2f2",
            color: "#b91c1c",
            border: "1px solid #fecaca",
          }}
        >
          {error}
        </div>
      )}

      {/* =====================================================
          ADD EVIDENCE
      ===================================================== */}

      <div className="empty-card">

        <h2>Add New Evidence</h2>

        <p
          style={{
            color: "#64748b",
            marginBottom: "20px",
          }}
        >
          Select an investigation case and upload the evidence
          file. The forensic system will automatically generate
          the Evidence ID and calculate the SHA-256 hash.
        </p>

        <form
          onSubmit={handleSubmit}
          className="case-form"
        >

          {/* CASE SELECTION */}

          <label>
            Investigation Case
          </label>

          <select
            name="caseId"
            value={formData.caseId}
            onChange={handleChange}
          >
            <option value="">
              Select Case
            </option>

            {cases.map((item) => (
              <option
                key={item.case_id}
                value={item.case_id}
              >
                {item.case_id} — {item.case_name}
              </option>
            ))}
          </select>

          {/* FILE */}

          <label>
            Select Evidence File
          </label>

          <input
            id="evidence-file-input"
            type="file"
            onChange={handleFileChange}
          />

          {/* SELECTED FILE */}

          {selectedFile && (
            <div
              style={{
                padding: "12px",
                marginTop: "10px",
                background: "#f8fafc",
                border: "1px solid #e2e8f0",
                borderRadius: "8px",
              }}
            >
              <strong>
                Selected File:
              </strong>

              <p style={{ margin: "5px 0 0" }}>
                {selectedFile.name}
              </p>

              <small>
                Size:{" "}
                {formatFileSize(selectedFile.size)}
              </small>
            </div>
          )}

          {/* EVIDENCE TYPE */}

          <label>
            Evidence Type
          </label>

          <select
            name="evidenceType"
            value={formData.evidenceType}
            onChange={handleChange}
          >
            <option value="Memory Image">
              Memory Image
            </option>

            <option value="Disk Image">
              Disk Image
            </option>

            <option value="Log File">
              Log File
            </option>

            <option value="Network Capture">
              Network Capture
            </option>

            <option value="Other">
              Other
            </option>
          </select>

          {/* INFORMATION */}

          <div
            style={{
              padding: "12px 14px",
              marginTop: "5px",
              background: "#eff6ff",
              border: "1px solid #bfdbfe",
              borderRadius: "8px",
              color: "#1e40af",
            }}
          >
            <strong>Automatic Processing</strong>

            <p
              style={{
                margin: "6px 0 0",
                fontSize: "14px",
              }}
            >
              Evidence ID and SHA-256 integrity hash will be
              generated automatically by the forensic backend.
            </p>
          </div>

          {/* SUBMIT */}

          <button
            type="submit"
            disabled={uploading}
          >
            {uploading
              ? "Uploading Evidence..."
              : "+ Add Evidence"}
          </button>

        </form>
      </div>

      {/* =====================================================
          EVIDENCE RECORDS
      ===================================================== */}

      <div className="section">

        <h2>Evidence Records</h2>

        {/* LOADING */}

        {loading && (
          <p>
            Loading evidence records...
          </p>
        )}

        {/* EMPTY */}

        {!loading &&
          !error &&
          evidenceList.length === 0 && (
            <div className="empty-card">
              <p>
                No evidence records found.
              </p>
            </div>
          )}

        {/* RECORDS */}

        {!loading &&
          evidenceList.length > 0 && (
            <div>
              {evidenceList.map((item) => {

                /*
                 * Backend returns snake_case.
                 * We support both snake_case and camelCase
                 * so the page remains compatible.
                 */

                const evidenceId =
                  item.evidence_id ||
                  item.evidenceId;

                const caseId =
                  item.case_id ||
                  item.caseId;

                const filename =
                  item.filename ||
                  "Unknown";

                const evidenceType =
                  item.evidence_type ||
                  item.evidenceType ||
                  "Unknown";

                const sha256 =
                  item.sha256 ||
                  "Not Available";

                const status =
                  item.status ||
                  "Unknown";

                const fileSize =
                  item.file_size ||
                  item.size_bytes ||
                  0;

                return (
                  <div
                    className="investigation-card"
                    key={evidenceId}
                  >

                    <div className="evidence-details">

                      {/* TITLE */}

                      <div className="evidence-title-row">

                        <h3>
                          {evidenceId}
                        </h3>

                        <span className="badge">
                          {String(
                            status
                          ).toUpperCase()}
                        </span>

                      </div>

                      {/* CASE */}

                      <p>
                        <strong>
                          Case ID:
                        </strong>{" "}
                        {caseId}
                      </p>

                      {/* FILE */}

                      <p>
                        <strong>
                          Filename:
                        </strong>{" "}
                        {filename}
                      </p>

                      {/* TYPE */}

                      <p>
                        <strong>
                          Type:
                        </strong>{" "}
                        {evidenceType}
                      </p>

                      {/* SIZE */}

                      <p>
                        <strong>
                          File Size:
                        </strong>{" "}
                        {formatFileSize(
                          fileSize
                        )}
                      </p>

                      {/* HASH */}

                      <p className="hash-text">

                        <strong>
                          SHA-256:
                        </strong>{" "}

                        {sha256}

                      </p>

                      {/* ANALYSIS */}

                      {evidenceType ===
                        "Memory Image" && (
                        <button
                          type="button"
                          className="analysis-button"
                          onClick={() =>
                            openMemoryAnalysis(
                              evidenceId,
                              evidenceType
                            )
                          }
                        >
                          Open Memory Analysis →
                        </button>
                      )}

                    </div>
                  </div>
                );
              })}
            </div>
          )}

      </div>

    </div>
  );
}

export default Evidence;