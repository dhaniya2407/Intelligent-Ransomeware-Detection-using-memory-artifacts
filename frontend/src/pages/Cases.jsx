import { useEffect, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

function Cases() {

  // ============================================================
  // CASE LIST
  // ============================================================

  const [cases, setCases] = useState([]);

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState("");

  const [success, setSuccess] = useState("");


  // ============================================================
  // FORM DATA
  // ============================================================

  const [formData, setFormData] = useState({

    caseName: "",

    description: "",

    investigator: "",

    status: "Open"

  });


  // ============================================================
  // GET ALL CASES
  // ============================================================

  const fetchCases = async () => {

    try {

      setLoading(true);

      setError("");

      const response = await fetch(
        `${API_BASE_URL}/cases`
      );

      if (!response.ok) {

        throw new Error(
          "Failed to load cases"
        );

      }

      const data = await response.json();

      setCases(
        Array.isArray(data)
          ? data
          : []
      );

    } catch (error) {

      console.error(
        "Cases loading error:",
        error
      );

      setError(
        "Unable to load investigation cases."
      );

    } finally {

      setLoading(false);

    }
  };


  // ============================================================
  // LOAD CASES
  // ============================================================

  useEffect(() => {

    fetchCases();

  }, []);


  // ============================================================
  // HANDLE FORM CHANGE
  // ============================================================

  const handleChange = (e) => {

    const {
      name,
      value
    } = e.target;

    setFormData(
      previous => ({
        ...previous,
        [name]: value
      })
    );
  };


  // ============================================================
  // CREATE CASE
  // ============================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    setError("");

    setSuccess("");


    // ----------------------------------------------------------
    // VALIDATION
    // ----------------------------------------------------------

    if (!formData.caseName.trim()) {

      setError(
        "Please enter a Case Name."
      );

      return;
    }

    if (!formData.investigator.trim()) {

      setError(
        "Please enter the Investigator Name."
      );

      return;
    }


    // ----------------------------------------------------------
    // CREATE CASE
    // ----------------------------------------------------------

    try {

      const response = await fetch(
        `${API_BASE_URL}/cases`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({

            case_name:
              formData.caseName.trim(),

            investigator:
              formData.investigator.trim(),

            description:
              formData.description.trim(),

            status:
              formData.status

          })
        }
      );


      // --------------------------------------------------------
      // HANDLE BACKEND ERROR
      // --------------------------------------------------------

      if (!response.ok) {

        let errorMessage =
          "Failed to create case.";

        try {

          const errorData =
            await response.json();

          if (errorData.detail) {

            errorMessage =
              errorData.detail;
          }

        } catch {

          // Keep default error message

        }

        throw new Error(
          errorMessage
        );
      }


      // --------------------------------------------------------
      // READ CREATED CASE
      // --------------------------------------------------------

      const result =
        await response.json();

      const createdCase =
        result.case;


      // --------------------------------------------------------
      // SUCCESS MESSAGE
      // --------------------------------------------------------

      setSuccess(
        `Case ${createdCase.case_id} created successfully.`
      );


      // --------------------------------------------------------
      // CLEAR FORM
      // --------------------------------------------------------

      setFormData({

        caseName: "",

        description: "",

        investigator: "",

        status: "Open"

      });


      // --------------------------------------------------------
      // REFRESH CASE LIST
      // --------------------------------------------------------

      await fetchCases();


    } catch (error) {

      console.error(
        "Case creation error:",
        error
      );

      setError(
        error.message ||
        "Unable to create case."
      );

    }

  };


  // ============================================================
  // PAGE
  // ============================================================

  return (

    <div>

      {/* ======================================================
          HEADER
      ====================================================== */}

      <div className="page-header">

        <div>

          <h1>
            Case Management
          </h1>

          <p>
            Create and manage digital forensic
            investigation cases.
          </p>

        </div>

      </div>


      {/* ======================================================
          SUCCESS MESSAGE
      ====================================================== */}

      {success && (

        <div
          style={{
            padding: "12px 16px",
            marginBottom: "20px",
            borderRadius: "8px",
            background: "#ecfdf5",
            color: "#047857",
            border:
              "1px solid #a7f3d0"
          }}
        >

          ✓ {success}

        </div>

      )}


      {/* ======================================================
          ERROR MESSAGE
      ====================================================== */}

      {error && (

        <div
          style={{
            padding: "12px 16px",
            marginBottom: "20px",
            borderRadius: "8px",
            background: "#fef2f2",
            color: "#b91c1c",
            border:
              "1px solid #fecaca"
          }}
        >

          {error}

        </div>

      )}


      {/* ======================================================
          CREATE CASE
      ====================================================== */}

      <div className="empty-card">

        <h2>
          Create New Case
        </h2>


        <p
          style={{
            color: "#64748b",
            marginBottom: "20px"
          }}
        >
          Case ID will be generated automatically
          by the forensic system.
        </p>


        <form
          onSubmit={handleSubmit}
          className="case-form"
        >

          {/* CASE NAME */}

          <input
            type="text"
            name="caseName"
            placeholder="Case Name"
            value={formData.caseName}
            onChange={handleChange}
          />


          {/* DESCRIPTION */}

          <textarea
            name="description"
            placeholder="Case Description"
            value={formData.description}
            onChange={handleChange}
          />


          {/* INVESTIGATOR */}

          <input
            type="text"
            name="investigator"
            placeholder="Investigator Name"
            value={formData.investigator}
            onChange={handleChange}
          />


          {/* STATUS */}

          <select
            name="status"
            value={formData.status}
            onChange={handleChange}
          >

            <option value="Open">
              OPEN
            </option>

            <option value="In Progress">
              IN PROGRESS
            </option>

            <option value="Closed">
              CLOSED
            </option>

          </select>


          {/* CREATE BUTTON */}

          <button type="submit">

            + Create Case

          </button>

        </form>

      </div>


      {/* ======================================================
          CASE LIST
      ====================================================== */}

      <div className="section">

        <h2>
          Investigation Cases
        </h2>


        {/* LOADING */}

        {loading && (

          <p>
            Loading investigation cases...
          </p>

        )}


        {/* NO CASES */}

        {!loading &&
          !error &&
          cases.length === 0 && (

            <p>
              No investigation cases found.
            </p>

        )}


        {/* CASE LIST */}

        {!loading &&
          cases.length > 0 && (

            <div>

              {cases.map((item) => (

                <div
                  className="investigation-card"
                  key={item.case_id}
                >

                  <div>

                    <h3>
                      {item.case_id}
                    </h3>

                    <p>

                      <strong>
                        {item.case_name}
                      </strong>

                    </p>

                    {item.description && (

                      <p>
                        {item.description}
                      </p>

                    )}

                    <p>

                      Investigator:{" "}

                      {item.investigator}

                    </p>

                  </div>


                  <span className="badge">

                    {item.status
                      ?.toUpperCase()}

                  </span>

                </div>

              ))}

            </div>

        )}

      </div>

    </div>

  );
}

export default Cases;