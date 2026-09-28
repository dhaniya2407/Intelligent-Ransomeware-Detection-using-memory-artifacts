import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  User,
  Mail,
  Lock,
  Users,
  ArrowLeft
} from "lucide-react";

import "./Register.css";

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Investigator");
  const [message, setMessage] = useState("");

  const handleRegister = async (e) => {
    e.preventDefault();

    setMessage("");

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/register",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            email,
            password,
            role,
          }),
        }
      );

      const data = await response.json();

      if (response.ok) {
        alert("Account created successfully!");
        navigate("/");
      } else {
        setMessage(data.detail || "Registration failed");
      }

    } catch (error) {
      console.error(error);
      setMessage("Cannot connect to backend");
    }
  };

  return (
    <div className="register-page-container">

      <div className="register-main-card">

        <button
          className="register-back-button"
          onClick={() => navigate("/")}
        >
          <ArrowLeft size={20} />
          Back to Login
        </button>

        <div className="register-logo-section">

          <div className="register-shield-circle">
            <Shield size={45} />
          </div>

          <h1>Create Account</h1>

          <p>
            Join the ForensiRansom AI Investigation Platform
          </p>

        </div>


        <form onSubmit={handleRegister}>

          <div className="register-two-column">

            <div className="register-field">

              <label>Username</label>

              <div className="register-input-box">
                <User size={20} />

                <input
                  type="text"
                  placeholder="Enter username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>

            </div>


            <div className="register-field">

              <label>Email Address</label>

              <div className="register-input-box">
                <Mail size={20} />

                <input
                  type="email"
                  placeholder="Enter email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

            </div>

          </div>


          <div className="register-field">

            <label>Password</label>

            <div className="register-input-box">
              <Lock size={20} />

              <input
                type="password"
                placeholder="Create password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

          </div>


          <div className="register-field">

            <label>Role</label>

            <div className="register-input-box">

              <Users size={20} />

              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="Investigator">
                  Investigator
                </option>

                <option value="Analyst">
                  Analyst
                </option>

                <option value="Admin">
                  Admin
                </option>

              </select>

            </div>

          </div>


          <button
            type="submit"
            className="register-submit-button"
          >
            Create Account
          </button>

        </form>


        {message && (
          <p className="register-error-message">
            {message}
          </p>
        )}


        <p className="register-login-text">
          Already have an account?

          <span onClick={() => navigate("/")}>
            Login here
          </span>
        </p>

      </div>

    </div>
  );
}

export default Register;