import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, User, UserPlus } from "lucide-react";
import { API_BASE_URL, setAuthSession } from "../config";

function Login() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sessionNotice, setSessionNotice] = useState(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      return params.get("session_expired") === "1" ? "Your previous session expired or token was invalid. Please sign in again." : "";
    }
    return "";
  });

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(
        `${API_BASE_URL}/login`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: username.trim(),
            password: password,
          }),
        }
      );

      const data = await response.json();

      if (response.ok && data.access_token) {
        setAuthSession(data.access_token, data.user);
        navigate("/dashboard");
      } else {
        alert(data.detail || "Invalid username or password");
      }
    } catch (error) {
      console.error(error);
      alert("Cannot connect to backend");
    }
  };

  return (
    <>
      <style>
        {`
          * {
            box-sizing: border-box;
          }

          .login-page {
            width: 100%;
            min-height: 100vh;
            min-height: 100dvh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #17263c, #263d5b);
            padding: 30px;
            font-family: Arial, sans-serif;
            overflow-y: auto;
            overflow-x: hidden;
            -webkit-overflow-scrolling: touch;
          }

          .login-card {
            width: 680px;
            max-width: 95%;
            background: #ffffff;
            border-radius: 28px;
            padding: 55px 65px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.35);
            margin: auto;
            box-sizing: border-box;
          }

          .login-icon {
            width: 100px;
            height: 100px;
            margin: 0 auto 20px;
            border-radius: 50%;
            background: #3566c7;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
          }

          .login-icon svg {
            width: 55px;
            height: 55px;
          }

          .login-title {
            font-size: 45px;
            font-weight: 700;
            color: #24364d;
            margin: 0 0 12px;
            word-break: break-word;
          }

          .login-subtitle {
            font-size: 20px;
            color: #64748b;
            margin-bottom: 40px;
            line-height: 1.4;
          }

          .login-field {
            text-align: left;
            margin-bottom: 25px;
          }

          .login-field label {
            display: block;
            font-size: 20px;
            font-weight: 600;
            color: #334155;
            margin-bottom: 10px;
          }

          .login-input {
            width: 100%;
            height: 68px;
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 0 20px;
            border: 2px solid #cbd5e1;
            border-radius: 14px;
            background: #ffffff;
            box-sizing: border-box;
          }

          .login-input:focus-within {
            border-color: #3566c7;
            box-shadow: 0 0 0 3px rgba(53,102,199,0.15);
          }

          .login-input svg {
            flex-shrink: 0;
          }

          .login-input input {
            flex: 1;
            min-width: 0;
            height: 100%;
            border: none;
            outline: none;
            font-size: 20px;
            color: #334155;
            background: transparent;
          }

          .login-button {
            width: 100%;
            height: 68px;
            margin-top: 10px;
            border: none;
            border-radius: 14px;
            background: #3566c7;
            color: white;
            font-size: 22px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.2s ease;
          }

          .login-button:hover {
            background: #274fa0;
          }

          .register-area {
            margin-top: 28px;
            text-align: center;
          }

          .register-area p {
            font-size: 18px;
            color: #64748b;
            margin-bottom: 12px;
          }

          .register-button {
            border: none;
            background: transparent;
            color: #3566c7;
            font-size: 19px;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
          }

          .register-button svg {
            flex-shrink: 0;
          }

          .security-text {
            margin-top: 30px;
            font-size: 17px;
            color: #94a3b8;
          }

          /* Tablet & medium screens */
          @media (max-width: 768px) {
            .login-page {
              padding: 24px 16px;
            }

            .login-card {
              width: 100%;
              max-width: 540px;
              padding: 40px 32px;
              border-radius: 24px;
              margin: auto 0;
            }

            .login-icon {
              width: 80px;
              height: 80px;
              margin-bottom: 16px;
            }

            .login-icon svg {
              width: 44px;
              height: 44px;
            }

            .login-title {
              font-size: 34px;
            }

            .login-subtitle {
              font-size: 16px;
              margin-bottom: 28px;
            }

            .login-field {
              margin-bottom: 20px;
            }

            .login-field label {
              font-size: 17px;
              margin-bottom: 8px;
            }

            .login-input {
              height: 58px;
              padding: 0 16px;
              gap: 12px;
              border-radius: 12px;
            }

            .login-input input {
              font-size: 17px;
            }

            .login-button {
              height: 58px;
              font-size: 19px;
              border-radius: 12px;
            }

            .register-area {
              margin-top: 24px;
            }

            .register-area p {
              font-size: 16px;
              margin-bottom: 10px;
            }

            .register-button {
              font-size: 17px;
            }

            .security-text {
              margin-top: 24px;
              font-size: 15px;
            }
          }

          /* Mobile / Android screens (<= 480px, e.g. 430px, 390px, 360px) */
          @media (max-width: 480px) {
            .login-page {
              padding: 16px 12px;
              justify-content: flex-start;
            }

            .login-card {
              width: 100%;
              max-width: 100%;
              padding: 28px 18px 24px;
              border-radius: 20px;
              margin: auto 0;
              box-shadow: 0 10px 30px rgba(0,0,0,0.25);
            }

            .login-icon {
              width: 64px;
              height: 64px;
              margin: 0 auto 14px;
            }

            .login-icon svg {
              width: 34px;
              height: 34px;
            }

            .login-title {
              font-size: 26px;
              letter-spacing: -0.5px;
              margin: 0 0 8px;
            }

            .login-subtitle {
              font-size: 14px;
              margin-bottom: 22px;
              line-height: 1.4;
            }

            .login-field {
              margin-bottom: 16px;
            }

            .login-field label {
              font-size: 14px;
              margin-bottom: 6px;
            }

            .login-input {
              height: 50px;
              padding: 0 14px;
              gap: 10px;
              border-radius: 10px;
            }

            .login-input svg {
              width: 20px;
              height: 20px;
            }

            .login-input input {
              font-size: 16px;
            }

            .login-button {
              height: 50px;
              font-size: 16px;
              border-radius: 10px;
              margin-top: 6px;
            }

            .register-area {
              margin-top: 18px;
            }

            .register-area p {
              font-size: 14px;
              margin-bottom: 8px;
            }

            .register-button {
              font-size: 15px;
              gap: 6px;
            }

            .register-button svg {
              width: 18px;
              height: 18px;
            }

            .security-text {
              margin-top: 18px;
              font-size: 12px;
            }
          }

          /* Small mobile screens (<= 360px, e.g. 320px) */
          @media (max-width: 360px) {
            .login-page {
              padding: 12px 8px;
            }

            .login-card {
              padding: 20px 12px 18px;
              border-radius: 16px;
            }

            .login-icon {
              width: 52px;
              height: 52px;
              margin: 0 auto 10px;
            }

            .login-icon svg {
              width: 28px;
              height: 28px;
            }

            .login-title {
              font-size: 22px;
            }

            .login-subtitle {
              font-size: 12px;
              margin-bottom: 16px;
            }

            .login-field {
              margin-bottom: 12px;
            }

            .login-field label {
              font-size: 13px;
              margin-bottom: 4px;
            }

            .login-input {
              height: 44px;
              padding: 0 10px;
              gap: 8px;
              border-radius: 8px;
            }

            .login-input svg {
              width: 18px;
              height: 18px;
            }

            .login-input input {
              font-size: 15px;
            }

            .login-button {
              height: 44px;
              font-size: 15px;
              border-radius: 8px;
            }

            .register-area {
              margin-top: 14px;
            }

            .register-area p {
              font-size: 13px;
              margin-bottom: 6px;
            }

            .register-button {
              font-size: 14px;
            }

            .register-button svg {
              width: 16px;
              height: 16px;
            }

            .security-text {
              margin-top: 14px;
              font-size: 11px;
            }
          }
        `}
      </style>

      <div className="login-page">

        <div className="login-card">

          {/* LOGO */}
          <div className="login-icon">
            <Shield size={55} />
          </div>

          <h1 className="login-title">
            ForensiRansom AI
          </h1>

          <p className="login-subtitle">
            AI-Based Digital Forensic Investigation Platform
          </p>

          {sessionNotice && (
            <div style={{
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid rgba(239, 68, 68, 0.4)",
              color: "#f87171",
              padding: "10px 14px",
              borderRadius: "10px",
              marginBottom: "20px",
              fontSize: "14px",
              lineHeight: "1.4"
            }}>
              {sessionNotice}
            </div>
          )}


          {/* LOGIN FORM */}
          <form onSubmit={handleLogin}>

            <div className="login-field">
              <label>Username</label>

              <div className="login-input">
                <User size={25} color="#64748b" />

                <input
                  type="text"
                  placeholder="Enter username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
            </div>


            <div className="login-field">
              <label>Password</label>

              <div className="login-input">
                <Lock size={25} color="#64748b" />

                <input
                  type="password"
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>


            <button
              type="submit"
              className="login-button"
            >
              Login to Dashboard
            </button>

          </form>


          {/* REGISTER */}
          <div className="register-area">

            <p>Don't have an account?</p>

            <button
              className="register-button"
              onClick={() => navigate("/register")}
            >
              <UserPlus size={22} />
              Create Account
            </button>

          </div>


          <p className="security-text">
            Secure Digital Forensic Investigation System
          </p>

        </div>

      </div>
    </>
  );
}

export default Login;
