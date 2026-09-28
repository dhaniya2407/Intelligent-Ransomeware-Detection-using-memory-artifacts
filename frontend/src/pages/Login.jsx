import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, User, UserPlus } from "lucide-react";

function Login() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/login",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username: username,
            password: password,
          }),
        }
      );

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem("user", JSON.stringify(data));
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
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #17263c, #263d5b);
            padding: 30px;
            font-family: Arial, sans-serif;
          }

          .login-card {
            width: 680px;
            max-width: 95%;
            background: #ffffff;
            border-radius: 28px;
            padding: 55px 65px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.35);
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

          .login-title {
            font-size: 45px;
            font-weight: 700;
            color: #24364d;
            margin: 0 0 12px;
          }

          .login-subtitle {
            font-size: 20px;
            color: #64748b;
            margin-bottom: 40px;
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
          }

          .login-input:focus-within {
            border-color: #3566c7;
            box-shadow: 0 0 0 3px rgba(53,102,199,0.15);
          }

          .login-input input {
            flex: 1;
            height: 100%;
            border: none;
            outline: none;
            font-size: 20px;
            color: #334155;
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

          .security-text {
            margin-top: 30px;
            font-size: 17px;
            color: #94a3b8;
          }

          @media (max-width: 700px) {
            .login-card {
              width: 95%;
              padding: 40px 30px;
            }

            .login-title {
              font-size: 35px;
            }

            .login-subtitle {
              font-size: 17px;
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