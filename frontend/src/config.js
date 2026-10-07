// API Configuration for ForensiRansom AI
// 1. If running locally with Vite dev server (port 5173), target the local backend (http://127.0.0.1:8000)
// 2. If running on Render (where frontend and backend are unified), use relative path ""
// 3. If running anywhere else (e.g. Vercel deployment), target the live Render backend URL

export const API_BASE_URL = (() => {
  if (import.meta.env.VITE_API_BASE_URL !== undefined) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  if (typeof window !== "undefined") {
    if (window.location.port === "5173") {
      return "http://127.0.0.1:8000";
    }
    if (window.location.hostname.includes("onrender.com")) {
      return "";
    }
    // External deployment (e.g. Vercel) -> send API calls to Render backend
    return "https://intelligent-ransomeware-detection-using-jmsr.onrender.com";
  }
  return "";
})();

export default API_BASE_URL;
