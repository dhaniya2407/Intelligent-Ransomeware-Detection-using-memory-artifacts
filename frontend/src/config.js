// API Configuration for ForensiRansom AI
// When running locally with Vite dev server (port 5173), target the local backend (http://127.0.0.1:8000)
// In production on Render (unified deployment), use relative path "" (same origin)

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL !== undefined
    ? import.meta.env.VITE_API_BASE_URL
    : typeof window !== "undefined" && window.location.port === "5173"
    ? "http://127.0.0.1:8000"
    : "";

export default API_BASE_URL;
