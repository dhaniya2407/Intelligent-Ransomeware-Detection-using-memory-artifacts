// API Configuration for ForensiRansom AI

export const RENDER_PRODUCTION_URL = "https://intelligent-ransomeware-detection-using-jmsr.onrender.com";
export const LOCAL_DEV_URL = "http://127.0.0.1:8000";

export const getSavedBackendUrl = () => {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("forensiransom_backend_url");
    if (saved && saved.trim() !== "") {
      return saved.trim().replace(/\/+$/, "");
    }
  }
  return null;
};

export const setSavedBackendUrl = (url) => {
  if (typeof window !== "undefined") {
    if (!url || url.trim() === "" || url === "default") {
      localStorage.removeItem("forensiransom_backend_url");
    } else {
      localStorage.setItem("forensiransom_backend_url", url.trim().replace(/\/+$/, ""));
    }
    window.location.reload();
  }
};

export const API_BASE_URL = (() => {
  const saved = getSavedBackendUrl();
  if (saved !== null) {
    return saved;
  }
  if (import.meta.env.VITE_API_BASE_URL !== undefined) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  if (typeof window !== "undefined") {
    if (window.location.port === "5173") {
      return LOCAL_DEV_URL;
    }
    if (window.location.hostname.includes("onrender.com")) {
      return "";
    }
    // Desktop (Electron / file / localhost) or external deployment -> target Render backend
    return RENDER_PRODUCTION_URL;
  }
  return RENDER_PRODUCTION_URL;
})();

export default API_BASE_URL;
