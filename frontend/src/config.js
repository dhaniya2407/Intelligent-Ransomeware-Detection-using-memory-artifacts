// API Configuration & Authenticated Request Handler for ForensiRansom AI

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
  if (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_API_BASE_URL !== undefined) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  if (typeof window !== "undefined") {
    // 1. When accessed via local FastAPI server directly (port 8000)
    if (window.location.port === "8000") {
      return "";
    }
    // 2. Vite dev server running on port 5173 targets local backend
    if (window.location.port === "5173") {
      return LOCAL_DEV_URL;
    }
    // 3. Render production cloud host uses same origin
    if (window.location.hostname.includes("onrender.com")) {
      return "";
    }
    // 4. Desktop (Electron / file / localhost) or external deployment -> target Render backend
    return RENDER_PRODUCTION_URL;
  }
  return RENDER_PRODUCTION_URL;
})();

// ============================================================
// AUTHENTICATION SESSION MANAGEMENT
// ============================================================

export const getAuthToken = () => {
  if (typeof window !== "undefined") {
    for (const key of ["forensiransom_token", "token"]) {
      const val = localStorage.getItem(key);
      if (val && val !== "undefined" && val !== "null" && typeof val === "string" && val.trim() !== "") {
        return val.trim();
      }
    }
  }
  return null;
};

export const getCurrentUser = () => {
  if (typeof window !== "undefined") {
    for (const key of ["forensiransom_user", "user"]) {
      const stored = localStorage.getItem(key);
      if (stored && stored !== "undefined" && stored !== "null" && typeof stored === "string") {
        try {
          const parsed = JSON.parse(stored);
          if (parsed && typeof parsed === "object" && parsed.username) {
            return parsed;
          }
        } catch {
          // ignore corrupted JSON
        }
      }
    }
  }
  return null;
};

export const setAuthSession = (token, user) => {
  if (typeof window !== "undefined") {
    if (token && token !== "undefined" && token !== "null" && String(token).trim() !== "") {
      const cleanToken = String(token).trim();
      localStorage.setItem("forensiransom_token", cleanToken);
      localStorage.setItem("token", cleanToken);
    } else {
      localStorage.removeItem("forensiransom_token");
      localStorage.removeItem("token");
    }
    if (user && typeof user === "object") {
      const userStr = JSON.stringify(user);
      localStorage.setItem("forensiransom_user", userStr);
      localStorage.setItem("user", userStr);
    }
  }
};

export const clearAuthSession = () => {
  if (typeof window !== "undefined") {
    localStorage.removeItem("forensiransom_token");
    localStorage.removeItem("forensiransom_user");
    // Also clear legacy keys
    localStorage.removeItem("token");
    localStorage.removeItem("user");
  }
};

// ============================================================
// AUTHENTICATED FETCH WRAPPER
// Automatically attaches Bearer token to all protected API calls
// and cleanly handles session expiration (401).
// ============================================================

export const authFetch = async (url, options = {}) => {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  // Ensure JSON requests set Accept header unless already set
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  // If token is expired or unauthorized, clear session and redirect to login
  if (response.status === 401) {
    clearAuthSession();
    if (typeof window !== "undefined") {
      const path = window.location.pathname;
      if (path !== "/" && path !== "/register") {
        window.location.replace("/?session_expired=1");
      }
    }
  }

  return response;
};

export default API_BASE_URL;
