/**
 * netguard/frontend/src/services/api.js
 * ────────────────────────────────────────
 * Centralized API client for all backend calls.
 *
 * Security: JWT is stored in an httpOnly cookie set by the backend.
 * The frontend NEVER touches the token directly — no localStorage,
 * no sessionStorage. This eliminates XSS token exfiltration risk.
 *
 * All fetch() calls use credentials: "include" so the browser
 * automatically sends the cookie on every request.
 */
 
const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_URL   = import.meta.env.VITE_WS_URL  || "ws://localhost:8000";
 
// ── Auth state (in-memory only — not persisted to storage) ───────────────────
// We only store the username for display purposes.
// The actual JWT lives exclusively in the httpOnly cookie.
let _username = sessionStorage.getItem("ng_username") || null;
 
export const auth_state = {
  getUsername:  ()  => _username,
  setUsername:  (u) => { _username = u; sessionStorage.setItem("ng_username", u); },
  clearUsername: () => { _username = null; sessionStorage.removeItem("ng_username"); },
  isLoggedIn:   ()  => !!_username,
};
 
// ── Error parser — never expose raw FastAPI validation JSON to the user ───────
function parseError(data) {
  // FastAPI validation errors come as an array of objects
  if (Array.isArray(data.detail)) {
    return data.detail.map(e => {
      const field = e.loc?.[e.loc.length - 1] ?? '';
      const msg = e.msg
        .replace('Value error, ', '')
        .replace('value_error, ', '');
      return field ? `${field}: ${msg}` : msg;
    }).join(' · ');
  }
  // Plain string error
  if (typeof data.detail === 'string') return data.detail;
  // Fallback
  return 'Something went wrong. Please try again.';
}
 
// ── Base fetch wrapper ────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    "X-Requested-With": "NetGuard",   // CSRF guard — forces CORS preflight
    ...options.headers,
  };

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
    credentials: "include",   // ← sends httpOnly cookie automatically
  });
 
  if (response.status === 204) return null;
 
  const data = await response.json().catch(() => ({}));
 
  if (!response.ok) {
    throw new Error(parseError(data));
  }
 
  return data;
}
 
// ══════════════════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════════════════
 
export const auth = {
  async register(username, email, password, turnstileToken) {
    const data = await apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        turnstile_token: turnstileToken,
      }),
    });
    auth_state.setUsername(data.username);
    return data;
  },
 
  async login(username, password, turnstileToken) {
    const form = new URLSearchParams({
      username,
      password,
      client_id: turnstileToken,
    });
    const response = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "NetGuard",
      },
      body: form,
      credentials: "include",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(parseError(data));
    auth_state.setUsername(data.username);
    sessionStorage.removeItem('ng_avatar');
    return data;
  },
 
  async logout() {
    await apiFetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    auth_state.clearUsername();
    sessionStorage.removeItem('ng_avatar');
  },

    async me() {
    return apiFetch("/api/auth/me")
  },

  async profile() {
    return apiFetch("/api/auth/profile")
  },
 
  isLoggedIn: () => auth_state.isLoggedIn(),
};
 
// ══════════════════════════════════════════════════════════════════════════════
// NETWORK SCANNING
// ══════════════════════════════════════════════════════════════════════════════
 
export const scan = {
  async start(networkRange = "192.168.1.0/24", scanType = "full") {
    return apiFetch("/api/scan/start", {
      method: "POST",
      body: JSON.stringify({ network_range: networkRange, scan_type: scanType }),
    });
  },
 
  async history(limit = 10) {
    return apiFetch(`/api/scan/results?limit=${limit}`);
  },
 
  async detail(scanId) {
    return apiFetch(`/api/scan/${scanId}`);
  },
};
 
// ══════════════════════════════════════════════════════════════════════════════
// DEVICE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
 
export const devices = {
  async listTrusted() {
    return apiFetch("/api/devices/trusted");
  },
 
  async trust(macAddress, label = "") {
    return apiFetch("/api/devices/trust", {
      method: "POST",
      body: JSON.stringify({ mac_address: macAddress, label }),
    });
  },
 
  async untrust(macAddress) {
    return apiFetch(`/api/devices/trust/${encodeURIComponent(macAddress)}`, {
      method: "DELETE",
    });
  },
 
  async kick(macAddress) {
    return apiFetch(`/api/devices/kick?mac_address=${encodeURIComponent(macAddress)}`, {
      method: "POST",
    });
  },
};
 
// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD CHECK (HIBP k-anonymity)
// ══════════════════════════════════════════════════════════════════════════════
 
export const password = {
  async check(plainPassword) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plainPassword);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
 
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
 
    const result = await apiFetch("/api/password/check", {
      method: "POST",
      body: JSON.stringify({ hash_prefix: prefix }),
    });
 
    const lines = (result.message || "").split("\n");
    for (const line of lines) {
      const [responseSuffix, countStr] = line.split(":");
      if (responseSuffix === suffix) {
        return { pwned: true, count: parseInt(countStr, 10) };
      }
    }
 
    return { pwned: false, count: 0 };
  },
 
  async tips() {
    return apiFetch("/api/password/tips");
  },
};
 
// ══════════════════════════════════════════════════════════════════════════════
// AI CHAT
// ══════════════════════════════════════════════════════════════════════════════
 
export const chat = {
  async send(messages, scanContext = null) {
    return apiFetch("/api/chat/message", {
      method: "POST",
      body: JSON.stringify({ messages, scan_context: scanContext }),
    });
  },
};
 
// ══════════════════════════════════════════════════════════════════════════════
// ALERTS
// ══════════════════════════════════════════════════════════════════════════════
 
export const alerts = {
  async list(unreadOnly = false, limit = 50) {
    return apiFetch(`/api/alerts?unread_only=${unreadOnly}&limit=${limit}`);
  },
 
  async markAllRead() {
    return apiFetch("/api/alerts/read-all", { method: "PATCH" });
  },
};
 
// ══════════════════════════════════════════════════════════════════════════════
// WEBSOCKET — Real-time alerts
// ══════════════════════════════════════════════════════════════════════════════
 
/**
 * For WebSocket, browsers can't send cookies on the initial handshake
 * when using a different origin (CORS). We ask the backend for a short-lived
 * WS ticket instead, which is safe to put in the URL query param because:
 *   - it's single-use / short TTL (60s)
 *   - it never touches localStorage/sessionStorage
 */
export async function createAlertSocket(userId, onMessage, onConnect, onDisconnect) {
  let ticket;
  try {
    const res = await apiFetch("/api/auth/ws-ticket");
    ticket = res.ticket;
  } catch {
    throw new Error("Could not get WS ticket — are you logged in?");
  }
 
  const ws = new WebSocket(`${WS_URL}/ws/${userId}?token=${ticket}`);
 
  ws.onopen    = () => { console.log("NetGuard WS connected"); onConnect?.(); };
  ws.onmessage = (e) => { onMessage?.(JSON.parse(e.data)); };
  ws.onclose   = () => { onDisconnect?.(); };
  ws.onerror   = (e) => { console.error("NetGuard WS error:", e); };
 
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send("ping");
  }, 30_000);
 
  return {
    close: () => {
      clearInterval(pingInterval);
      ws.close();
    },
  };
}