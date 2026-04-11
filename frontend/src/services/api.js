/**
 * netguard/frontend/src/services/api.js
 * ────────────────────────────────────────
 * Centralized API client for all backend calls.
 * Handles auth tokens, error formatting, and WebSocket setup.
 */

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_URL   = import.meta.env.VITE_WS_URL  || "ws://localhost:8000";

// ── Token management ──────────────────────────────────────────────────────────
export const token = {
  get: ()        => localStorage.getItem("ng_token"),
  set: (t)       => localStorage.setItem("ng_token", t),
  clear: ()      => localStorage.removeItem("ng_token"),
  isLoggedIn: () => !!localStorage.getItem("ng_token"),
};

// ── Base fetch wrapper ────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(token.get() ? { Authorization: `Bearer ${token.get()}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 204) return null;   // No content

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = data.detail || `API error ${response.status}`;
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }

  return data;
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════════════════

export const auth = {
  async register(username, email, password) {
    const data = await apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    });
    token.set(data.access_token);
    return data;
  },

  async login(username, password) {
    // Login uses form encoding (OAuth2 standard)
    const form = new URLSearchParams({ username, password });
    const response = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Login failed");
    token.set(data.access_token);
    return data;
  },

  logout() {
    token.clear();
  },
};

// ══════════════════════════════════════════════════════════════════════════════
// NETWORK SCANNING
// ══════════════════════════════════════════════════════════════════════════════

export const scan = {
  /** Trigger a scan from the server side (same LAN as backend). */
  async start(networkRange = "192.168.1.0/24", scanType = "full") {
    return apiFetch("/api/scan/start", {
      method: "POST",
      body: JSON.stringify({ network_range: networkRange, scan_type: scanType }),
    });
  },

  /** Get the N most recent scans. */
  async history(limit = 10) {
    return apiFetch(`/api/scan/results?limit=${limit}`);
  },

  /** Get full details of one scan including devices + findings. */
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
  /**
   * Check if a password has been pwned.
   * All SHA-1 hashing and comparison happens here in the browser.
   * Only the first 5 chars of the hash ever leave this function.
   */
  async check(plainPassword) {
    // Step 1: SHA-1 hash in the browser
    const encoder = new TextEncoder();
    const data = encoder.encode(plainPassword);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    // Step 2: Send only the prefix to backend (which forwards to HIBP)
    const result = await apiFetch("/api/password/check", {
      method: "POST",
      body: JSON.stringify({ hash_prefix: prefix }),
    });

    // Step 3: Check locally if our suffix is in the response
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
  /**
   * Send conversation to AI advisor.
   * messages: [{role: "user"|"assistant", content: "..."}]
   * scanContext: optional object from latest scan
   */
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

export function createAlertSocket(userId, onMessage, onConnect, onDisconnect) {
  const jwt = token.get();
  if (!jwt) throw new Error("No auth token — log in first");

  const ws = new WebSocket(`${WS_URL}/ws/${userId}?token=${jwt}`);

  ws.onopen    = () => { console.log("NetGuard WS connected"); onConnect?.(); };
  ws.onmessage = (e) => { onMessage?.(JSON.parse(e.data)); };
  ws.onclose   = () => { onDisconnect?.(); };
  ws.onerror   = (e) => { console.error("NetGuard WS error:", e); };

  // Keep-alive ping every 30s
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
