/* ═══════════════════════════════════════════════════
   app_admin.js  –  Admin Console Logic
   ═══════════════════════════════════════════════════ */

let adminJWT = sessionStorage.getItem("shield_admin_jwt") || "";
// Admin token lives in sessionStorage only (cleared when browser tab closes — more secure)

// ── Boot ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  if (adminJWT) {
    showDashboard();
    loadDashboard();
  }
});

// ── Screen switching ─────────────────────────────────
function showDashboard() {
  document.getElementById("loginScreen").style.display    = "none";
  document.getElementById("dashboardScreen").style.display = "block";
}
function showLoginScreen() {
  document.getElementById("loginScreen").style.display    = "block";
  document.getElementById("dashboardScreen").style.display = "none";
}

// ── Login ────────────────────────────────────────────
async function doLogin() {
  const u = document.getElementById("loginUser").value.trim();
  const p = document.getElementById("loginPass").value.trim();
  if (!u || !p) { showToast("Please enter username and password", "error"); return; }

  const btn  = document.getElementById("btnLogin");
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<div class="spinner"></div> Authenticating…`;

  try {
    const res = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: u, password: p })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast(`Login failed: ${err.detail || "Invalid credentials"}`, "error");
      return;
    }

    const { token } = await res.json();
    adminJWT = token;
    sessionStorage.setItem("shield_admin_jwt", adminJWT);

    showDashboard();
    await loadDashboard();
    showToast("Authenticated successfully!", "success");

  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

async function doLogout() {
  adminJWT = "";
  sessionStorage.removeItem("shield_admin_jwt");
  showLoginScreen();
  showToast("Logged out", "info");
}

// ── Load dashboard: stats + tokens + JWT render ──────
async function loadDashboard() {
  renderAdminJwt(adminJWT);
  await Promise.all([loadStats(), listTokens()]);

  // Set username label from JWT payload
  try {
    const parts  = adminJWT.split(".");
    const padded = parts[1].replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(parts[1].length/4)*4,"=");
    const payload = JSON.parse(atob(padded));
    const lbl = document.getElementById("adminUsernameLabel");
    if (lbl && payload.sub) lbl.textContent = payload.sub;
  } catch { /* ignore */ }
}

// ── Stats ────────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch("/admin/stats", {
      headers: { Authorization: `Bearer ${adminJWT}` }
    });
    if (!res.ok) { handleAuthError(res); return; }
    const d = await res.json();
    document.getElementById("statTotalTokens").textContent = d.total_user_tokens ?? "—";
    document.getElementById("statApiCalls").textContent    = d.total_api_calls ?? "—";
    document.getElementById("statGuestTokens").textContent  = d.guest_tokens ?? "—";
    document.getElementById("statNamedTokens").textContent  = d.named_user_tokens ?? "—";
  } catch { /* silently fail stats */ }
}

// ── Admin JWT visualiser ─────────────────────────────
function renderAdminJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return;
  const [h, p, s] = parts;

  document.getElementById("adminJwtHeader").textContent    = h;
  document.getElementById("adminJwtPayload").textContent   = p;
  document.getElementById("adminJwtSignature").textContent = s;

  // Decode payload
  try {
    const padded  = p.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(p.length/4)*4,"=");
    const decoded = JSON.parse(atob(padded));
    const grid    = document.getElementById("adminJwtDecodedGrid");
    grid.innerHTML = "";
    for (const [key, val] of Object.entries(decoded)) {
      const keyEl = document.createElement("span");
      keyEl.className = "jwt-key";
      keyEl.textContent = key + ":";

      const valEl = document.createElement("span");
      if (key === "exp" || key === "iat") {
        valEl.className = "jwt-val";
        valEl.textContent = new Date(val * 1000).toLocaleString() + "  ← expiry";
      } else if (typeof val === "boolean") {
        valEl.className = "jwt-val-bool";
        valEl.textContent = String(val);
      } else {
        valEl.className = "jwt-val-str";
        valEl.textContent = `"${val}"`;
      }
      grid.appendChild(keyEl);
      grid.appendChild(valEl);
    }
  } catch { /* skip */ }
}

function copyAdminJwt() {
  navigator.clipboard.writeText(adminJWT);
  showToast("Admin JWT copied to clipboard", "success");
}

// ── Token creation ───────────────────────────────────
async function createToken(isAdmin) {
  try {
    const res = await fetch(`/auth/tokens?is_admin=${isAdmin}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminJWT}` }
    });
    if (!res.ok) { handleAuthError(res); return; }

    const { token } = await res.json();
    const box   = document.getElementById("newTokenBox");
    const input = document.getElementById("newTokenValue");
    input.value = token;
    box.style.display = "block";

    showToast(`New ${isAdmin ? "Admin" : "User"} token created!`, "success");
    await listTokens();
    await loadStats();
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

function copyNewToken() {
  const v = document.getElementById("newTokenValue").value;
  if (!v) return;
  navigator.clipboard.writeText(v);
  showToast("Token copied to clipboard!", "success");
}

// ── Token list ───────────────────────────────────────
async function listTokens() {
  const tbody = document.getElementById("tokenTableBody");
  tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:1.5rem;">
    <div class="spinner" style="margin:0 auto;"></div></td></tr>`;

  try {
    const res = await fetch("/auth/tokens", {
      headers: { Authorization: `Bearer ${adminJWT}` }
    });
    if (!res.ok) { handleAuthError(res); return; }

    const tokens = await res.json();
    // tokens already filtered to non-admin (user + guest) on the backend
    const label = document.getElementById("tokenCountLabel");
    label.textContent = `${tokens.length} active session${tokens.length === 1 ? "" : "s"}`;

    if (!tokens.length) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:2rem;">
        No user or guest sessions active.</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    tokens.forEach(rec => {
      const shortTok  = rec.token.substring(0, 20) + "…";
      const created   = rec.createdAt ? new Date(rec.createdAt).toLocaleString() : "N/A";
      const role      = rec.role || "user";
      const badgeCls  = role === "guest" ? "role-user" : "role-admin";
      const badgeTxt  = role === "guest" ? "GUEST" : "USER";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:#fff;">
          ${shortTok}
          <button style="background:none;border:none;color:var(--primary);cursor:pointer;padding:0 0.3rem;" 
            title="Copy full token" onclick="copyFull('${rec.token}')">
            <i class="fa-regular fa-copy"></i>
          </button>
        </td>
        <td><span class="role-badge ${badgeCls}">${badgeTxt}</span></td>
        <td style="color:var(--text-muted);font-size:0.82rem;">${created}</td>
        <td style="text-align:right;">
          <button class="btn btn-danger" onclick="deleteToken('${rec.token}')">
            <i class="fa-solid fa-trash"></i> Revoke
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--danger);padding:1.5rem;">
      ${err.message}</td></tr>`;
  }
}

// ── Purge & Delete ───────────────────────────────────
async function purgeTokens() {
  if (!confirm("Delete ALL user and guest sessions from the database?")) return;
  try {
    const res = await fetch("/auth/tokens/purge", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${adminJWT}` }
    });
    if (!res.ok) { handleAuthError(res); return; }
    const d = await res.json();
    showToast(d.message || "Tokens cleared!", "success");
    await listTokens();
    await loadStats();
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function deleteToken(tokenStr) {
  if (!confirm("Revoke and delete this token?")) return;
  try {
    const res = await fetch(`/auth/tokens/${encodeURIComponent(tokenStr)}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${adminJWT}` }
    });
    if (!res.ok) { handleAuthError(res); return; }
    showToast("Token revoked!", "success");
    await listTokens();
    await loadStats();
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

function copyFull(str) {
  navigator.clipboard.writeText(str);
  showToast("Full token copied!", "success");
}

// ── Error handler ────────────────────────────────────
function handleAuthError(res) {
  if (res.status === 401 || res.status === 403) {
    showToast("Session expired. Please log in again.", "error");
    doLogout();
  } else {
    showToast(`Server error (${res.status})`, "error");
  }
}

// ── Toast ────────────────────────────────────────────
function showToast(message, type = "info") {
  const icons = {
    info:    `<i class="fa-solid fa-circle-info"  style="color:var(--primary);"></i>`,
    success: `<i class="fa-solid fa-circle-check" style="color:var(--success);"></i>`,
    error:   `<i class="fa-solid fa-circle-xmark" style="color:var(--danger);"></i>`,
    warning: `<i class="fa-solid fa-triangle-exclamation" style="color:var(--warning);"></i>`,
  };
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `${icons[type] || icons.info} <span>${message}</span>`;
  document.getElementById("toastContainer").appendChild(toast);
  setTimeout(() => {
    toast.style.cssText += "opacity:0;transform:translateY(10px);transition:all 0.3s ease;";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
