/* ═══════════════════════════════════════════════════
   app_user.js  –  User Portal Logic
   ═══════════════════════════════════════════════════ */

let userToken = localStorage.getItem("shield_user_token") || "";

// ── Boot ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  if (!userToken) {
    await initGuestToken();
  } else {
    renderJwtVisualiser(userToken, "jwtHeader", "jwtPayload", "jwtSignature", "jwtDecodedGrid");
    setSessionBadge("Session Active");
  }

  // Drag & drop wiring
  const dz = document.getElementById("dropzone");
  ["dragenter","dragover","dragleave","drop"].forEach(e => dz.addEventListener(e, stopProp, false));
  ["dragenter","dragover"].forEach(e => dz.addEventListener(e, () => dz.classList.add("dragover")));
  ["dragleave","drop"].forEach(e => dz.addEventListener(e, () => dz.classList.remove("dragover")));
  dz.addEventListener("drop", e => {
    const files = e.dataTransfer.files;
    if (files.length) { document.getElementById("imgFile").files = files; handleFileSelect({ target: { files } }); }
  });
});

function stopProp(e) { e.preventDefault(); e.stopPropagation(); }

// ── JWT token helpers ─────────────────────────────────
async function initGuestToken() {
  setSessionBadge("Connecting...");
  try {
    const res = await fetch("/auth/tokens/guest", { method: "POST" });
    if (res.ok) {
      const { token } = await res.json();
      userToken = token;
      localStorage.setItem("shield_user_token", userToken);
      renderJwtVisualiser(userToken, "jwtHeader", "jwtPayload", "jwtSignature", "jwtDecodedGrid");
      setSessionBadge("Session Active");
    }
  } catch { setSessionBadge("Offline"); }
}

function setSessionBadge(text) {
  const el = document.getElementById("sessionStatus");
  if (el) el.textContent = text;
}

// ── JWT Visualiser (shared utility) ──────────────────
function renderJwtVisualiser(token, headerId, payloadId, sigId, gridId) {
  const parts = token.split(".");
  if (parts.length !== 3) return;

  const [h, p, s] = parts;
  document.getElementById(headerId).textContent  = h;
  document.getElementById(payloadId).textContent = p;
  document.getElementById(sigId).textContent     = s;

  // Decode payload (base64url → JSON)
  try {
    const padded  = p.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(p.length/4)*4,"=");
    const decoded = JSON.parse(atob(padded));
    const grid    = document.getElementById(gridId);
    grid.innerHTML = "";
    for (const [key, val] of Object.entries(decoded)) {
      const keyEl = document.createElement("span");
      keyEl.className = "jwt-key";
      keyEl.textContent = key + ":";

      const valEl = document.createElement("span");
      if (key === "exp" || key === "iat") {
        valEl.className = "jwt-val";
        valEl.textContent = new Date(val * 1000).toLocaleString() + " (timestamp)";
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
  } catch { /* skip if decode fails */ }
}

// ── File handling ────────────────────────────────────
function handleFileSelect(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ev => {
    document.getElementById("previewImage").src    = ev.target.result;
    document.getElementById("previewName").textContent = file.name;
    document.getElementById("previewSize").textContent = (file.size / 1024).toFixed(1) + " KB";
    document.getElementById("previewContainer").style.display = "flex";
    document.getElementById("resultCard").style.display = "none";
  };
  reader.readAsDataURL(file);
}

function clearPreview(e) {
  if (e) e.stopPropagation();
  document.getElementById("imgFile").value = "";
  document.getElementById("previewContainer").style.display = "none";
  document.getElementById("resultCard").style.display = "none";
}

// ── Core: Moderate ───────────────────────────────────
async function moderate() {
  if (!userToken) await initGuestToken();

  const input = document.getElementById("imgFile");
  if (!input.files || !input.files.length) {
    showToast("Please select or drop an image first", "error"); return;
  }

  const btn = document.getElementById("btnModerate");
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<div class="spinner"></div> Analyzing…`;

  const form = new FormData();
  form.append("file", input.files[0]);

  try {
    const res = await fetch("/moderate", {
      method: "POST",
      headers: { Authorization: `Bearer ${userToken}` },
      body: form
    });

    if (res.status === 401) {
      showToast("Session expired — renewing…", "warning");
      localStorage.removeItem("shield_user_token");
      userToken = "";
      await initGuestToken();
      btn.disabled = false; btn.innerHTML = orig;
      return moderate();
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast(`Error: ${err.detail || "Request failed"}`, "error");
      return;
    }

    const data = await res.json();
    renderResult(data, input.files[0].name);

  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

function renderResult(data, filename) {
  const card     = document.getElementById("resultCard");
  const icon     = document.getElementById("resultIcon");
  const title    = document.getElementById("resultTitle");
  const subtitle = document.getElementById("resultFilename");
  const flagCont = document.getElementById("flaggedContainer");
  const flagList = document.getElementById("flaggedList");
  const rawBlock = document.getElementById("rawJsonBlock");

  rawBlock.textContent = JSON.stringify(data, null, 2);
  rawBlock.style.display = "none";
  flagList.innerHTML = "";
  subtitle.textContent = data.filename || filename;
  card.style.display = "block";

  if (data.status === "safe") {
    card.className = "result-card safe";
    icon.innerHTML = `<i class="fa-solid fa-shield-check"></i>`;
    title.textContent = "SAFE — No moderation flags detected";
    flagCont.style.display = "none";
    showToast("Image passed content moderation!", "success");
  } else {
    card.className = "result-card unsafe";
    icon.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i>`;
    title.textContent = "UNSAFE — Content flags detected";
    flagCont.style.display = "block";
    (data.labels || []).forEach(label => {
      const conf = parseFloat(label.confidence).toFixed(1);
      const item = document.createElement("div");
      item.className = "flagged-item";
      item.innerHTML = `
        <div class="flagged-info"><span>${label.name}</span><span>${conf}% confidence</span></div>
        <div class="confidence-bar-bg"><div class="confidence-bar-fill" style="width:${conf}%"></div></div>
      `;
      flagList.appendChild(item);
    });
    showToast("Unsafe content detected!", "warning");
  }
}

// ── JWT Panel toggle ─────────────────────────────────
function toggleJwtPanel() {
  const panel   = document.getElementById("jwtPanel");
  const chevron = document.getElementById("jwtChevron");
  const open    = panel.style.display === "none";
  panel.style.display   = open ? "block" : "none";
  chevron.style.transform = open ? "rotate(180deg)" : "rotate(0deg)";
}

function toggleRawJson() {
  const el = document.getElementById("rawJsonBlock");
  el.style.display = el.style.display === "none" ? "block" : "none";
}

// ── Toast ────────────────────────────────────────────
function showToast(message, type = "info") {
  const icons = {
    info:    `<i class="fa-solid fa-circle-info"  style="color:var(--accent);"></i>`,
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
