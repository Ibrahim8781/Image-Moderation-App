let adminJWT = "";

async function doLogin() {
  const u = document.getElementById("loginUser").value;
  const p = document.getElementById("loginPass").value;
  const res = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: u, password: p })
  });
  const txt = document.getElementById("loginResult");
  if (!res.ok) {
    txt.textContent = `Error: ${await res.text()}`;
    return;
  }
  const { token } = await res.json();
  adminJWT = token;
  txt.textContent = `Logged in! JWT:\n${token}`;
}

async function createToken(isAdmin) {
  if (!adminJWT) return alert("Log in first");
  const res = await fetch("/auth/tokens?is_admin=" + isAdmin, {
    method: "POST",
    headers: { Authorization: `Bearer ${adminJWT}` }
  });
  const txt = document.getElementById("tokenResult");
  if (!res.ok) {
    txt.textContent = `Error: ${await res.text()}`;
    return;
  }
  const { token } = await res.json();
  txt.textContent = `New token:\n${token}`;
}

async function listTokens() {
  if (!adminJWT) return alert("Log in first");
  const res = await fetch("/auth/tokens", {
    headers: { Authorization: `Bearer ${adminJWT}` }
  });
  const txt = document.getElementById("tokenResult");
  const data = await res.json();
  txt.textContent = JSON.stringify(data, null, 2);
}
