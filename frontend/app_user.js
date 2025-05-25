let userToken = "";

function saveToken() {
  userToken = document.getElementById("userToken").value;
  alert("Token saved!");
}

async function moderate() {
  if (!userToken) return alert("Save your token first");
  const input = document.getElementById("imgFile");
  if (!input.files.length) return alert("Pick a file");
  const form = new FormData();
  form.append("file", input.files[0]);

  const res = await fetch("/moderate", {
    method: "POST",
    headers: { Authorization: `Bearer ${userToken}` },
    body: form
  });
  const out = document.getElementById("modResult");
  if (!res.ok) {
    const err = await res.json();
    out.textContent = `Error: ${err.detail || JSON.stringify(err)}`;
    return;
  }
  out.textContent = JSON.stringify(await res.json(), null, 2);
}
