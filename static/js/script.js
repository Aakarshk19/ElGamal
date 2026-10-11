const state = {
  keys: null,
  lastCalculations: "",
  textCipher: null,
  originalMessage: "",
  encryptedPackage: null,
  encryptedName: "",
  decryptedBlob: null,
  decryptedName: "",
};

const $ = (id) => document.getElementById(id);

function setStatus(el, message, kind) {
  el.hidden = !message;
  el.textContent = message || "";
  el.className = `status ${kind || "info"}`;
}

function requireKeys(needPrivate = false) {
  if (!state.keys) {
    throw new Error("Generate keys first.");
  }
  if (needPrivate && !state.keys.private_key) {
    throw new Error("Private key x is missing.");
  }
}

function keyPayload(extra = {}) {
  return {
    p: state.keys.public_key.p,
    g: state.keys.public_key.g,
    y: state.keys.public_key.y,
    x: state.keys.private_key.x,
    ...extra,
  };
}

function formatCalc(title, lines) {
  return `${title}\n${"=".repeat(title.length)}\n${lines.join("\n")}`;
}

function updateCalc(...sections) {
  state.lastCalculations = sections.filter(Boolean).join("\n\n");
  $("btn-show-calc").disabled = !state.lastCalculations;
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.error || "Request failed.");
  }
  return data;
}

async function postForm(url, formData) {
  const res = await fetch(url, { method: "POST", body: formData });
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.error || "Request failed.");
  }
  return data;
}

$("btn-generate").addEventListener("click", async () => {
  const status = $("key-status");
  setStatus(status, "Generating a safe prime. This may take a few seconds…", "info");
  $("btn-generate").disabled = true;
  try {
    const bits = Number($("key-bits").value);
    const data = await postJSON("/api/generate-keys", { bits });
    state.keys = data;
    $("val-p").textContent = data.public_key.p;
    $("val-g").textContent = data.public_key.g;
    $("val-y").textContent = data.public_key.y;
    $("val-x").textContent = data.private_key.x;
    $("val-p").classList.remove("empty");
    $("val-g").classList.remove("empty");
    $("val-y").classList.remove("empty");
    $("val-x").classList.remove("empty");
    updateCalc(formatCalc("Key Generation", data.calculations.steps));
    setStatus(status, `Keys generated (${data.bits}-bit modulus). Public key = (p, g, y), private key = x.`, "ok");
  } catch (err) {
    setStatus(status, err.message, "bad");
  } finally {
    $("btn-generate").disabled = false;
  }
});

$("btn-encrypt-text").addEventListener("click", async () => {
  const verify = $("text-verify");
  verify.hidden = true;
  try {
    requireKeys();
    const message = $("message-input").value;
    if (!message.trim()) {
      throw new Error("Please enter a non-empty message.");
    }
    const data = await postJSON("/api/encrypt-text", keyPayload({ message }));
    state.textCipher = data.ciphertext;
    state.originalMessage = message.trim();
    $("text-original").textContent = state.originalMessage;
    $("text-cipher").textContent = data.display;
    $("text-plain").textContent = "—";
    $("text-original").classList.remove("empty");
    $("text-cipher").classList.remove("empty");
    $("text-plain").classList.add("empty");
    $("btn-decrypt-text").disabled = false;
    updateCalc(
      state.lastCalculations.split("\n\n")[0],
      formatCalc("Text Encryption", data.calculations.summary)
    );
  } catch (err) {
    verify.hidden = false;
    verify.className = "verify bad";
    verify.textContent = err.message;
  }
});

$("btn-decrypt-text").addEventListener("click", async () => {
  const verify = $("text-verify");
  try {
    requireKeys(true);
    if (!state.textCipher) {
      throw new Error("Encrypt a message first.");
    }
    const data = await postJSON("/api/decrypt-text", keyPayload({
      ciphertext: state.textCipher,
      original_message: state.originalMessage,
    }));
    $("text-plain").textContent = data.message;
    $("text-plain").classList.remove("empty");
    verify.hidden = false;
    verify.className = "verify ok";
    verify.textContent = data.integrity_note;
    const existing = state.lastCalculations.split("\n\n");
    updateCalc(existing[0], existing[1], formatCalc("Text Decryption", data.calculations.summary));
  } catch (err) {
    verify.hidden = false;
    verify.className = "verify bad";
    verify.textContent = err.message;
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const name = tab.dataset.tab;
    $("panel-text").classList.toggle("hidden", name !== "text");
    $("panel-file").classList.toggle("hidden", name !== "file");
  });
});

$("file-input").addEventListener("change", () => {
  const file = $("file-input").files[0];
  $("file-name").textContent = file ? file.name : "None";
  $("file-size").textContent = file ? `${file.size} bytes` : "—";
  $("file-hash").textContent = "—";
  $("file-hash").classList.add("empty");
});

$("enc-input").addEventListener("change", () => {
  const file = $("enc-input").files[0];
  $("enc-name").textContent = file ? file.name : "None";
});

$("btn-hash").addEventListener("click", async () => {
  try {
    const file = $("file-input").files[0];
    if (!file) throw new Error("Please choose a file first.");
    const form = new FormData();
    form.append("file", file);
    const data = await postForm("/api/hash-file", form);
    $("file-name").textContent = data.filename;
    $("file-size").textContent = data.size_label;
    $("file-hash").textContent = data.sha256;
    $("file-hash").classList.remove("empty");
  } catch (err) {
    $("file-hash").textContent = err.message;
    $("file-hash").classList.remove("empty");
  }
});

$("btn-encrypt-file").addEventListener("click", async () => {
  try {
    requireKeys();
    const file = $("file-input").files[0];
    if (!file) throw new Error("Please choose a file first.");
    const form = new FormData();
    form.append("file", file);
    form.append("p", state.keys.public_key.p);
    form.append("g", state.keys.public_key.g);
    form.append("y", state.keys.public_key.y);
    const data = await postForm("/api/encrypt-file-info", form);
    state.encryptedPackage = data.package_text;
    state.encryptedName = data.download_name;
    $("file-hash").textContent = data.original_sha256;
    $("file-hash").classList.remove("empty");
    $("enc-file-status").textContent = `${data.scheme}. Package ready: ${data.download_name}`;
    $("btn-download-enc").disabled = false;
    const existing = state.lastCalculations.split("\n\n")[0];
    updateCalc(existing, formatCalc("Hybrid File Encryption", data.calculations.summary));
  } catch (err) {
    $("enc-file-status").textContent = err.message;
  }
});

$("btn-download-enc").addEventListener("click", () => {
  if (!state.encryptedPackage) return;
  const blob = new Blob([state.encryptedPackage], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = state.encryptedName || "encrypted.elgamal.json";
  a.click();
  URL.revokeObjectURL(a.href);
});

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

$("btn-decrypt-file").addEventListener("click", async () => {
  const status = $("hash-status");
  try {
    requireKeys(true);
    const file = $("enc-input").files[0];
    if (!file) throw new Error("Upload an encrypted package first.");
    const form = new FormData();
    form.append("file", file);
    form.append("p", state.keys.public_key.p);
    form.append("x", state.keys.private_key.x);
    const data = await postForm("/api/decrypt-file", form);
    $("hash-original").textContent = data.original_sha256 || "—";
    $("hash-decrypted").textContent = data.decrypted_sha256;
    $("hash-original").classList.remove("empty");
    $("hash-decrypted").classList.remove("empty");
    status.hidden = false;
    if (data.integrity_match) {
      status.className = "verify ok";
      status.textContent = "✓ Hash Match – File integrity verified";
    } else {
      status.className = "verify bad";
      status.textContent = "✗ Hash Mismatch – File may have been modified/corrupted";
    }
    const bytes = hexToBytes(data.file_b64);
    state.decryptedBlob = new Blob([bytes]);
    state.decryptedName = data.original_name || "decrypted.bin";
    $("btn-download-dec").disabled = false;
    const existing = state.lastCalculations.split("\n\n")[0];
    updateCalc(existing, formatCalc("Hybrid File Decryption", data.calculations.summary));
  } catch (err) {
    status.hidden = false;
    status.className = "verify bad";
    status.textContent = err.message;
  }
});

$("btn-download-dec").addEventListener("click", () => {
  if (!state.decryptedBlob) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(state.decryptedBlob);
  a.download = state.decryptedName;
  a.click();
  URL.revokeObjectURL(a.href);
});

$("btn-show-calc").addEventListener("click", () => {
  $("calc-body").textContent = state.lastCalculations || "No calculations yet.";
  $("calc-modal").classList.remove("hidden");
});

$("btn-close-calc").addEventListener("click", () => {
  $("calc-modal").classList.add("hidden");
});

$("calc-modal").addEventListener("click", (event) => {
  if (event.target.id === "calc-modal") {
    $("calc-modal").classList.add("hidden");
  }
});
