const API = window.PROOFCAM_API ?? "http://localhost:3000";
const registerFile = document.querySelector("#register-file");
const verifyFile = document.querySelector("#verify-file");
const registerButton = document.querySelector("#register-button");
const verifyButton = document.querySelector("#verify-button");
let listingImageUrl = null;

async function updateListing(file, captureId) {
  const badge = document.querySelector("#listing-badge");
  const origin = document.querySelector("#listing-origin");
  const preview = document.querySelector("#listing-image");
  const placeholder = document.querySelector("#listing-placeholder");
  if (listingImageUrl) URL.revokeObjectURL(listingImageUrl);
  listingImageUrl = URL.createObjectURL(file);
  preview.src = listingImageUrl;
  preview.style.display = "block";
  placeholder.hidden = true;
  badge.className = "badge unknown";
  badge.textContent = "Checking…";
  origin.textContent = "Checking submitted image";
  try {
    const result = await api("/v1/verify", { file_base64: await fileBase64(file), capture_id: captureId });
    const labels = { match: "File matches record", mismatch: "File mismatch", unknown: "No record found", unavailable: "Check unavailable" };
    badge.className = "badge " + (labels[result.file_integrity] ? result.file_integrity : "unavailable");
    badge.textContent = labels[result.file_integrity] ?? labels.unavailable;
    origin.textContent = result.record?.registry === "solana_devnet" ? "Solana Devnet" : result.record ? "Local demo registry" : "No matching record";
  } catch {
    badge.className = "badge unavailable";
    badge.textContent = "Check unavailable";
    origin.textContent = "Verification API unavailable";
  }
}

function setFileLabel(input, label, button) {
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    label.textContent = file ? file.name : "Choose a file";
    input.closest(".dropzone").classList.toggle("has-file", Boolean(file));
    button.disabled = !file;
  });
}
setFileLabel(registerFile, document.querySelector("#register-filename"), registerButton);
setFileLabel(verifyFile, document.querySelector("#verify-filename"), verifyButton);

async function api(path, body) {
  const response = await fetch(API + path, body ? {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body)
  } : {});
  const data = await response.json();
  if (!response.ok) throw new Error(data.message ?? "Request failed (" + response.status + ")");
  return data;
}
async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function b64(bytes) {
  let text = "";
  for (const b of new Uint8Array(bytes)) text += String.fromCharCode(b);
  return btoa(text);
}
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
}
function randomHex(length) {
  return [...crypto.getRandomValues(new Uint8Array(length))].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function fileBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = () => reject(new Error("Could not read the file."));
    reader.readAsDataURL(file);
  });
}
function escapeHtml(value) {
  return String(value ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));
}

registerButton.addEventListener("click", async () => {
  registerButton.disabled = true;
  const output = document.querySelector("#register-result");
  output.textContent = "Creating a temporary signing key and validating the package…";
  try {
    const file = registerFile.files[0];
    if (file.size > 10 * 1024 * 1024) throw new Error("Choose an image smaller than 10 MB.");
    const imageHash = await sha256(await file.arrayBuffer());
    const challenge = await api("/v1/captures/challenge", {});
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const keyId = await sha256(publicKey);
    const id = randomHex(32);
    const payload = {
      schema_version: "1", capture_id: id, image_sha256: imageHash,
      capture_method: "browser_upload_demo", captured_at_device: new Date().toISOString(),
      device_key_id: keyId, challenge_nonce: challenge.nonce, app_version: "0.1.0",
      location: { shared: false, geohash: null }
    };
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, new TextEncoder().encode(canonical(payload)));
    const signedPackage = {
      schema_version: "1", payload, signature: b64(signature),
      signature_algorithm: "ECDSA_P256_SHA256_WEBCRYPTO",
      public_key: b64(publicKey), key_id: keyId, attestation_chain_ref: null, api_validation_ref: null
    };
    const validated = await api("/v1/captures/validate", { package: signedPackage });
    const registered = await api("/v1/captures/index", { capture_id: id, manifest_cid: validated.manifest_cid, authority: "browser-demo" });
    await updateListing(file, id);
    document.querySelector("#capture-id").value = id;
    output.innerHTML = "<strong>Local demo record created.</strong><div class=\"capture-id\">Capture ID: " + id +
      "</div><div>Image SHA-256: " + imageHash + "</div><div>Manifest: " + escapeHtml(validated.manifest_cid) +
      "</div><div class=\"origin-label\">" + escapeHtml(registered.warning) + "</div>";
  } catch (error) {
    output.textContent = error instanceof Error ? error.message : "Registration failed.";
  } finally {
    registerButton.disabled = !registerFile.files?.length;
  }
});

verifyButton.addEventListener("click", async () => {
  verifyButton.disabled = true;
  const output = document.querySelector("#verification-result");
  output.innerHTML = "<div class=\"inline-result\">Hashing exact image bytes and checking the selected record…</div>";
  try {
    const file = verifyFile.files[0];
    if (file.size > 10 * 1024 * 1024) throw new Error("Choose an image smaller than 10 MB.");
    const capture = document.querySelector("#capture-id").value.trim();
    const result = await api("/v1/verify", {
      file_base64: await fileBase64(file),
      ...(capture ? { capture_id: capture } : {})
    });
    const status = result.file_integrity;
    const display = { match: "Verified file match", mismatch: "File mismatch", unknown: "No record found", unavailable: "Verification unavailable" }[status] ?? "Verification unavailable";
    const record = result.record;
    output.innerHTML = "<div class=\"verification-card\"><div class=\"result-head\">File integrity <span class=\"badge " + escapeHtml(status) + "\">" + escapeHtml(display) +
      "</span></div><div class=\"result-grid\"><div class=\"result-row\"><span>Capture evidence</span><span>" + escapeHtml(result.capture_attestation.status) +
      "</span></div><div class=\"result-row\"><span>Manifest</span><span>" + escapeHtml(result.manifest_valid) +
      "</span></div><div class=\"result-row\"><span>AI-risk estimate</span><span>" + escapeHtml(result.ai_risk.status) + "</span></div>" +
      (record ? "<div class=\"result-row\"><span>Record source</span><span class=\"origin-label\">" + escapeHtml(record.registry) +
      " · not on-chain</span></div><div class=\"result-row\"><span>Registered</span><span>" +
      escapeHtml(new Date(record.registered_at * 1000).toLocaleString()) + "</span></div>" : "") + "</div></div>";
  } catch (error) {
    output.innerHTML = "<div class=\"inline-result\">" + escapeHtml(error instanceof Error ? error.message : "Verification failed.") + "</div>";
  } finally {
    verifyButton.disabled = !verifyFile.files?.length;
  }
});

void api("/v1/config").then((config) => {
  if (config.live_chain) document.querySelector(".network-pill").innerHTML = "<i></i> SOLANA DEVNET";
}).catch(() => { document.querySelector(".network-pill").innerHTML = "<i></i> API OFFLINE"; });
