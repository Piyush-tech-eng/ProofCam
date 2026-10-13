import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  canonicalize,
  buildRegisterCaptureTransaction,
  computeManifestHash,
  createSolanaVerificationSource,
  isValidSha256Hex,
  sha256,
  validatePackageStructure,
  verifyFile,
  type OnChainCaptureRecord,
  type RecordSummary,
  type SignedCapturePackage,
  type VerificationSource,
} from "@proofcam/client";

async function loadProjectEnv(): Promise<void> {
  try {
    const content = await readFile(join(process.cwd(), "..", "..", ".env"), "utf8");
    for (const line of content.split(/\r?\n/)) {
      const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (!match || match[1] in process.env) continue;
      const value = match[2].replace(/^(['"])(.*)\1$/, "$2");
      process.env[match[1]] = value;
    }
  } catch { /* local .env is optional */ }
}
await loadProjectEnv();

const port = Number(process.env.PORT ?? 3000);
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES ?? 10 * 1024 * 1024);
const dataDir = process.env.PROOFCAM_DATA_DIR ?? join(process.cwd(), "..", "..", ".proofcam-data");
const registryMode = process.env.PROOFCAM_REGISTRY_MODE ?? "local_demo";
const manifestStorageApi = process.env.MANIFEST_STORAGE_API_URL;
const manifestGateway = process.env.MANIFEST_GATEWAY_URL ?? "https://ipfs.io/ipfs";
const solanaSource = registryMode === "solana_devnet" && process.env.SOLANA_RPC_URL && process.env.PROOFCAM_PROGRAM_ID
  ? createSolanaVerificationSource({
      rpcUrl: process.env.SOLANA_RPC_URL,
      programId: process.env.PROOFCAM_PROGRAM_ID,
      manifestGatewayUrl: manifestGateway,
    })
  : null;
const challenges = new Map<string, { expiresAt: number; used: boolean }>();
const packages = new Map<string, SignedCapturePackage>();
const records = new Map<string, DemoRecord>();

interface DemoRecord extends OnChainCaptureRecord { registry: "local_demo"; }

function reply(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "access-control-allow-origin": "*" });
  res.end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const part = Buffer.from(chunk);
    size += part.length;
    if (size > maxUploadBytes * 1.5 + 1024 * 1024) throw Object.assign(new Error("Request exceeds the configured size limit."), { status: 413 });
    chunks.push(part);
  }
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch { throw Object.assign(new Error("Request body must be a JSON object."), { status: 400 }); }
}

function verifyPackage(pkg: SignedCapturePackage): boolean {
  if (!["SHA256withECDSA", "ECDSA_P256_SHA256_WEBCRYPTO"].includes(pkg.signature_algorithm)) return false;
  try {
    const key = createPublicKey({ key: Buffer.from(pkg.public_key, "base64"), format: "der", type: "spki" });
    const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    if (fingerprint !== pkg.payload.device_key_id) return false;
    const signatureKey = pkg.signature_algorithm === "ECDSA_P256_SHA256_WEBCRYPTO" ? { key, dsaEncoding: "ieee-p1363" as const } : key;
    return verifySignature("sha256", Buffer.from(canonicalize(pkg.payload)), signatureKey, Buffer.from(pkg.signature, "base64"));
  } catch { return false; }
}

function summarize(record: DemoRecord): RecordSummary {
  return {
    capture_id: record.captureId,
    authority: record.authority,
    registered_at: record.registeredAt,
    transaction_signature: null,
    explorer_url: null,
    registry: "local_demo",
  };
}

const localSource: VerificationSource = {
  async getRecordByCaptureId(captureId) {
    const record = records.get(captureId);
    return record ? { record, summary: summarize(record) } : null;
  },
  async findRecordsByImageHash(imageHash) {
    return [...records.values()].filter((record) => record.imageHash === imageHash)
      .map((record) => ({ record, summary: summarize(record) }));
  },
  async getManifest(cid) { return packages.get(cid) ?? null; },
};
const unavailableSource: VerificationSource = {
  async getRecordByCaptureId() { throw new Error("Solana registry is not configured"); },
  async findRecordsByImageHash() { throw new Error("Solana registry is not configured"); },
  async getManifest() { throw new Error("Solana registry is not configured"); },
};
const activeSource = registryMode === "solana_devnet" ? solanaSource ?? unavailableSource : localSource;

async function persist(): Promise<void> {
  await mkdir(dataDir, { recursive: true });
  await Promise.all([
    writeFile(join(dataDir, "records.json"), JSON.stringify([...records.values()], null, 2)),
    writeFile(join(dataDir, "manifests.json"), JSON.stringify([...packages.entries()], null, 2)),
  ]);
}

async function storeManifest(pkg: SignedCapturePackage): Promise<string> {
  const manifestHash = computeManifestHash(pkg);
  if (registryMode !== "solana_devnet") return "sha256:" + manifestHash;
  if (!manifestStorageApi) throw Object.assign(new Error("MANIFEST_STORAGE_API_URL is required for Solana registrations."), { status: 503 });

  const endpoint = new URL(manifestStorageApi);
  endpoint.searchParams.set("cid-version", "1");
  endpoint.searchParams.set("pin", "true");
  const form = new FormData();
  form.append("file", new Blob([canonicalize(pkg)], { type: "application/json" }), "manifest.json");
  const headers: Record<string, string> = {};
  if (process.env.MANIFEST_STORAGE_TOKEN) headers.authorization = "Bearer " + process.env.MANIFEST_STORAGE_TOKEN;
  const response = await fetch(endpoint, { method: "POST", headers, body: form, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw Object.assign(new Error("Manifest storage returned HTTP " + response.status), { status: 503 });
  const stored = await response.json() as { Hash?: unknown; cid?: unknown };
  const cid = typeof stored.Hash === "string" ? stored.Hash : typeof stored.cid === "string" ? stored.cid : "";
  if (!/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{9,})$/.test(cid) || cid.length > 64) {
    throw Object.assign(new Error("Manifest storage returned an invalid or oversized CID."), { status: 502 });
  }
  return cid;
}

async function restore(): Promise<void> {
  await mkdir(dataDir, { recursive: true });
  try { for (const record of JSON.parse(await readFile(join(dataDir, "records.json"), "utf8")) as DemoRecord[]) records.set(record.captureId, record); } catch { /* first launch */ }
  try { for (const [cid, pkg] of JSON.parse(await readFile(join(dataDir, "manifests.json"), "utf8")) as [string, SignedCapturePackage][]) packages.set(cid, pkg); } catch { /* first launch */ }
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (req.method === "OPTIONS") { res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-allow-methods": "GET,POST,OPTIONS" }); res.end(); return; }
  if (req.method === "GET" && url.pathname === "/health") { reply(res, 200, { status: "ok", registry: registryMode, live_chain: Boolean(solanaSource) }); return; }
  if (req.method === "GET" && url.pathname === "/v1/config") { reply(res, 200, { registry: registryMode, live_chain: Boolean(solanaSource), manifest_storage: registryMode === "local_demo" || Boolean(manifestStorageApi), detector: "not_configured" }); return; }

  if (req.method === "GET" && url.pathname.startsWith("/v1/manifests/")) {
    const cid = decodeURIComponent(url.pathname.slice("/v1/manifests/".length));
    const pkg = await activeSource.getManifest(cid).catch(() => null);
    if (!pkg) { reply(res, 404, { code: "RECORD_NOT_FOUND", message: "Manifest not found." }); return; }
    reply(res, 200, pkg); return;
  }

  if (req.method === "POST" && url.pathname === "/v1/captures/challenge") {
    const nonce = randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + 5 * 60_000;
    challenges.set(nonce, { expiresAt, used: false });
    reply(res, 200, { nonce, expires_at: new Date(expiresAt).toISOString() }); return;
  }

  if (req.method === "POST" && url.pathname === "/v1/captures/validate") {
    const input = await readJson(req);
    const validation = validatePackageStructure(input.package);
    if (!validation.valid) { reply(res, 400, { code: "INVALID_MANIFEST", message: "Capture package schema is invalid.", details: validation.errors }); return; }
    const pkg = input.package as SignedCapturePackage;
    const challenge = challenges.get(pkg.payload.challenge_nonce);
    if (!challenge || challenge.used || challenge.expiresAt < Date.now()) { reply(res, 400, { code: challenge?.used ? "NONCE_REUSED" : "NONCE_EXPIRED", message: "Challenge is missing, expired, or already used." }); return; }
    if (!verifyPackage(pkg)) { reply(res, 400, { code: "SIGNATURE_INVALID", message: "Device signature validation failed." }); return; }
    const manifestHash = computeManifestHash(pkg);
    let cid: string;
    try { cid = await storeManifest(pkg); }
    catch (error) {
      const status = error && typeof error === "object" && "status" in error ? Number(error.status) : 503;
      reply(res, status, { code: "STORAGE_UNAVAILABLE", message: error instanceof Error ? error.message : "Manifest storage is unavailable." }); return;
    }
    packages.set(cid, pkg);
    challenge.used = true;
    await persist();
    reply(res, 200, { valid: true, manifest_cid: cid, manifest_hash: manifestHash, key_id: pkg.key_id, attestation_level: "unsupported" }); return;
  }

  if (req.method === "POST" && url.pathname === "/v1/captures/index") {
    const input = await readJson(req);
    const captureId = String(input.capture_id ?? "");
    const cid = String(input.manifest_cid ?? "");
    if (registryMode === "solana_devnet") {
      if (!solanaSource) { reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: "Solana RPC or program ID is not configured." }); return; }
      try {
        const selected = await solanaSource.getRecordByCaptureId(captureId);
        if (!selected) { reply(res, 404, { code: "RECORD_NOT_FOUND", message: "The Solana registration is not confirmed yet." }); return; }
        if (selected.record.manifestCid !== cid) { reply(res, 400, { code: "INVALID_REGISTRATION", message: "On-chain manifest CID differs from the requested capture." }); return; }
        reply(res, 200, { record: selected.summary, registry: "solana_devnet" }); return;
      } catch { reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: "Solana RPC could not confirm the capture record." }); return; }
    }
    const pkg = packages.get(cid);
    if (!/^[0-9a-f]{64}$/.test(captureId) || !pkg || pkg.payload.capture_id !== captureId) { reply(res, 400, { code: "INVALID_REGISTRATION", message: "Capture ID does not match the validated manifest." }); return; }
    if (records.has(captureId)) { reply(res, 409, { code: "DUPLICATE_CAPTURE_ID", message: "Capture ID is already registered." }); return; }
    const record: DemoRecord = {
      captureId,
      imageHash: pkg.payload.image_sha256,
      manifestHash: computeManifestHash(pkg),
      authority: String(input.authority ?? "local-demo-wallet"),
      registeredAt: Math.floor(Date.now() / 1000),
      manifestCid: cid,
      locationGeohash: pkg.payload.location.shared ? pkg.payload.location.geohash : null,
      schemaVersion: 1,
      registry: "local_demo",
    };
    records.set(captureId, record);
    await persist();
    reply(res, 201, { record: summarize(record), warning: "Local demo record only; this was not written to Solana." }); return;
  }

  if (req.method === "POST" && url.pathname === "/v1/captures/transaction") {
    if (registryMode !== "solana_devnet") { reply(res, 409, { code: "LOCAL_DEMO_ONLY", message: "The local demo registry does not create Solana transactions." }); return; }
    if (!solanaSource || !process.env.SOLANA_RPC_URL || !process.env.PROOFCAM_PROGRAM_ID) { reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: "Solana RPC or program ID is not configured." }); return; }
    const input = await readJson(req);
    const captureId = String(input.capture_id ?? "");
    const cid = String(input.manifest_cid ?? "");
    const pkg = packages.get(cid);
    if (!pkg || pkg.payload.capture_id !== captureId) { reply(res, 400, { code: "INVALID_REGISTRATION", message: "Capture ID does not match a validated package." }); return; }
    try {
      const transaction = await buildRegisterCaptureTransaction({
        rpcUrl: process.env.SOLANA_RPC_URL,
        programId: process.env.PROOFCAM_PROGRAM_ID,
        authority: String(input.authority ?? ""),
        captureId,
        imageHash: pkg.payload.image_sha256,
        manifestHash: computeManifestHash(pkg),
        manifestCid: cid,
        locationGeohash: pkg.payload.location.shared ? pkg.payload.location.geohash : null,
      });
      reply(res, 200, transaction); return;
    } catch (error) {
      reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: error instanceof Error ? error.message : "Could not build a Solana transaction." }); return;
    }
  }

  if (req.method === "GET" && url.pathname.startsWith("/v1/captures/by-hash/")) {
    const hash = url.pathname.slice("/v1/captures/by-hash/".length);
    if (!isValidSha256Hex(hash)) { reply(res, 400, { code: "INVALID_HASH_FORMAT", message: "Expected lowercase SHA-256 hex." }); return; }
    try {
      const found = await activeSource.findRecordsByImageHash(hash);
      reply(res, 200, { captures: found.map((item) => item.summary) });
    } catch { reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: "Registry lookup is unavailable." }); }
    return;
  }
  if (req.method === "GET" && url.pathname.startsWith("/v1/captures/")) {
    const id = decodeURIComponent(url.pathname.slice("/v1/captures/".length));
    try {
      const selected = await activeSource.getRecordByCaptureId(id);
      if (!selected) { reply(res, 404, { code: "RECORD_NOT_FOUND", message: "No capture record found." }); return; }
      reply(res, 200, { ...selected.record, summary: selected.summary }); return;
    } catch { reply(res, 503, { code: "CHAIN_UNAVAILABLE", message: "Registry lookup is unavailable." }); return; }
  }

  if (req.method === "POST" && url.pathname === "/v1/verify") {
    const input = await readJson(req);
    if (typeof input.file_base64 !== "string" || input.file_base64.length > Math.ceil(maxUploadBytes * 4 / 3) + 8) { reply(res, 413, { code: "PAYLOAD_TOO_LARGE", message: "Image is missing or exceeds the upload limit." }); return; }
    const bytes = Buffer.from(input.file_base64, "base64");
    if (!bytes.length || bytes.length > maxUploadBytes) { reply(res, 413, { code: "PAYLOAD_TOO_LARGE", message: "Image is empty or exceeds the upload limit." }); return; }
    const id = typeof input.capture_id === "string" ? input.capture_id : null;
    const result = await verifyFile({ fileBytes: bytes, captureId: id ?? undefined, includeAiRisk: input.include_ai_risk === true }, activeSource);
    reply(res, 200, result); return;
  }

  reply(res, 404, { code: "NOT_FOUND", message: "Endpoint not found." });
}

await restore();
const server = createServer((req, res) => { void handle(req, res).catch((error: unknown) => {
  const status = error && typeof error === "object" && "status" in error ? Number(error.status) : 500;
  reply(res, status, { code: "INTERNAL_ERROR", message: status === 500 ? "Unexpected server error." : error instanceof Error ? error.message : "Request failed." });
}); });
server.listen(port, "0.0.0.0", () => console.log("ProofCam API listening at http://localhost:" + port + "; registry=" + registryMode));
