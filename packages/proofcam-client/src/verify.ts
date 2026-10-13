import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import type {
  AiRiskResult,
  CaptureAttestation,
  OnChainCaptureRecord,
  RecordSummary,
  SignedCapturePackage,
  VerificationResponse,
} from "./types.js";
import { canonicalize } from "./canonicalize.js";
import { computeManifestHash, validatePackageStructure } from "./manifest.js";
import { sha256 } from "./hashing.js";

/** Read-only interface implemented by an on-chain registry adapter and manifest store. */
export interface VerificationSource {
  getRecordByCaptureId(captureId: string): Promise<{ record: OnChainCaptureRecord; summary: RecordSummary } | null>;
  findRecordsByImageHash(imageHash: string): Promise<Array<{ record: OnChainCaptureRecord; summary: RecordSummary }>>;
  getManifest(cid: string): Promise<SignedCapturePackage | null>;
}

export interface VerifyFileOptions {
  /** Exact file bytes. No decoding, metadata removal, or re-encoding is performed. */
  fileBytes: Uint8Array;
  /** Optional expected capture ID; a mismatch is reported against that record. */
  captureId?: string;
  /** Requests an independent detector signal. */
  includeAiRisk?: boolean;
}

function verifyDeviceSignature(pkg: SignedCapturePackage): boolean {
  if (pkg.signature_algorithm !== "SHA256withECDSA" && pkg.signature_algorithm !== "ECDSA_P256_SHA256_WEBCRYPTO") return false;
  try {
    const key = createPublicKey({ key: Buffer.from(pkg.public_key, "base64"), format: "der", type: "spki" });
    const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    if (fingerprint !== pkg.payload.device_key_id || pkg.key_id !== pkg.payload.device_key_id) return false;
    const verifierKey = pkg.signature_algorithm === "ECDSA_P256_SHA256_WEBCRYPTO" ? { key, dsaEncoding: "ieee-p1363" as const } : key;
    return verifySignature("sha256", Buffer.from(canonicalize(pkg.payload)), verifierKey, Buffer.from(pkg.signature, "base64"));
  } catch {
    return false;
  }
}

function aiRisk(include: boolean): AiRiskResult {
  return { status: include ? "unavailable" : "not_assessed", score: null, risk_category: null, score_semantics: null, model_version: null };
}

function empty(status: VerificationResponse["file_integrity"], includeAiRisk: boolean): VerificationResponse {
  return {
    file_integrity: status,
    capture_attestation: { status: "unavailable", checks: [] },
    manifest_valid: "unavailable",
    ai_risk: aiRisk(includeAiRisk),
    record: null,
  };
}

function manifestEvidence(
  pkg: SignedCapturePackage | null,
  expectedHash: string,
  record: OnChainCaptureRecord
): { status: VerificationResponse["manifest_valid"]; attestation: CaptureAttestation } {
  if (!pkg) return { status: "unavailable", attestation: { status: "unavailable", checks: [] } };
  const structure = validatePackageStructure(pkg);
  if (!structure.valid || computeManifestHash(pkg) !== expectedHash ||
      pkg.payload.image_sha256 !== record.imageHash || pkg.payload.capture_id !== record.captureId) {
    return { status: "invalid", attestation: { status: "invalid", checks: [] } };
  }
  if (!verifyDeviceSignature(pkg)) return { status: "invalid", attestation: { status: "invalid", checks: [] } };
  // A valid public-key signature does not establish Android Keystore or hardware attestation.
  return { status: "valid", attestation: { status: "unsupported", checks: ["signature_valid"] } };
}

/**
 * Verify exact file bytes against an expected capture or a hash-index result.
 * Chain/index and storage failures return unavailable; they never produce a false match.
 */
export async function verifyFile(
  options: VerifyFileOptions,
  source: VerificationSource
): Promise<VerificationResponse> {
  const hash = sha256(options.fileBytes);
  let candidates: Array<{ record: OnChainCaptureRecord; summary: RecordSummary }>;
  try {
    if (options.captureId) {
      const selected = await source.getRecordByCaptureId(options.captureId);
      candidates = selected ? [selected] : [];
    } else {
      candidates = await source.findRecordsByImageHash(hash);
    }
  } catch {
    return empty("unavailable", Boolean(options.includeAiRisk));
  }
  if (!candidates.length) return empty("unknown", Boolean(options.includeAiRisk));

  const selected = candidates.find(({ record }) => record.imageHash === hash) ?? candidates[0];
  let pkg: SignedCapturePackage | null;
  try {
    pkg = await source.getManifest(selected.record.manifestCid);
  } catch {
    pkg = null;
  }
  const evidence = manifestEvidence(pkg, selected.record.manifestHash, selected.record);
  return {
    file_integrity: hash === selected.record.imageHash ? "match" : options.captureId ? "mismatch" : "unknown",
    capture_attestation: evidence.attestation,
    manifest_valid: evidence.status,
    ai_risk: aiRisk(Boolean(options.includeAiRisk)),
    record: selected.summary,
  };
}
