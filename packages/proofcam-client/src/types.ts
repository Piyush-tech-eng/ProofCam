/**
 * ProofCam Shared Types — v1
 *
 * These types are the single source of truth for all components:
 * Android app, API, Solana program client, verifier, and frontend.
 *
 * Status fields are kept independent:
 * - file_integrity: does the file hash match the on-chain record?
 * - capture_attestation: what device/key evidence is available?
 * - manifest_valid: does the signed package match the on-chain commitment?
 * - ai_risk: what does the optional detector estimate?
 */

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/** Current capture payload schema version. */
export const SCHEMA_VERSION = "1" as const;

// ---------------------------------------------------------------------------
// Status enumerations — never collapsed into a single "authentic" flag
// ---------------------------------------------------------------------------

/**
 * File integrity: does the submitted file's SHA-256 match the on-chain record?
 *
 * - match:       exact byte-level SHA-256 equality
 * - mismatch:    an expected record was supplied but the hash differs
 * - unknown:     lookup succeeded but no matching record was found
 * - unavailable: a required dependency could not be reached
 */
export type FileIntegrityStatus =
  | "match"
  | "mismatch"
  | "unknown"
  | "unavailable";

/**
 * Manifest validity: does the signed capture package match the on-chain commitment?
 *
 * - valid:       package hash matches manifest_hash and signature verifies
 * - invalid:     hash mismatch or signature verification failure
 * - unavailable: package could not be retrieved or verified
 */
export type ManifestStatus = "valid" | "invalid" | "unavailable";

/**
 * Capture attestation level — derived from validated evidence, never self-reported.
 *
 * - hardware_backed: key is TEE/StrongBox-backed and attestation chain validated
 * - software_only:   key exists in Keystore but not hardware-backed
 * - unsupported:     device does not support key attestation
 * - invalid:         attestation evidence failed validation
 * - unavailable:     attestation status could not be determined
 */
export type AttestationLevel =
  | "hardware_backed"
  | "software_only"
  | "unsupported"
  | "invalid"
  | "unavailable";

/**
 * AI/manipulation risk assessment status.
 *
 * - assessed:      model returned a score
 * - not_assessed:  detector was not invoked (e.g., not requested)
 * - unavailable:   detector service could not be reached
 */
export type AiRiskStatus = "assessed" | "not_assessed" | "unavailable";

// ---------------------------------------------------------------------------
// Error codes — machine-readable, for API responses
// ---------------------------------------------------------------------------

export type ErrorCode =
  | "INVALID_IMAGE"
  | "INVALID_HASH_FORMAT"
  | "NONCE_EXPIRED"
  | "NONCE_REUSED"
  | "SIGNATURE_INVALID"
  | "ATTESTATION_INVALID"
  | "RECORD_NOT_FOUND"
  | "CHAIN_UNAVAILABLE"
  | "STORAGE_UNAVAILABLE"
  | "DETECTOR_UNAVAILABLE"
  | "PAYLOAD_TOO_LARGE"
  | "INVALID_SCHEMA_VERSION"
  | "INVALID_CAPTURE_ID"
  | "INVALID_CID"
  | "DUPLICATE_CAPTURE_ID";

// ---------------------------------------------------------------------------
// Capture payload — what the device key signs
// ---------------------------------------------------------------------------

/**
 * Location consent and data.
 * Default: { shared: false, geohash: null }.
 */
export interface LocationData {
  /** Whether the user explicitly consented to share location. */
  shared: boolean;
  /** Coarse geohash, only populated when shared === true. */
  geohash: string | null;
}

/**
 * Version-1 capture payload.
 *
 * This is the canonical object signed by the device key.
 * The `captured_at_device` timestamp is device-supplied — it is
 * NOT necessarily the moment the camera sensor exposed the image.
 * The `capture_method` indicates the app's intended flow, not alone
 * proof that the sensor produced the image.
 */
export interface CapturePayload {
  /** Schema version identifier. */
  schema_version: typeof SCHEMA_VERSION;
  /** Unique capture identifier — 32 random bytes as lowercase hex (64 chars). */
  capture_id: string;
  /** SHA-256 hash of the exact image bytes, lowercase hex (64 chars). */
  image_sha256: string;
  /** Capture path recorded by the client; browser uploads are not native camera evidence. */
  capture_method: "native_camera" | "browser_upload_demo";
  /** Device-local timestamp, ISO-8601 format. */
  captured_at_device: string;
  /** Fingerprint / identifier of the device signing key. */
  device_key_id: string;
  /** Server-issued one-time nonce bound to this capture. */
  challenge_nonce: string;
  /** Application version (semver). */
  app_version: string;
  /** Location data — opt-in, off by default. */
  location: LocationData;
}

// ---------------------------------------------------------------------------
// Signed capture package — stored in manifest storage
// ---------------------------------------------------------------------------

/**
 * The signed capture package assembled after device signing.
 *
 * Hash order:
 * 1. Device signs the canonical payload → signature
 * 2. Package = { payload, signature, public_key, ... }
 * 3. Package is serialized deterministically (RFC 8785 JCS)
 * 4. manifest_hash = SHA-256(deterministic package bytes)
 * 5. manifest_hash is committed on-chain
 *
 * No circular dependency: the payload is signed first,
 * then the package wraps everything, then the package is hashed.
 */
export interface SignedCapturePackage {
  /** Schema version of this package format. */
  schema_version: typeof SCHEMA_VERSION;
  /** The canonical capture payload that was signed. */
  payload: CapturePayload;
  /** Device signature over the canonical payload bytes. */
  signature: string;
  /** Signature algorithm used (e.g., "SHA256withECDSA"). */
  signature_algorithm: string;
  /** Device public key, base64-encoded. */
  public_key: string;
  /** Key identifier matching payload.device_key_id. */
  key_id: string;
  /**
   * Reference to the attestation certificate chain.
   * This may be a URL, CID, or inline data depending on
   * enrollment implementation. Null if unsupported.
   */
  attestation_chain_ref: string | null;
  /**
   * API's validation result reference, if generated.
   * This is NOT the device attestation itself.
   */
  api_validation_ref: string | null;
}

// ---------------------------------------------------------------------------
// On-chain record — mirrors the Anchor account (TypeScript representation)
// ---------------------------------------------------------------------------

/**
 * TypeScript representation of the on-chain CaptureRecord.
 * Field names match the Anchor account struct.
 */
export interface OnChainCaptureRecord {
  /** Random capture identifier — 32 bytes as hex. */
  captureId: string;
  /** SHA-256 of the exact image bytes — 32 bytes as hex. */
  imageHash: string;
  /** SHA-256 of the deterministic signed package — 32 bytes as hex. */
  manifestHash: string;
  /** Solana public key of the registering wallet. */
  authority: string;
  /** Program-clock timestamp of registration (Unix seconds). */
  registeredAt: number;
  /** Content-addressed reference to the signed package. */
  manifestCid: string;
  /** Coarse location geohash, null if not shared. */
  locationGeohash: string | null;
  /** Account schema version. */
  schemaVersion: number;
}

// ---------------------------------------------------------------------------
// Verification response — returned by the verifier / API
// ---------------------------------------------------------------------------

/** Individual attestation check results. */
export type AttestationCheck =
  | "signature_valid"
  | "challenge_fresh"
  | "attestation_chain_valid"
  | "key_not_revoked"
  | "app_integrity_valid";

/** Capture attestation details. */
export interface CaptureAttestation {
  /** Overall attestation level — derived from evidence, never self-reported. */
  status: AttestationLevel;
  /** Which individual checks passed. */
  checks: AttestationCheck[];
}

/** AI risk assessment details. */
export interface AiRiskResult {
  /** Whether assessment was performed. */
  status: AiRiskStatus;
  /** Risk score from the model, null if not assessed. */
  score: number | null;
  /**
   * Risk category derived from the score.
   * Only present when status === "assessed".
   */
  risk_category: "low_risk" | "moderate_risk" | "elevated_risk" | null;
  /**
   * Explanation of score semantics.
   * e.g., "model_score_not_calibrated_probability"
   */
  score_semantics: string | null;
  /** Model version that produced this result. */
  model_version: string | null;
}

/** On-chain record summary included in verification response. */
export interface RecordSummary {
  /** Capture identifier. */
  capture_id: string;
  /** Registering wallet public key. */
  authority: string;
  /** Program-clock timestamp of registration (Unix seconds). */
  registered_at: number;
  /** Solana transaction signature; absent for local demo records. */
  transaction_signature: string | null;
  /** Solana Explorer URL; absent for local demo records. */
  explorer_url: string | null;
  /** Identifies whether this record was read from Solana or a local demo registry. */
  registry: "solana_devnet" | "local_demo";
}

/**
 * Complete verification response.
 *
 * Status fields are independent — a hash match does NOT imply
 * the pictured event really happened. A detector score does NOT
 * override a valid hash match. "No record found" does NOT mean
 * the image is AI-generated.
 */
export interface VerificationResponse {
  /** File integrity: does the file hash match the on-chain record? */
  file_integrity: FileIntegrityStatus;
  /** Capture attestation: what device/key evidence is available? */
  capture_attestation: CaptureAttestation;
  /** Manifest validity: does the package match the on-chain commitment? */
  manifest_valid: ManifestStatus;
  /** AI risk assessment: separate probabilistic estimate. */
  ai_risk: AiRiskResult;
  /** On-chain record summary, null if no record found. */
  record: RecordSummary | null;
}

// ---------------------------------------------------------------------------
// API request/response types
// ---------------------------------------------------------------------------

/** Challenge response from the API. */
export interface ChallengeResponse {
  /** One-time nonce. */
  nonce: string;
  /** Expiry timestamp, ISO-8601. */
  expires_at: string;
}

/** Validation result from the API after checking the signed payload. */
export interface ValidationResult {
  /** Whether the package passed validation. */
  valid: boolean;
  /** Content identifier of the stored signed package. */
  manifest_cid: string;
  /** SHA-256 hash of the deterministic package bytes. */
  manifest_hash: string;
  /** Device key identifier. */
  key_id: string;
  /** Determined attestation level. */
  attestation_level: AttestationLevel;
}

/** Structured API error response. */
export interface ApiError {
  /** Machine-readable error code. */
  code: ErrorCode;
  /** Human-readable message. */
  message: string;
  /** Optional additional details. */
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Verification request
// ---------------------------------------------------------------------------

/** Request to the /v1/verify endpoint. */
export interface VerifyRequest {
  /** SHA-256 hash of the uploaded file (lowercase hex, 64 chars). */
  image_sha256: string;
  /** Optional: specific capture ID to verify against. */
  capture_id?: string;
  /** Optional: request AI risk assessment. */
  include_ai_risk?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum allowed manifest CID length in bytes. */
export const MAX_CID_LENGTH = 64;

/** Maximum allowed geohash length in bytes. */
export const MAX_GEOHASH_LENGTH = 12;

/** Expected SHA-256 hex digest length. */
export const SHA256_HEX_LENGTH = 64;

/** Expected capture ID hex length (32 bytes = 64 hex chars). */
export const CAPTURE_ID_HEX_LENGTH = 64;

/** PDA seed prefix for capture records. */
export const CAPTURE_PDA_SEED = "capture";
