/**
 * ProofCam Client SDK — public API surface.
 *
 * Re-exports all types, hashing, canonicalization, and manifest utilities.
 * Registry and verify modules will be added in Gate C.
 */

// Types
export type {
  FileIntegrityStatus,
  ManifestStatus,
  AttestationLevel,
  AiRiskStatus,
  ErrorCode,
  LocationData,
  CapturePayload,
  SignedCapturePackage,
  OnChainCaptureRecord,
  AttestationCheck,
  CaptureAttestation,
  AiRiskResult,
  RecordSummary,
  VerificationResponse,
  ChallengeResponse,
  ValidationResult,
  ApiError,
  VerifyRequest,
} from "./types.js";

export {
  SCHEMA_VERSION,
  MAX_CID_LENGTH,
  MAX_GEOHASH_LENGTH,
  SHA256_HEX_LENGTH,
  CAPTURE_ID_HEX_LENGTH,
  CAPTURE_PDA_SEED,
} from "./types.js";

// Hashing
export {
  sha256,
  sha256String,
  sha256File,
  isValidSha256Hex,
  hexToBytes,
  bytesToHex,
} from "./hashing.js";

// Canonicalization
export { canonicalize, canonicalizeToBytes } from "./canonicalize.js";

// Manifest
export {
  buildSignedPackage,
  computeManifestHash,
  getPackageCanonicalBytes,
  getPayloadCanonicalBytes,
  getPayloadCanonicalString,
  validatePackageStructure,
} from "./manifest.js";

// Verification orchestration
export { verifyFile } from "./verify.js";
export type { VerificationSource, VerifyFileOptions } from "./verify.js";
export { buildRegisterCaptureTransaction, createSolanaVerificationSource } from "./solana.js";
export type { RegisterCaptureTransactionOptions, SolanaSourceOptions } from "./solana.js";
