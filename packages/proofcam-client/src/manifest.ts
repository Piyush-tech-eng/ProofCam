/**
 * Signed capture package builder and validator.
 *
 * Hash order (no circular dependency):
 * 1. Device signs the canonical payload → signature
 * 2. Package = { payload, signature, public_key, ... }
 * 3. Package is serialized deterministically via RFC 8785 JCS
 * 4. manifest_hash = SHA-256(deterministic package bytes)
 * 5. manifest_hash is committed on-chain
 */

import type {
  CapturePayload,
  SignedCapturePackage,
} from "./types.js";
import { MAX_GEOHASH_LENGTH, SCHEMA_VERSION } from "./types.js";
import { canonicalize, canonicalizeToBytes } from "./canonicalize.js";
import { sha256, isValidSha256Hex } from "./hashing.js";

/**
 * Build a signed capture package from a payload and device signature.
 *
 * @param payload - The canonical capture payload (already signed by device key).
 * @param signature - Base64-encoded signature over the canonical payload bytes.
 * @param signatureAlgorithm - Algorithm used (e.g., "SHA256withECDSA").
 * @param publicKey - Base64-encoded device public key.
 * @param keyId - Key identifier matching payload.device_key_id.
 * @param attestationChainRef - Reference to attestation chain, or null.
 * @param apiValidationRef - Reference to API's validation result, or null.
 * @returns The assembled signed capture package.
 */
export function buildSignedPackage(
  payload: CapturePayload,
  signature: string,
  signatureAlgorithm: string,
  publicKey: string,
  keyId: string,
  attestationChainRef: string | null = null,
  apiValidationRef: string | null = null
): SignedCapturePackage {
  return {
    schema_version: SCHEMA_VERSION,
    payload,
    signature,
    signature_algorithm: signatureAlgorithm,
    public_key: publicKey,
    key_id: keyId,
    attestation_chain_ref: attestationChainRef,
    api_validation_ref: apiValidationRef,
  };
}

/**
 * Compute the manifest hash of a signed capture package.
 *
 * Serializes the package deterministically via RFC 8785 JCS,
 * then returns the SHA-256 of the resulting bytes.
 *
 * @param pkg - The signed capture package.
 * @returns Lowercase hex SHA-256 hash of the canonical package bytes.
 */
export function computeManifestHash(pkg: SignedCapturePackage): string {
  const canonicalBytes = canonicalizeToBytes(pkg);
  return sha256(canonicalBytes);
}

/**
 * Get the canonical bytes of a signed capture package.
 * Useful for verification: re-serialize and compare hash.
 *
 * @param pkg - The signed capture package.
 * @returns UTF-8 bytes of the canonical JSON.
 */
export function getPackageCanonicalBytes(
  pkg: SignedCapturePackage
): Uint8Array {
  return canonicalizeToBytes(pkg);
}

/**
 * Get the canonical bytes of a capture payload.
 * These are the bytes that the device key signs.
 *
 * @param payload - The capture payload.
 * @returns UTF-8 bytes of the canonical JSON.
 */
export function getPayloadCanonicalBytes(payload: CapturePayload): Uint8Array {
  return canonicalizeToBytes(payload);
}

/**
 * Get the canonical JSON string of a capture payload.
 *
 * @param payload - The capture payload.
 * @returns Canonical JSON string.
 */
export function getPayloadCanonicalString(payload: CapturePayload): string {
  return canonicalize(payload);
}

/**
 * Validate the structure of a signed capture package.
 *
 * Checks:
 * - Schema version matches.
 * - Payload fields are present and well-formed.
 * - Image hash is valid SHA-256 hex.
 * - Capture ID is valid hex.
 * - Key ID in package matches payload.device_key_id.
 * - Signature and public key are non-empty.
 *
 * Does NOT verify the cryptographic signature — that requires
 * the appropriate crypto library for the key type.
 *
 * @param pkg - The package to validate.
 * @returns Object with valid flag and list of error messages.
 */
export function validatePackageStructure(pkg: unknown): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (typeof pkg !== "object" || pkg === null) {
    return { valid: false, errors: ["Package must be a non-null object"] };
  }

  const p = pkg as Record<string, unknown>;

  // Schema version
  if (p.schema_version !== SCHEMA_VERSION) {
    errors.push(
      `Expected schema_version "${SCHEMA_VERSION}", got "${p.schema_version}"`
    );
  }

  // Payload
  if (typeof p.payload !== "object" || p.payload === null) {
    errors.push("Missing or invalid payload");
  } else {
    const payload = p.payload as Record<string, unknown>;

    if (!isValidSha256Hex(payload.image_sha256 as string)) {
      errors.push("Invalid image_sha256 — must be 64 lowercase hex chars");
    }

    if (
      typeof payload.capture_id !== "string" ||
      !/^[0-9a-f]{64}$/.test(payload.capture_id)
    ) {
      errors.push("Invalid capture_id — must be 64 lowercase hex chars");
    }

    if (payload.schema_version !== SCHEMA_VERSION) {
      errors.push("Payload schema_version mismatch");
    }

    if (typeof payload.captured_at_device !== "string") {
      errors.push("Missing captured_at_device");
    } else if (!Number.isFinite(Date.parse(payload.captured_at_device))) {
      errors.push("Invalid captured_at_device — expected a parseable ISO-8601 timestamp");
    }

    if (payload.capture_method !== "native_camera" && payload.capture_method !== "browser_upload_demo") {
      errors.push("Unsupported capture_method");
    }

    if (typeof payload.device_key_id !== "string" || !payload.device_key_id) {
      errors.push("Missing device_key_id");
    }

    if (typeof payload.challenge_nonce !== "string" || !payload.challenge_nonce) {
      errors.push("Missing challenge_nonce");
    }

    if (typeof payload.app_version !== "string" || !payload.app_version) {
      errors.push("Missing app_version");
    }

    const location = payload.location;
    if (typeof location !== "object" || location === null || Array.isArray(location)) {
      errors.push("Missing or invalid location consent object");
    } else {
      const locationData = location as Record<string, unknown>;
      if (typeof locationData.shared !== "boolean") {
        errors.push("location.shared must be a boolean");
      }
      if (locationData.shared === false && locationData.geohash !== null) {
        errors.push("location.geohash must be null when location is not shared");
      }
      if (locationData.shared === true) {
        const geohash = locationData.geohash;
        if (typeof geohash !== "string" || geohash.length < 1 || geohash.length > MAX_GEOHASH_LENGTH ||
            !/^[0123456789bcdefghjkmnpqrstuvwxyz]+$/.test(geohash)) {
          errors.push("location.geohash must be a valid coarse geohash of at most 12 characters");
        }
      }
    }

    // Key ID consistency
    if (
      typeof p.key_id === "string" &&
      typeof payload.device_key_id === "string" &&
      p.key_id !== payload.device_key_id
    ) {
      errors.push("Package key_id does not match payload.device_key_id");
    }
  }

  // Signature
  if (typeof p.signature !== "string" || !p.signature) {
    errors.push("Missing signature");
  }

  // Signature algorithm
  if (typeof p.signature_algorithm !== "string" || !p.signature_algorithm) {
    errors.push("Missing signature_algorithm");
  }

  // Public key
  if (typeof p.public_key !== "string" || !p.public_key) {
    errors.push("Missing public_key");
  }

  // Key ID
  if (typeof p.key_id !== "string" || !p.key_id) {
    errors.push("Missing key_id");
  }

  return { valid: errors.length === 0, errors };
}
