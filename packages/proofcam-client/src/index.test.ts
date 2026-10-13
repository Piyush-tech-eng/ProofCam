/**
 * ProofCam SDK — Unit Tests
 *
 * Tests cover:
 * - SHA-256 hashing (exact bytes, hex encoding, validation)
 * - RFC 8785 JCS canonicalization (deterministic output, key sorting)
 * - Manifest package building and hash computation
 * - Package structural validation
 * - Cross-platform test vector agreement
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  sha256,
  sha256String,
  isValidSha256Hex,
  hexToBytes,
  bytesToHex,
} from "./hashing.js";

import { canonicalize, canonicalizeToBytes } from "./canonicalize.js";

import {
  buildSignedPackage,
  computeManifestHash,
  getPayloadCanonicalString,
  validatePackageStructure,
} from "./manifest.js";

import type { CapturePayload, SignedCapturePackage } from "./types.js";

// ---------------------------------------------------------------------------
// Load test vectors
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(__dirname, "../../../tests/fixtures");
const vectorsPath = resolve(fixturesDir, "test-vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf-8"));
const expectedHashesPath = resolve(fixturesDir, "expected-hashes.json");
const expectedHashes = JSON.parse(readFileSync(expectedHashesPath, "utf-8"));
const sampleJpgPath = resolve(fixturesDir, "sample.jpg");
const sampleJpgBytes = readFileSync(sampleJpgPath);

// ---------------------------------------------------------------------------
// SHA-256 Hashing
// ---------------------------------------------------------------------------

describe("sha256", () => {
  it("hashes an empty buffer correctly", () => {
    const expected =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(sha256(Buffer.alloc(0))).toBe(expected);
  });

  it("hashes 'hello world' correctly", () => {
    const expected =
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    expect(sha256(Buffer.from("hello world"))).toBe(expected);
  });

  it("always returns lowercase hex", () => {
    const hash = sha256(Buffer.from("test"));
    expect(hash).toBe(hash.toLowerCase());
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("matches test vector for sample image bytes", () => {
    const imageVector = vectors.image_vectors[0];
    const imageBytes = Buffer.from(imageVector.bytes_base64, "base64");
    const hash = sha256(imageBytes);
    expect(hash).toBe(imageVector.expected_sha256);
  });

  it("hashes sample.jpg file and matches expected-hashes.json", () => {
    const hash = sha256(sampleJpgBytes);
    expect(hash).toBe(expectedHashes.sample_image.sha256);
  });

  it("produces different hashes for different bytes", () => {
    const hash1 = sha256(Buffer.from("image data version 1"));
    const hash2 = sha256(Buffer.from("image data version 2"));
    expect(hash1).not.toBe(hash2);
  });
});

describe("sha256String", () => {
  it("hashes a UTF-8 string", () => {
    const hash = sha256String("test");
    expect(hash).toBe(
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
  });
});

describe("isValidSha256Hex", () => {
  for (const vec of vectors.validation_vectors) {
    it(`${vec.description}: "${vec.input.substring(0, 20)}..."`, () => {
      expect(isValidSha256Hex(vec.input)).toBe(vec.expected_valid);
    });
  }

  it("rejects non-string input", () => {
    // @ts-expect-error — testing runtime behavior
    expect(isValidSha256Hex(123)).toBe(false);
    // @ts-expect-error — testing runtime behavior
    expect(isValidSha256Hex(null)).toBe(false);
  });
});

describe("hexToBytes / bytesToHex", () => {
  it("round-trips correctly", () => {
    const hex = "a1b2c3d4e5f6";
    const bytes = hexToBytes(hex);
    expect(bytesToHex(bytes)).toBe(hex);
  });

  it("converts known bytes", () => {
    const bytes = new Uint8Array([0, 255, 16, 128]);
    expect(bytesToHex(bytes)).toBe("00ff1080");
  });

  it("rejects odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow("even length");
  });

  it("rejects uppercase hex", () => {
    expect(() => hexToBytes("AABB")).toThrow("lowercase");
  });
});

// ---------------------------------------------------------------------------
// JCS Canonicalization
// ---------------------------------------------------------------------------

describe("canonicalize (RFC 8785)", () => {
  it("sorts object keys lexicographically", () => {
    const obj = { z: 1, a: 2, m: 3 };
    expect(canonicalize(obj)).toBe('{"a":2,"m":3,"z":1}');
  });

  it("handles nested objects with sorted keys", () => {
    const obj = { b: { d: 1, c: 2 }, a: 3 };
    expect(canonicalize(obj)).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it("handles null", () => {
    expect(canonicalize(null)).toBe("null");
  });

  it("handles booleans", () => {
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
  });

  it("handles numbers", () => {
    expect(canonicalize(42)).toBe("42");
    expect(canonicalize(3.14)).toBe("3.14");
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(1e20)).toBe("100000000000000000000");
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(-Infinity)).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
  });

  it("escapes control characters in strings", () => {
    expect(canonicalize("line\nbreak")).toBe('"line\\nbreak"');
    expect(canonicalize("tab\there")).toBe('"tab\\there"');
    expect(canonicalize("\x00")).toBe('"\\u0000"');
  });

  it("escapes backslash and quotes", () => {
    expect(canonicalize('say "hi"')).toBe('"say \\"hi\\""');
    expect(canonicalize("back\\slash")).toBe('"back\\\\slash"');
  });

  it("handles arrays in order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("omits undefined properties", () => {
    const obj = { a: 1, b: undefined, c: 3 };
    expect(canonicalize(obj)).toBe('{"a":1,"c":3}');
  });

  it("produces no whitespace", () => {
    const obj = { key: "value", arr: [1, 2] };
    const result = canonicalize(obj);
    expect(result).not.toMatch(/\s/);
  });

  it("matches expected canonical output for basic payload", () => {
    const vec = vectors.payload_vectors[0];
    const result = canonicalize(vec.payload);
    expect(result).toBe(vec.expected_canonical);
  });

  it("matches expected canonical output for payload with location", () => {
    const vec = vectors.payload_vectors[1];
    const result = canonicalize(vec.payload);
    expect(result).toBe(vec.expected_canonical);
  });

  it("produces deterministic output regardless of property insertion order", () => {
    // Build the same payload with different property orders
    const payload1 = {
      schema_version: "1",
      capture_id: "aa",
      image_sha256: "bb",
    };
    const payload2 = {
      image_sha256: "bb",
      schema_version: "1",
      capture_id: "aa",
    };
    expect(canonicalize(payload1)).toBe(canonicalize(payload2));
  });
});

describe("canonicalizeToBytes", () => {
  it("returns UTF-8 encoded bytes", () => {
    const bytes = canonicalizeToBytes({ a: 1 });
    const text = new TextDecoder().decode(bytes);
    expect(text).toBe('{"a":1}');
  });

  it("produces bytes whose SHA-256 is deterministic", () => {
    const bytes1 = canonicalizeToBytes({ z: 1, a: 2 });
    const bytes2 = canonicalizeToBytes({ a: 2, z: 1 });
    expect(sha256(bytes1)).toBe(sha256(bytes2));
  });
});

// ---------------------------------------------------------------------------
// Manifest / Package
// ---------------------------------------------------------------------------

describe("buildSignedPackage", () => {
  const samplePayload: CapturePayload = vectors.payload_vectors[0].payload;

  it("assembles a valid package", () => {
    const pkg = buildSignedPackage(
      samplePayload,
      "test-signature",
      "SHA256withECDSA",
      "test-public-key",
      "test-device-key-001"
    );

    expect(pkg.schema_version).toBe("1");
    expect(pkg.payload).toBe(samplePayload);
    expect(pkg.signature).toBe("test-signature");
    expect(pkg.signature_algorithm).toBe("SHA256withECDSA");
    expect(pkg.public_key).toBe("test-public-key");
    expect(pkg.key_id).toBe("test-device-key-001");
    expect(pkg.attestation_chain_ref).toBeNull();
    expect(pkg.api_validation_ref).toBeNull();
  });

  it("includes optional fields when provided", () => {
    const pkg = buildSignedPackage(
      samplePayload,
      "sig",
      "SHA256withECDSA",
      "pubkey",
      "key-001",
      "ipfs://attest-chain-cid",
      "ipfs://validation-ref-cid"
    );

    expect(pkg.attestation_chain_ref).toBe("ipfs://attest-chain-cid");
    expect(pkg.api_validation_ref).toBe("ipfs://validation-ref-cid");
  });
});

describe("computeManifestHash", () => {
  it("produces a valid SHA-256 hex hash", () => {
    const pkg: SignedCapturePackage = vectors.package_vectors[0].package;
    const hash = computeManifestHash(pkg);
    expect(isValidSha256Hex(hash)).toBe(true);
  });

  it("is deterministic for the same package", () => {
    const pkg: SignedCapturePackage = vectors.package_vectors[0].package;
    const hash1 = computeManifestHash(pkg);
    const hash2 = computeManifestHash(pkg);
    expect(hash1).toBe(hash2);
  });

  it("changes when any field is modified", () => {
    const pkg: SignedCapturePackage = vectors.package_vectors[0].package;
    const original = computeManifestHash(pkg);

    // Alter the signature
    const altered = { ...pkg, signature: "tampered-signature" };
    const tampered = computeManifestHash(altered);
    expect(tampered).not.toBe(original);
  });

  it("changes when a payload field is modified", () => {
    const pkg: SignedCapturePackage = vectors.package_vectors[0].package;
    const original = computeManifestHash(pkg);

    const alteredPayload = {
      ...pkg.payload,
      image_sha256:
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    const altered = { ...pkg, payload: alteredPayload };
    const tampered = computeManifestHash(altered);
    expect(tampered).not.toBe(original);
  });
});

describe("getPayloadCanonicalString", () => {
  it("matches the test vector's expected canonical output", () => {
    const vec = vectors.payload_vectors[0];
    const result = getPayloadCanonicalString(vec.payload);
    expect(result).toBe(vec.expected_canonical);
  });
});

// ---------------------------------------------------------------------------
// Package Structural Validation
// ---------------------------------------------------------------------------

describe("validatePackageStructure", () => {
  it("accepts a valid package", () => {
    const pkg = vectors.package_vectors[0].package;
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects null input", () => {
    const result = validatePackageStructure(null);
    expect(result.valid).toBe(false);
  });

  it("rejects wrong schema version", () => {
    const pkg = { ...vectors.package_vectors[0].package, schema_version: "2" };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("schema_version"))).toBe(true);
  });

  it("rejects missing signature", () => {
    const pkg = { ...vectors.package_vectors[0].package, signature: "" };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("signature"))).toBe(true);
  });

  it("rejects invalid image_sha256 in payload", () => {
    const pkg = {
      ...vectors.package_vectors[0].package,
      payload: {
        ...vectors.package_vectors[0].package.payload,
        image_sha256: "not-a-valid-hash",
      },
    };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("image_sha256"))).toBe(true);
  });

  it("rejects mismatched key_id", () => {
    const pkg = {
      ...vectors.package_vectors[0].package,
      key_id: "wrong-key-id",
    };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("key_id"))).toBe(true);
  });

  it("rejects missing payload", () => {
    const pkg = { ...vectors.package_vectors[0].package, payload: null };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
  });

  it("rejects missing challenge_nonce in payload", () => {
    const pkg = {
      ...vectors.package_vectors[0].package,
      payload: {
        ...vectors.package_vectors[0].package.payload,
        challenge_nonce: "",
      },
    };
    const result = validatePackageStructure(pkg);
    expect(result.valid).toBe(false);
  });
});
