/**
 * SHA-256 hashing utilities for ProofCam.
 *
 * Critical rule: hash the EXACT file bytes. Do not resize, re-encode,
 * strip EXIF, or normalize before hashing. Two visually identical images
 * with different bytes will (correctly) produce different hashes.
 *
 * Display format: lowercase hexadecimal, consistently.
 */

import { createHash } from "node:crypto";
import { SHA256_HEX_LENGTH } from "./types.js";

/**
 * Compute SHA-256 hash of raw bytes.
 *
 * @param data - Exact file bytes (Buffer or Uint8Array).
 * @returns Lowercase hexadecimal SHA-256 digest (64 characters).
 */
export function sha256(data: Uint8Array | Buffer): string {
  const hash = createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

/**
 * Compute SHA-256 hash of a UTF-8 string.
 * Useful for hashing canonical JSON payload/package bytes.
 *
 * @param text - UTF-8 string to hash.
 * @returns Lowercase hexadecimal SHA-256 digest (64 characters).
 */
export function sha256String(text: string): string {
  return sha256(Buffer.from(text, "utf-8"));
}

/**
 * Compute SHA-256 hash from a file path.
 * Reads the entire file into memory — use for files within MAX_UPLOAD_BYTES.
 *
 * @param filePath - Absolute path to the file.
 * @returns Lowercase hexadecimal SHA-256 digest (64 characters).
 */
export async function sha256File(filePath: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const data = await readFile(filePath);
  return sha256(data);
}

/**
 * Validate that a string is a well-formed SHA-256 hex digest.
 *
 * @param hash - String to validate.
 * @returns true if it's a valid 64-character lowercase hex string.
 */
export function isValidSha256Hex(hash: string): boolean {
  if (typeof hash !== "string") return false;
  if (hash.length !== SHA256_HEX_LENGTH) return false;
  return /^[0-9a-f]{64}$/.test(hash);
}

/**
 * Convert a hex string to a Uint8Array of bytes.
 *
 * @param hex - Lowercase hex string (must have even length).
 * @returns Byte array.
 * @throws {Error} If the hex string is invalid.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error("Hex string must contain only lowercase hex characters");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a lowercase hex string.
 *
 * @param bytes - Byte array.
 * @returns Lowercase hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
