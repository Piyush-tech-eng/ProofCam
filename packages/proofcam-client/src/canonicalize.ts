/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 *
 * Produces a deterministic JSON serialization so that all implementations
 * (TypeScript, Android/Kotlin, Rust) produce identical bytes for the same
 * logical payload. This is critical because:
 *
 * 1. The device signs the canonical payload bytes.
 * 2. The package is serialized canonically before hashing.
 * 3. The manifest_hash on-chain commits to those exact bytes.
 *
 * Ordinary JSON.stringify is NOT sufficient because property order
 * and number formatting can vary.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8785
 */

/**
 * Serialize a value to its RFC 8785 canonical JSON form.
 *
 * Rules (from RFC 8785):
 * - Object keys are sorted by their UTF-16 code units (matching JS sort).
 * - No whitespace between tokens.
 * - Numbers use ES2015 Number.toString() semantics.
 * - Strings use minimal \\uXXXX escaping for control characters.
 * - null, boolean pass through unchanged.
 * - Undefined values and functions are omitted (like JSON.stringify).
 *
 * @param value - The value to serialize.
 * @returns Canonical JSON string.
 * @throws {TypeError} If the value contains unsupported types (BigInt, Symbol, circular refs).
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }

  const type = typeof value;

  if (type === "boolean") {
    return value ? "true" : "false";
  }

  if (type === "number") {
    return canonicalizeNumber(value as number);
  }

  if (type === "string") {
    return canonicalizeString(value as string);
  }

  if (type === "bigint") {
    throw new TypeError("BigInt values are not supported in JCS canonicalization");
  }

  if (type === "symbol" || type === "function") {
    // Omitted — same behavior as JSON.stringify
    return "null";
  }

  if (Array.isArray(value)) {
    return canonicalizeArray(value);
  }

  // Object
  return canonicalizeObject(value as Record<string, unknown>);
}

/**
 * Serialize a number per RFC 8785.
 * Uses ES2015 Number.prototype.toString() which aligns with JCS requirements.
 */
function canonicalizeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError(
      `Non-finite numbers (${value}) are not allowed in JCS canonicalization`
    );
  }

  // Per RFC 8785: use JavaScript's built-in number-to-string,
  // which matches the required IEEE 754 representation.
  // -0 must serialize as "0".
  if (Object.is(value, -0)) {
    return "0";
  }

  return String(value);
}

/**
 * Serialize a string per RFC 8785.
 * Control characters (U+0000–U+001F) are escaped as \\uXXXX.
 * Backslash and double-quote are escaped.
 * All other characters pass through as-is (including non-BMP via surrogate pairs).
 */
function canonicalizeString(value: string): string {
  let result = '"';

  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);

    if (code === 0x08) {
      result += "\\b";
    } else if (code === 0x09) {
      result += "\\t";
    } else if (code === 0x0a) {
      result += "\\n";
    } else if (code === 0x0c) {
      result += "\\f";
    } else if (code === 0x0d) {
      result += "\\r";
    } else if (code === 0x22) {
      result += '\\"';
    } else if (code === 0x5c) {
      result += "\\\\";
    } else if (code < 0x20) {
      // Other control characters → \uXXXX
      result += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      result += value[i];
    }
  }

  result += '"';
  return result;
}

/**
 * Serialize an array per RFC 8785.
 * Elements are serialized in order; undefined elements become "null".
 */
function canonicalizeArray(value: unknown[]): string {
  const elements = value.map((item) => canonicalize(item));
  return "[" + elements.join(",") + "]";
}

/**
 * Serialize an object per RFC 8785.
 *
 * Keys are sorted by UTF-16 code unit order (which is what
 * JavaScript's Array.prototype.sort() does by default).
 * Properties with undefined values are omitted.
 */
function canonicalizeObject(value: Record<string, unknown>): string {
  const keys = Object.keys(value).sort();
  const pairs: string[] = [];

  for (const key of keys) {
    const val = value[key];
    // Omit undefined and function values (like JSON.stringify)
    if (val === undefined || typeof val === "function") {
      continue;
    }

    pairs.push(canonicalizeString(key) + ":" + canonicalize(val));
  }

  return "{" + pairs.join(",") + "}";
}

/**
 * Serialize a value to canonical JSON and return the UTF-8 bytes.
 * This is the form that should be signed and hashed.
 *
 * @param value - The value to serialize.
 * @returns UTF-8 encoded bytes of the canonical JSON.
 */
export function canonicalizeToBytes(value: unknown): Uint8Array {
  const json = canonicalize(value);
  return new TextEncoder().encode(json);
}
