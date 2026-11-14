/** JSON canonicalization used by the formats this verifier reads. */

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalError";
  }
}

export type CanonicalMode = "jcs" | "codepoint";

const MAX_DEPTH = 64;

function compareUtf16(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function compareCodePoint(a: string, b: string): number {
  const left = Array.from(a);
  const right = Array.from(b);
  const count = Math.min(left.length, right.length);
  for (let i = 0; i < count; i += 1) {
    const diff = left[i]!.codePointAt(0)! - right[i]!.codePointAt(0)!;
    if (diff !== 0) return diff;
  }
  return left.length - right.length;
}

function escapeString(value: string, jcs: boolean): string {
  let out = '"';
  for (const ch of value) {
    const cp = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, "0")}`;
    else if (jcs && (cp === 0x2028 || cp === 0x2029)) {
      out += `\\u${cp.toString(16).padStart(4, "0")}`;
    } else out += ch;
  }
  out += '"';
  return out;
}

function write(value: unknown, mode: CanonicalMode, depth: number): string {
  if (depth > MAX_DEPTH) throw new CanonicalError("JSON exceeds the nesting limit");
  const jcs = mode === "jcs";
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new CanonicalError("only safe integers can be canonicalized");
    }
    return String(value);
  }
  if (typeof value === "string") return escapeString(value, jcs);
  if (Array.isArray(value)) {
    return `[${value.map((item) => write(item, mode, depth + 1)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(jcs ? compareUtf16 : compareCodePoint);
    const parts = keys.map(
      (key) => `${escapeString(key, jcs)}:${write(record[key], mode, depth + 1)}`,
    );
    return `{${parts.join(",")}}`;
  }
  throw new CanonicalError("value cannot be canonicalized");
}

/** RFC 8785 key order and escapes. Numbers must be safe integers. */
export function canonicalJcs(value: unknown): string {
  return write(value, "jcs", 0);
}

/**
 * Sorted by Unicode code point, compact separators, UTF-8, no ASCII escaping.
 * This matches the Keel payload profile and the flight-recorder canonical form.
 */
export function canonicalCodePoint(value: unknown): string {
  return write(value, "codepoint", 0);
}

const VOLATILE = new Set([
  "requestid",
  "traceid",
  "spanid",
  "idempotencykey",
  "keelrequestid",
  "xrequestid",
  "xkeeltimestamp",
  "timestamp",
  "keelidempotencykey",
]);

const SENSITIVE = new Set([
  "authorization",
  "apikey",
  "xapikey",
  "openaiapikey",
  "anthropicapikey",
  "xgoogapikey",
  "proxyauthorization",
]);

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Strip Keel volatile and credential keys, then return a JSON-ready value. */
export function stripWireBody(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new CanonicalError("JSON exceeds the nesting limit");
  if (Array.isArray(value)) return value.map((item) => stripWireBody(item, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      const normalized = normalizeKey(key);
      if (VOLATILE.has(normalized) || SENSITIVE.has(normalized)) continue;
      out[key] = stripWireBody(inner, depth + 1);
    }
    return out;
  }
  return value;
}

/** True when any number in the tree is not a safe integer. */
export function hasNonIntegerNumber(value: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true;
  if (typeof value === "number") return !Number.isSafeInteger(value) || Object.is(value, -0);
  if (Array.isArray(value)) return value.some((item) => hasNonIntegerNumber(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some((item) =>
      hasNonIntegerNumber(item, depth + 1),
    );
  }
  return false;
}
