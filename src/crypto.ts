import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function sha256(data: Uint8Array | string): Buffer {
  const hash = createHash("sha256");
  hash.update(data);
  return hash.digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return sha256(data).toString("hex");
}

export function bytesOf(text: string): Buffer {
  return Buffer.from(text, "utf8");
}

export function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function base64urlDecode(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const buf = Buffer.from(value, "base64url");
  if (buf.length === 0) return null;
  return buf;
}

/** Standard base64, no whitespace. Used by Keel revocation signatures. */
export function base64Decode(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  if (value.length % 4 !== 0) return null;
  const buf = Buffer.from(value, "base64");
  if (buf.length === 0) return null;
  return buf;
}

export function ed25519KeyFromRaw(raw: Uint8Array): KeyObject | null {
  if (raw.length !== 32) return null;
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
      format: "der",
      type: "spki",
    });
  } catch {
    return null;
  }
}

export function parsePublicKey(material: string): Uint8Array | null {
  const trimmed = material.trim();
  if (trimmed.includes("BEGIN PUBLIC KEY")) {
    try {
      const key = createPublicKey(trimmed);
      const der = key.export({ format: "der", type: "spki" });
      const buf = Buffer.from(der);
      if (buf.length !== ED25519_SPKI_PREFIX.length + 32) return null;
      if (!buf.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) return null;
      return buf.subarray(ED25519_SPKI_PREFIX.length);
    } catch {
      return null;
    }
  }
  const raw = base64urlDecode(trimmed);
  if (!raw || raw.length !== 32) return null;
  return raw;
}

export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  const key = ed25519KeyFromRaw(publicKey);
  if (!key) return false;
  try {
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

export function hexEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export function isLowerHex(value: string, chars: number): boolean {
  return new RegExp(`^[0-9a-f]{${chars}}$`).test(value);
}
