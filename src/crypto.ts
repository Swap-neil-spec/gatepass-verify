import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
  type JsonWebKey,
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

/** P-256 public JWK. Only the public members are kept. */
export interface EcJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export function isEcJwk(value: unknown): value is EcJwk {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record["kty"] === "EC" &&
    record["crv"] === "P-256" &&
    typeof record["x"] === "string" &&
    typeof record["y"] === "string" &&
    record["x"].length > 0 &&
    record["y"].length > 0
  );
}

export function sha256Base64url(data: Uint8Array | string): string {
  return base64urlEncode(sha256(data));
}

/** PEM SubjectPublicKeyInfo, or a JSON JWK, for a P-256 public key. */
export function parseEcPublicKey(material: string): EcJwk | null {
  const trimmed = material.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!isEcJwk(parsed)) return null;
      return { kty: "EC", crv: "P-256", x: parsed.x, y: parsed.y };
    } catch {
      return null;
    }
  }
  if (trimmed.includes("BEGIN PUBLIC KEY")) {
    try {
      const exported = createPublicKey(trimmed).export({ format: "jwk" });
      if (!isEcJwk(exported)) return null;
      return { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
    } catch {
      return null;
    }
  }
  return null;
}

/** ES256, raw R || S, as used by compact JWS (RFC 7518). */
export function es256Verify(jwk: EcJwk, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  try {
    const key = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
    return verify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}
