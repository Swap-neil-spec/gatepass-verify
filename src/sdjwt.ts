import { base64urlDecode, base64urlEncode, bytesOf, es256Verify, sha256, type EcJwk } from "./crypto.js";
import { isRecord } from "./text.js";

const MAX_DEPTH = 64;

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

export interface SdJwtParts {
  issuerJwt: string;
  disclosures: string[];
  kbJwt: string | null;
}

export interface DecodedDisclosure {
  segment: string;
  digest: string;
  salt: string;
  /** Null for an array-element disclosure, which has no claim name. */
  name: string | null;
  value: unknown;
}

export interface ReconstructedSdJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  disclosures: DecodedDisclosure[];
}

export function readJwt(token: string): JwtParts | { error: string } {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return { error: "compact JWT must have three non-empty segments" };
  }
  const headerRaw = base64urlDecode(parts[0]!);
  const payloadRaw = base64urlDecode(parts[1]!);
  const signature = base64urlDecode(parts[2]!);
  if (!headerRaw || !payloadRaw || !signature) {
    return { error: "JWT segments are not base64url" };
  }
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(headerRaw.toString("utf8")) as unknown;
    payload = JSON.parse(payloadRaw.toString("utf8")) as unknown;
  } catch {
    return { error: "JWT header or payload is not JSON" };
  }
  if (!isRecord(header) || !isRecord(payload)) {
    return { error: "JWT header and payload must be objects" };
  }
  return {
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature,
  };
}

export function verifyEs256Jwt(token: string, jwk: EcJwk): { jwt: JwtParts } | { error: string } {
  const jwt = readJwt(token);
  if ("error" in jwt) return jwt;
  if (jwt.header["alg"] !== "ES256") {
    return { error: `JWT alg is ${String(jwt.header["alg"])}, and only ES256 is checked` };
  }
  const ok = es256Verify(jwk, bytesOf(jwt.signingInput), jwt.signature);
  if (!ok) return { error: "ES256 signature did not verify" };
  return { jwt };
}

export function disclosureDigest(segment: string): string {
  return base64urlEncode(sha256(segment));
}

/**
 * Split one SD-JWT.
 * A final compact JWT, when present, is the separate key-binding JWT from RFC 9901.
 * AP2 and Verifiable Intent put key binding in the issuer JWT of the hop, so their
 * disclosures stay disclosures: base64url does not contain ".".
 */
export function splitSdJwt(token: string): SdJwtParts | { error: string } {
  const trimmed = token.trim();
  if (trimmed.length === 0) return { error: "SD-JWT is empty" };
  const parts = trimmed.split("~");
  if (parts[parts.length - 1] === "") parts.pop();
  if (parts.length === 0 || parts[0]!.length === 0) return { error: "SD-JWT is missing the issuer JWT" };
  let kbJwt: string | null = null;
  const last = parts[parts.length - 1]!;
  if (parts.length > 1 && last.split(".").length === 3) {
    kbJwt = parts.pop() ?? null;
  }
  const issuerJwt = parts[0]!;
  if (issuerJwt.split(".").length !== 3) return { error: "SD-JWT issuer segment is not a compact JWT" };
  const disclosures = parts.slice(1);
  for (const disclosure of disclosures) {
    if (disclosure.length === 0 || disclosure.includes(".")) {
      return { error: "SD-JWT disclosure is not one base64url segment" };
    }
  }
  return { issuerJwt, disclosures, kbJwt };
}

/**
 * Split a `~~` mandate chain.
 * `String.split("~~")` treats the SD-JWT terminator plus the separator (`~~~`)
 * as a separator starting at the first tilde, and leaves the terminator on the
 * next hop. That tilde is moved back onto the previous hop.
 */
export function splitChain(input: string): string[] | { error: string } {
  const trimmed = input.trim();
  if (trimmed.length === 0) return { error: "mandate chain is empty" };
  const parts = trimmed.split("~~");
  for (let i = 1; i < parts.length; i += 1) {
    const part = parts[i]!;
    if (part.startsWith("~")) {
      parts[i - 1] = `${parts[i - 1]}~`;
      parts[i] = part.slice(1);
    }
  }
  if (parts.some((part) => part.length === 0)) return { error: "mandate chain has an empty hop" };
  return parts;
}

function decodeDisclosure(segment: string): DecodedDisclosure | { error: string } {
  const raw = base64urlDecode(segment);
  if (!raw) return { error: "disclosure is not base64url" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8")) as unknown;
  } catch {
    return { error: "disclosure is not JSON" };
  }
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    return { error: "disclosure must be a JSON array of two or three elements" };
  }
  if (typeof parsed[0] !== "string" || parsed[0].length === 0) {
    return { error: "disclosure salt must be a non-empty string" };
  }
  if (parsed.length === 2) {
    return {
      segment,
      digest: disclosureDigest(segment),
      salt: parsed[0],
      name: null,
      value: parsed[1],
    };
  }
  if (typeof parsed[1] !== "string" || parsed[1].length === 0) {
    return { error: "disclosure claim name must be a non-empty string" };
  }
  return {
    segment,
    digest: disclosureDigest(segment),
    salt: parsed[0],
    name: parsed[1],
    value: parsed[2],
  };
}

function isDigestRef(value: unknown): value is { "...": string } {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 1 && keys[0] === "..." && typeof value["..."] === "string";
}

/**
 * Reconstruct disclosed claims.
 * Digests listed in `_sd` and not supplied stay hidden. That is selective disclosure.
 * A supplied disclosure whose digest is not referenced is an error.
 */
export function reconstructSdJwt(parts: SdJwtParts): ReconstructedSdJwt | { error: string } {
  const jwt = readJwt(parts.issuerJwt);
  if ("error" in jwt) return jwt;
  const decoded: DecodedDisclosure[] = [];
  const byDigest = new Map<string, DecodedDisclosure>();
  for (const segment of parts.disclosures) {
    const disclosure = decodeDisclosure(segment);
    if ("error" in disclosure) return disclosure;
    if (byDigest.has(disclosure.digest)) return { error: "duplicate disclosure digest" };
    byDigest.set(disclosure.digest, disclosure);
    decoded.push(disclosure);
  }
  const used = new Set<string>();
  let payload: unknown;
  try {
    payload = reveal(jwt.payload, byDigest, used, 0);
  } catch (err) {
    return { error: err instanceof Error ? err.message : "disclosure reconstruction failed" };
  }
  if (!isRecord(payload)) return { error: "reconstructed payload is not an object" };
  for (const disclosure of decoded) {
    if (!used.has(disclosure.digest)) return { error: "disclosure is not bound by a hash in the payload" };
  }
  return { header: jwt.header, payload, disclosures: decoded };
}

function reveal(
  value: unknown,
  byDigest: Map<string, DecodedDisclosure>,
  used: Set<string>,
  depth: number,
): unknown {
  if (depth > MAX_DEPTH) throw new Error("SD-JWT exceeds the nesting limit");
  if (Array.isArray(value)) {
    return value.map((item) => revealItem(item, byDigest, used, depth));
  }
  if (!isRecord(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value)) {
    if (key === "_sd") continue;
    out[key] = reveal(inner, byDigest, used, depth + 1);
  }
  const sd = value["_sd"];
  if (sd !== undefined) {
    if (!Array.isArray(sd) || sd.some((item) => typeof item !== "string")) {
      throw new Error("_sd must be an array of digest strings");
    }
    for (const digest of sd) {
      const disclosure = byDigest.get(digest);
      if (!disclosure) continue;
      if (disclosure.name === null) throw new Error("object disclosure is missing a claim name");
      if (disclosure.name === "_sd" || disclosure.name === "...") {
        throw new Error("disclosure claim name is reserved");
      }
      if (Object.prototype.hasOwnProperty.call(out, disclosure.name)) {
        throw new Error(`disclosure repeats claim ${disclosure.name}`);
      }
      used.add(digest);
      out[disclosure.name] = reveal(disclosure.value, byDigest, used, depth + 1);
    }
  }
  return out;
}

function revealItem(
  item: unknown,
  byDigest: Map<string, DecodedDisclosure>,
  used: Set<string>,
  depth: number,
): unknown {
  if (!isDigestRef(item)) return reveal(item, byDigest, used, depth + 1);
  const disclosure = byDigest.get(item["..."]);
  if (!disclosure) return item;
  if (disclosure.name !== null) throw new Error("array disclosure must not carry a claim name");
  used.add(item["..."]);
  return reveal(disclosure.value, byDigest, used, depth + 1);
}
