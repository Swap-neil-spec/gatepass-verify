import { CanonicalError, canonicalJcs, hasNonIntegerNumber } from "../canonical.js";
import {
  base64urlDecode,
  base64urlEncode,
  bytesOf,
  ed25519Verify,
  parsePublicKey,
  sha256,
} from "../crypto.js";
import { labelFor, worstVerdict } from "../result.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord, parseJson } from "../text.js";

const LEVELS = new Set(["HAPS-PoHP-1", "HAPS-PoHP-2", "HAPS-PoHP-3", "HAPS-PoHP-4"]);

export function isHapsDocument(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value["profile"] === "haps-v0.4") return true;
  if (
    (value["format"] === "jwt" || value["format"] === "vc+json") &&
    isRecord(value["claims"])
  ) {
    return true;
  }
  return isClaims(value) || isClaims(value["claims"]);
}

function isClaims(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value["intent_hash"] === "string" &&
    typeof value["jti"] === "string" &&
    typeof value["aud"] === "string" &&
    typeof value["exp"] === "number"
  );
}

function claimsOf(value: Record<string, unknown>): Record<string, unknown> | null {
  if (isRecord(value["claims"]) && typeof value["claims"]["intent_hash"] === "string") {
    return value["claims"];
  }
  if (isClaims(value)) return value;
  return null;
}

function intentHash(action: unknown): string {
  return `sha256:${base64urlEncode(sha256(bytesOf(canonicalJcs(action))))}`;
}

export function verifyHaps(value: unknown, options: VerifyOptions): RecordResult[] {
  if (!isRecord(value)) {
    return [one(0, null, "malformed", [{ name: "parse", ok: false, detail: "HAPS input must be a JSON object" }], "HAPS input must be a JSON object.")];
  }
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const claims = claimsOf(value);
  if (!claims) {
    return [
      one(
        0,
        null,
        "malformed",
        [{ name: "claims", ok: false, detail: "intent_hash, jti, aud, and exp are required" }],
        "HAPS claims are missing required fields.",
      ),
    ];
  }

  const jti = asString(claims["jti"]);
  if (!jti || jti.length < 8) {
    failures.push("malformed");
    checks.push({ name: "jti", ok: false, detail: "jti must be a string of at least 8 characters" });
  } else {
    checks.push({ name: "jti", ok: true, detail: "present. Single-use replay state is not checked offline." });
  }

  const aud = asString(claims["aud"]);
  if (!aud || aud.length < 3) {
    failures.push("malformed");
    checks.push({ name: "aud", ok: false, detail: "aud must be a non-empty audience" });
  } else if (options.audience && options.audience !== aud) {
    failures.push("malformed");
    checks.push({
      name: "aud",
      ok: false,
      detail: `audience is ${aud}, expected ${options.audience}`,
    });
  } else {
    checks.push({ name: "aud", ok: true, detail: aud });
  }

  const intent = asString(claims["intent_hash"]);
  if (!intent || !/^sha256:[A-Za-z0-9_-]{16,}$/.test(intent)) {
    failures.push("malformed");
    checks.push({ name: "intent_hash", ok: false, detail: "intent_hash must be sha256: and base64url" });
  }

  const presentation = asString(claims["presentation_hash"]);
  if (!presentation || !/^sha256:[A-Za-z0-9_-]{16,}$/.test(presentation)) {
    failures.push("malformed");
    checks.push({
      name: "presentation_hash",
      ok: false,
      detail: "presentation_hash must be sha256: and base64url",
    });
  }

  const exp = claims["exp"];
  const now = options.now ?? new Date();
  if (typeof exp !== "number" || !Number.isSafeInteger(exp)) {
    failures.push("malformed");
    checks.push({ name: "exp", ok: false, detail: "exp must be an integer unix time" });
  } else if (now.getTime() >= exp * 1000) {
    failures.push("expired");
    checks.push({ name: "exp", ok: false, detail: `expired at unix ${exp}` });
  } else {
    checks.push({ name: "exp", ok: true, detail: `expires at unix ${exp}` });
  }

  const assurance = claims["assurance"];
  if (!isRecord(assurance) || !LEVELS.has(String(assurance["level"])) || typeof assurance["method"] !== "string") {
    failures.push("malformed");
    checks.push({
      name: "assurance",
      ok: false,
      detail: "assurance.level and assurance.method are required. The factor itself is not checked.",
    });
  } else {
    checks.push({
      name: "assurance",
      ok: null,
      detail: `${String(assurance["level"])} via ${String(assurance["method"])}. Presence factors are not checked.`,
    });
  }

  const action = value["action"];
  if (action === undefined) {
    failures.push("malformed");
    checks.push({
      name: "intent_hash",
      ok: false,
      detail: "action intent was not supplied, so the binding cannot be checked",
    });
  } else if (hasNonIntegerNumber(action)) {
    failures.push("malformed");
    checks.push({
      name: "intent_hash",
      ok: false,
      detail: "action intent contains a non-integer number. HAPS rejects that before hashing.",
    });
  } else if (intent) {
    try {
      const computed = intentHash(action);
      if (computed === intent) {
        checks.push({ name: "intent_hash", ok: true, detail: "action intent matches intent_hash" });
      } else {
        failures.push("tampered");
        checks.push({
          name: "intent_hash",
          ok: false,
          detail: "action intent does not match intent_hash",
        });
      }
    } catch (err) {
      const detail = err instanceof CanonicalError ? err.message : "intent canonicalization failed";
      failures.push("malformed");
      checks.push({ name: "intent_hash", ok: false, detail });
    }
  }

  if (value["presentation"] !== undefined && presentation) {
    try {
      if (hasNonIntegerNumber(value["presentation"])) {
        failures.push("malformed");
        checks.push({
          name: "presentation_hash",
          ok: false,
          detail: "signing view contains a non-integer number",
        });
      } else {
        const computed = intentHash(value["presentation"]);
        if (computed === presentation) {
          checks.push({
            name: "presentation_hash",
            ok: true,
            detail: "signing view matches presentation_hash. This does not show what a person saw.",
          });
        } else {
          failures.push("tampered");
          checks.push({
            name: "presentation_hash",
            ok: false,
            detail: "signing view does not match presentation_hash",
          });
        }
      }
    } catch (err) {
      const detail = err instanceof CanonicalError ? err.message : "signing view canonicalization failed";
      failures.push("malformed");
      checks.push({ name: "presentation_hash", ok: false, detail });
    }
  }

  verifyCredential(value, claims, options, checks, failures);

  const verdict = worstVerdict(failures);
  return [one(0, jti, verdict, checks, hapsSummary(verdict))];
}

function verifyCredential(
  value: Record<string, unknown>,
  claims: Record<string, unknown>,
  options: VerifyOptions,
  checks: Check[],
  failures: Verdict[],
): void {
  const credential = asString(value["credential"]);
  if (!credential) {
    checks.push({
      name: "provider_signature",
      ok: null,
      detail: "provider signature not checked. No credential and no key were supplied.",
    });
    return;
  }
  const parts = credential.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    failures.push("malformed");
    checks.push({ name: "provider_signature", ok: false, detail: "credential is not a compact JWS" });
    return;
  }
  const headerBytes = base64urlDecode(parts[0]!);
  const payloadBytes = base64urlDecode(parts[1]!);
  const signature = base64urlDecode(parts[2]!);
  if (!headerBytes || !payloadBytes || !signature) {
    failures.push("malformed");
    checks.push({ name: "provider_signature", ok: false, detail: "JWS segments are not base64url" });
    return;
  }
  let header: unknown;
  let payload: unknown;
  try {
    header = parseJson(headerBytes.toString("utf8"));
    payload = parseJson(payloadBytes.toString("utf8"));
  } catch {
    failures.push("malformed");
    checks.push({ name: "provider_signature", ok: false, detail: "JWS header or payload is not JSON" });
    return;
  }
  if (!isRecord(header) || header["alg"] !== "EdDSA") {
    failures.push("malformed");
    checks.push({
      name: "provider_signature",
      ok: false,
      detail: "only an EdDSA JWS can be checked. Other algorithms are unsupported.",
    });
    return;
  }
  const keys = Object.values(options.keys ?? {})
    .map((material) => parsePublicKey(material))
    .filter((key): key is Uint8Array => key !== null);
  if (keys.length === 0) {
    checks.push({
      name: "provider_signature",
      ok: null,
      detail: "provider signature not checked. A credential was supplied without a key.",
    });
    return;
  }
  const message = bytesOf(`${parts[0]}.${parts[1]}`);
  const ok = keys.some((key) => ed25519Verify(key, message, signature));
  if (!ok) {
    failures.push("tampered");
    checks.push({
      name: "provider_signature",
      ok: false,
      detail: "EdDSA credential did not verify with a supplied key",
    });
    return;
  }
  if (!sameJson(payload, claims)) {
    failures.push("tampered");
    checks.push({
      name: "provider_signature",
      ok: false,
      detail: "signed payload does not match the claims object",
    });
    return;
  }
  checks.push({
    name: "provider_signature",
    ok: true,
    detail: "EdDSA credential verified with a supplied key. Biometric evidence was not checked.",
  });
}

function sameJson(left: unknown, right: unknown): boolean {
  try {
    return canonicalJcs(left) === canonicalJcs(right);
  } catch {
    return false;
  }
}

function hapsSummary(verdict: Verdict): string {
  if (verdict === "valid") {
    return "HAPS claims bind the supplied action. Provider and biometric checks were not required for this result.";
  }
  if (verdict === "tampered") return "HAPS action binding or supplied credential check failed.";
  if (verdict === "expired") return "HAPS credential is past exp.";
  return "HAPS input is not well formed.";
}

function one(
  index: number,
  id: string | null,
  verdict: Verdict,
  checks: Check[],
  summary: string,
): RecordResult {
  return {
    index,
    id,
    format: "haps",
    verdict,
    label: labelFor(verdict),
    checks,
    summary,
  };
}
