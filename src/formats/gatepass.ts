import { CanonicalError, canonicalCodePoint } from "../canonical.js";
import {
  base64urlDecode,
  bytesOf,
  ed25519Verify,
  es256Verify,
  isLowerHex,
  parseEcPublicKey,
  parsePublicKey,
  sha256,
  sha256Base64url,
  sha256Hex,
  type EcJwk,
} from "../crypto.js";
import { fact, type EvidenceView } from "../facts.js";
import { labelFor, worstVerdict } from "../result.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord, parseTimestamp, sameBytes } from "../text.js";

/**
 * Profile for a GatePass decision record.
 * Field names here are the ones this verifier will check when a record carries them.
 * Unrecognized fields stay inside the signed bytes and are reported as not interpreted.
 */
export const GATEPASS_PROFILE = "gatepass-decision-record";

const GENESIS = "0".repeat(64);
const HASH_FIELDS = ["argsHash", "resolvedPathHash", "toolDefinitionHash"] as const;

interface Loaded {
  records: Record<string, unknown>[];
  witness: Record<string, unknown> | null;
  embeddedKey: string | null;
}

export function isGatepassDocument(value: unknown): boolean {
  return isRecord(value) && value["profile"] === GATEPASS_PROFILE;
}

export function verifyGatepass(value: unknown, _text: string, options: VerifyOptions): RecordResult[] {
  const loaded = load(value);
  if ("error" in loaded) return [malformed(loaded.error)];
  const now = options.now ?? new Date();
  const hashes: Array<string | null> = [];
  const results = loaded.records.map((record) => {
    const outcome = verifyOne(record, options, now);
    hashes.push(outcome.hash);
    return outcome.result;
  });
  applyChain(loaded.records, hashes, loaded.witness, results);
  return results;
}

export function describeGatepass(value: unknown, index: number): EvidenceView {
  const loaded = load(value);
  if ("error" in loaded) {
    return {
      approved: fact(loaded.error),
      approver: fact("The decision record could not be read."),
      when: fact("No time could be read."),
      executed: fact("No execution block could be read."),
      unsupported: ["decision record did not parse"],
    };
  }
  const record = loaded.records[index] ?? {};
  const approved = isRecord(record["approved"]) ? record["approved"] : null;
  const executed = isRecord(record["executed"]) ? record["executed"] : null;
  const mandate = isRecord(record["mandate"]) ? record["mandate"] : null;
  const approver = isRecord(record["approver"]) ? record["approver"] : null;
  return {
    approved: fact(
      approved ? "Approved tool and the hashes that were present." : "No approved block was in the record.",
      blockFields(approved),
    ),
    approver: fact(
      approver
        ? "Approver id from the record. The mandate signature, when present, is reported with the checks."
        : "No approver block was in the record.",
      {
        id: asString(approver?.["id"]),
        mandateSignature: mandate && typeof mandate["signature"] === "string" ? "present" : null,
      },
    ),
    when: fact("Times are the strings carried on the record.", {
      issuedAt: asString(record["issuedAt"]),
      expiresAt: asString(record["expiresAt"]) ?? asString(mandate?.["expiresAt"]),
    }),
    executed: fact(
      executed ? "Executed tool and hashes from the record. This is what the signer bound, not a live trace." : "No executed block was in the record.",
      blockFields(executed),
    ),
    unsupported: [
      "A witness URL is not contacted. Only a head hash and a length carried in the file can be compared.",
      "Fields this verifier does not know stay inside the signature and are not given a meaning.",
    ],
  };
}

function load(value: unknown): Loaded | { error: string } {
  if (!isRecord(value) || value["profile"] !== GATEPASS_PROFILE) {
    return { error: "gatepass decision record was not found" };
  }
  const witness = isRecord(value["witness"]) ? value["witness"] : null;
  if (Array.isArray(value["records"])) {
    if (value["records"].some((item) => !isRecord(item))) return { error: "records must be objects" };
    return {
      records: value["records"] as Record<string, unknown>[],
      witness,
      embeddedKey: null,
    };
  }
  return { records: [value], witness, embeddedKey: null };
}

function verifyOne(
  record: Record<string, unknown>,
  options: VerifyOptions,
  now: Date,
): { result: RecordResult; hash: string | null } {
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const id = asString(record["id"]);
  if (!id) {
    failures.push("malformed");
    checks.push({ name: "id", ok: false, detail: "id is required" });
  } else {
    checks.push({ name: "id", ok: true, detail: id });
  }
  const unrecognized = Object.keys(record).filter((key) => !KNOWN_RECORD.has(key) && key !== "profile" && key !== "witness" && key !== "records");
  if (unrecognized.length > 0) {
    checks.push({
      name: "extensions",
      ok: null,
      detail: `not interpreted, and still covered by the signature bytes: ${unrecognized.join(", ")}`,
    });
  }
  const hash = checkSignature(record, options, checks, failures);
  checkHashes(record, checks, failures);
  checkMaterials(record, checks, failures);
  checkMandate(record, now, options, checks, failures);
  checkRecordExpiry(record, now, checks, failures);
  const verdict = worstVerdict(failures);
  return {
    hash,
    result: {
      index: 0,
      id,
      format: "gatepass",
      verdict,
      label: labelFor(verdict),
      checks,
      summary: summary(verdict),
    },
  };
}

const KNOWN_RECORD = new Set([
  "profile",
  "id",
  "alg",
  "publicKey",
  "issuedAt",
  "expiresAt",
  "approver",
  "approved",
  "executed",
  "mandate",
  "chain",
  "signature",
  "materials",
  "witness",
  "records",
]);

function checkSignature(
  record: Record<string, unknown>,
  options: VerifyOptions,
  checks: Check[],
  failures: Verdict[],
): string | null {
  const alg = asString(record["alg"]);
  const signatureText = asString(record["signature"]);
  if (alg !== "Ed25519" && alg !== "ES256") {
    failures.push("malformed");
    checks.push({ name: "signature", ok: false, detail: "alg must be Ed25519 or ES256" });
    return null;
  }
  const signature = signatureText ? base64urlDecode(signatureText) : null;
  if (!signature) {
    failures.push("malformed");
    checks.push({ name: "signature", ok: false, detail: "signature must be base64url" });
    return null;
  }
  let payload = "";
  try {
    payload = canonicalCodePoint(without(record, ["signature"]));
  } catch (err) {
    const detail = err instanceof CanonicalError ? err.message : "canonicalization failed";
    failures.push("malformed");
    checks.push({ name: "signature", ok: false, detail });
    return null;
  }
  const ok = alg === "Ed25519"
    ? ed25519Ok(record["publicKey"], payload, signature)
    : es256Ok(record["publicKey"], payload, signature);
  if (!ok) {
    failures.push("tampered");
    checks.push({ name: "signature", ok: false, detail: `${alg} signature did not verify` });
  } else {
    checks.push({ name: "signature", ok: true, detail: `${alg} signature matches the public key on the record` });
  }
  const pinnedMaterial = options.keys?.["gatepass"];
  if (!pinnedMaterial) {
    checks.push({
      name: "pinned_key",
      ok: null,
      detail: "no pinned key supplied. The signature check uses the key on the record.",
    });
  } else if (!sameKey(record["publicKey"], pinnedMaterial, alg)) {
    failures.push("tampered");
    checks.push({ name: "pinned_key", ok: false, detail: "record public key does not match --key gatepass" });
  } else {
    checks.push({ name: "pinned_key", ok: true, detail: "record public key matches --key gatepass" });
  }
  if (!isRecord(record["chain"])) return null;
  try {
    const body = without(record, ["signature"]);
    const chain = without(record["chain"] as Record<string, unknown>, ["hash"]);
    body["chain"] = chain;
    return sha256Hex(canonicalCodePoint(body));
  } catch {
    return null;
  }
}

function checkHashes(record: Record<string, unknown>, checks: Check[], failures: Verdict[]): void {
  const approved = isRecord(record["approved"]) ? record["approved"] : null;
  const executed = isRecord(record["executed"]) ? record["executed"] : null;
  if (!approved && !executed) {
    checks.push({
      name: "approved_executed",
      ok: null,
      detail: "no approved or executed block was present",
    });
    return;
  }
  if (!approved || !executed) {
    checks.push({
      name: "approved_executed",
      ok: null,
      detail: "only one of approved and executed is present, so the pair was not compared",
    });
    return;
  }
  const approvedTool = asString(approved["tool"]);
  const executedTool = asString(executed["tool"]);
  if (approvedTool && executedTool && approvedTool !== executedTool) {
    failures.push("tampered");
    checks.push({ name: "tool", ok: false, detail: `approved tool ${approvedTool} and executed tool ${executedTool} differ` });
  } else if (approvedTool && executedTool) {
    checks.push({ name: "tool", ok: true, detail: approvedTool });
  }
  let compared = 0;
  for (const field of HASH_FIELDS) {
    const left = asString(approved[field]);
    const right = asString(executed[field]);
    if (!left && !right) {
      checks.push({ name: field, ok: null, detail: `${field} was not in the record` });
      continue;
    }
    if (!left || !right || !isLowerHex(left, 64) || !isLowerHex(right, 64)) {
      failures.push("malformed");
      checks.push({ name: field, ok: false, detail: `${field} must be 64 lowercase hex on both sides when either side has it` });
      continue;
    }
    compared += 1;
    if (left !== right) {
      failures.push("tampered");
      checks.push({ name: field, ok: false, detail: `approved ${field} and executed ${field} differ` });
    } else {
      checks.push({ name: field, ok: true, detail: `approved and executed ${field} match` });
    }
  }
  if (compared === 0) {
    checks.push({
      name: "approved_executed",
      ok: null,
      detail: "no args, resolved-path, or tool-definition hash was present on both sides",
    });
  }
}

function checkMaterials(record: Record<string, unknown>, checks: Check[], failures: Verdict[]): void {
  const materials = record["materials"];
  if (!isRecord(materials)) {
    checks.push({
      name: "preimage",
      ok: null,
      detail: "no preimage was supplied, so the stored hashes were compared with each other only",
    });
    return;
  }
  const approved = isRecord(record["approved"]) ? record["approved"] : null;
  const executed = isRecord(record["executed"]) ? record["executed"] : null;
  const pairs: Array<[string, unknown, string | null]> = [
    ["approved.argsHash", materials["approvedArgs"], asString(approved?.["argsHash"]) ?? null],
    ["executed.argsHash", materials["executedArgs"], asString(executed?.["argsHash"]) ?? null],
    ["approved.toolDefinitionHash", materials["approvedTool"], asString(approved?.["toolDefinitionHash"]) ?? null],
    ["executed.toolDefinitionHash", materials["executedTool"], asString(executed?.["toolDefinitionHash"]) ?? null],
  ];
  for (const [label, value, expected] of pairs) {
    if (value === undefined) continue;
    if (!expected) {
      failures.push("malformed");
      checks.push({ name: "preimage", ok: false, detail: `${label} preimage was supplied without a stored hash` });
      continue;
    }
    let digest = "";
    try {
      digest = sha256Hex(canonicalCodePoint(value));
    } catch (err) {
      const detail = err instanceof CanonicalError ? err.message : "preimage could not be canonicalized";
      failures.push("malformed");
      checks.push({ name: "preimage", ok: false, detail });
      continue;
    }
    if (digest !== expected) {
      failures.push("tampered");
      checks.push({ name: "preimage", ok: false, detail: `${label} does not match the stored hash` });
    } else {
      checks.push({ name: "preimage", ok: true, detail: `${label} matches the stored hash` });
    }
  }
  for (const [label, value, expected] of [
    ["approved.resolvedPathHash", materials["approvedPath"], asString(approved?.["resolvedPathHash"]) ?? null],
    ["executed.resolvedPathHash", materials["executedPath"], asString(executed?.["resolvedPathHash"]) ?? null],
  ] as const) {
    if (value === undefined) continue;
    if (typeof value !== "string" || !expected) {
      failures.push("malformed");
      checks.push({ name: "preimage", ok: false, detail: `${label} needs a path string and a stored hash` });
      continue;
    }
    const digest = sha256Hex(value);
    if (digest !== expected) {
      failures.push("tampered");
      checks.push({ name: "preimage", ok: false, detail: `${label} does not match the stored hash` });
    } else {
      checks.push({ name: "preimage", ok: true, detail: `${label} matches the stored hash` });
    }
  }
}

function checkMandate(
  record: Record<string, unknown>,
  now: Date,
  options: VerifyOptions,
  checks: Check[],
  failures: Verdict[],
): void {
  const mandate = record["mandate"];
  if (!isRecord(mandate)) {
    checks.push({ name: "mandate", ok: null, detail: "no mandate block was present" });
    return;
  }
  const core = without(mandate, ["signature", "clientDataJSON", "authenticatorData"]);
  let canonical = "";
  try {
    canonical = canonicalCodePoint(core);
  } catch (err) {
    const detail = err instanceof CanonicalError ? err.message : "mandate could not be canonicalized";
    failures.push("malformed");
    checks.push({ name: "mandate_signature", ok: false, detail });
    return;
  }
  const signature = asString(mandate["signature"]);
  const signatureBytes = signature ? base64urlDecode(signature) : null;
  if (!signatureBytes) {
    failures.push("malformed");
    checks.push({ name: "mandate_signature", ok: false, detail: "mandate signature must be base64url" });
    return;
  }
  const publicKey = mandate["publicKey"];
  const clientData = asString(mandate["clientDataJSON"]);
  const authData = asString(mandate["authenticatorData"]);
  if (clientData && authData) {
    checkPasskey(clientData, authData, signatureBytes, publicKey, canonical, options, checks, failures);
  } else if (es256Ok(publicKey, canonical, signatureBytes)) {
    checks.push({
      name: "mandate_signature",
      ok: true,
      detail: "ES256 signature matches the canonical mandate. authenticatorData was not supplied, so this is not a passkey ceremony check.",
    });
  } else if (ed25519Ok(publicKey, canonical, signatureBytes)) {
    checks.push({
      name: "mandate_signature",
      ok: true,
      detail: "Ed25519 signature matches the canonical mandate. This is not a passkey ceremony check.",
    });
  } else {
    failures.push("tampered");
    checks.push({ name: "mandate_signature", ok: false, detail: "mandate signature did not verify" });
  }
  const expires = asString(mandate["expiresAt"]);
  if (expires) {
    const at = parseTimestamp(expires);
    if (at === null) {
      failures.push("malformed");
      checks.push({ name: "mandate_expiry", ok: false, detail: "mandate expiresAt is not an ISO 8601 time" });
    } else if (now.getTime() >= at) {
      failures.push("expired");
      checks.push({ name: "mandate_expiry", ok: false, detail: "mandate is past expiresAt" });
    } else {
      checks.push({ name: "mandate_expiry", ok: true, detail: expires });
    }
  } else {
    checks.push({ name: "mandate_expiry", ok: null, detail: "mandate has no expiresAt" });
  }
  const executed = isRecord(record["executed"]) ? record["executed"] : null;
  if (!executed) {
    checks.push({ name: "mandate_scope", ok: null, detail: "no executed block to compare with the mandate" });
    return;
  }
  const scopes = Array.isArray(mandate["scopes"]) ? mandate["scopes"].filter((item) => typeof item === "string") : null;
  const tool = asString(executed["tool"]);
  if (!scopes) {
    checks.push({ name: "mandate_scope", ok: null, detail: "mandate has no scopes array" });
  } else if (!tool || !scopes.includes(tool)) {
    failures.push("widened");
    checks.push({ name: "mandate_scope", ok: false, detail: "executed tool is outside the mandate scopes" });
  } else {
    checks.push({ name: "mandate_scope", ok: true, detail: `${tool} is inside the mandate scopes` });
  }
  const caps = isRecord(mandate["caps"]) ? mandate["caps"] : null;
  if (!caps) {
    checks.push({ name: "mandate_cap", ok: null, detail: "mandate has no caps" });
    return;
  }
  const capAmount = caps["amount"];
  const spent = executed["amount"];
  if (typeof capAmount === "number" && typeof spent !== "number") {
    checks.push({
      name: "mandate_cap",
      ok: null,
      detail: "executed amount was not present, so the amount cap was not compared",
    });
  } else if (typeof capAmount === "number" && typeof spent === "number") {
    if (!Number.isSafeInteger(capAmount) || !Number.isSafeInteger(spent)) {
      failures.push("malformed");
      checks.push({ name: "mandate_cap", ok: false, detail: "amount cap and executed amount must be integers" });
    } else if (asString(caps["currency"]) && asString(executed["currency"]) && caps["currency"] !== executed["currency"]) {
      failures.push("widened");
      checks.push({ name: "mandate_cap", ok: false, detail: "executed currency differs from the mandate cap" });
    } else if (spent > capAmount) {
      failures.push("widened");
      checks.push({ name: "mandate_cap", ok: false, detail: `executed amount ${spent} is above cap ${capAmount}` });
    } else {
      checks.push({ name: "mandate_cap", ok: true, detail: `executed amount ${spent} is within cap ${capAmount}` });
    }
  }
  const capCount = caps["count"];
  const used = executed["count"];
  if (typeof capCount === "number" && typeof used !== "number") {
    checks.push({
      name: "mandate_count",
      ok: null,
      detail: "executed count was not present, so the count cap was not compared",
    });
  } else if (typeof capCount === "number" && typeof used === "number") {
    if (!Number.isSafeInteger(capCount) || !Number.isSafeInteger(used) || used > capCount) {
      failures.push(Number.isSafeInteger(capCount) && Number.isSafeInteger(used) ? "widened" : "malformed");
      checks.push({
        name: "mandate_count",
        ok: false,
        detail: `executed count ${String(used)} against cap ${String(capCount)}`,
      });
    } else {
      checks.push({ name: "mandate_count", ok: true, detail: `count ${used} is within cap ${capCount}` });
    }
  }
}

function checkPasskey(
  clientDataText: string,
  authDataText: string,
  signature: Buffer,
  publicKey: unknown,
  canonical: string,
  options: VerifyOptions,
  checks: Check[],
  failures: Verdict[],
): void {
  const clientRaw = decodeClientData(clientDataText);
  const authRaw = base64urlDecode(authDataText) ?? Buffer.from(authDataText, "utf8");
  if (!clientRaw || authRaw.length < 37) {
    failures.push("malformed");
    checks.push({ name: "mandate_signature", ok: false, detail: "passkey clientData or authenticatorData could not be read" });
    return;
  }
  let client: unknown;
  try {
    client = JSON.parse(clientRaw.toString("utf8")) as unknown;
  } catch {
    failures.push("malformed");
    checks.push({ name: "mandate_signature", ok: false, detail: "clientDataJSON is not JSON" });
    return;
  }
  if (!isRecord(client) || client["type"] !== "webauthn.get" || typeof client["challenge"] !== "string") {
    failures.push("malformed");
    checks.push({ name: "mandate_signature", ok: false, detail: "clientDataJSON must be a webauthn.get assertion with a challenge" });
    return;
  }
  const challenge = sha256Base64url(canonical);
  if (client["challenge"] !== challenge) {
    failures.push("tampered");
    checks.push({
      name: "mandate_signature",
      ok: false,
      detail: "passkey challenge is not the SHA-256 of the canonical mandate",
    });
    return;
  }
  const origin = asString(client["origin"]);
  if (options.audience && origin !== options.audience) {
    failures.push("malformed");
    checks.push({ name: "mandate_origin", ok: false, detail: `origin is ${origin ?? "missing"}, expected ${options.audience}` });
  }
  if (origin) {
    let host = "";
    try {
      host = new URL(origin).hostname;
    } catch {
      host = "";
    }
    const rpHash = authRaw.subarray(0, 32);
    if (!host || !sameBytes(rpHash, sha256(host))) {
      failures.push("tampered");
      checks.push({ name: "mandate_signature", ok: false, detail: "authenticatorData rpIdHash does not match the origin host" });
      return;
    }
  }
  if ((authRaw[32]! & 0x01) === 0) {
    failures.push("tampered");
    checks.push({ name: "mandate_signature", ok: false, detail: "authenticatorData user-present flag is not set" });
    return;
  }
  const message = Buffer.concat([authRaw, sha256(clientRaw)]);
  const jwk = ecFrom(publicKey);
  if (!jwk || !es256Verify(jwk, message, signature)) {
    failures.push("tampered");
    checks.push({ name: "mandate_signature", ok: false, detail: "passkey ES256 signature did not verify" });
    return;
  }
  checks.push({
    name: "mandate_signature",
    ok: true,
    detail: "passkey assertion verifies over authenticatorData and clientDataJSON, and the challenge binds the canonical mandate",
  });
}

function checkRecordExpiry(record: Record<string, unknown>, now: Date, checks: Check[], failures: Verdict[]): void {
  const expires = asString(record["expiresAt"]);
  if (!expires) return;
  const at = parseTimestamp(expires);
  if (at === null) {
    failures.push("malformed");
    checks.push({ name: "expiresAt", ok: false, detail: "expiresAt is not an ISO 8601 time" });
    return;
  }
  if (now.getTime() >= at) {
    failures.push("expired");
    checks.push({ name: "expiresAt", ok: false, detail: "record is past expiresAt" });
    return;
  }
  checks.push({ name: "expiresAt", ok: true, detail: expires });
}

function applyChain(
  records: Record<string, unknown>[],
  hashes: Array<string | null>,
  witness: Record<string, unknown> | null,
  results: RecordResult[],
): void {
  let broken = false;
  for (let i = 0; i < records.length; i += 1) {
    const chain = records[i]!["chain"];
    const result = results[i]!;
    if (!isRecord(chain)) {
      result.checks.push({
        name: "chain",
        ok: null,
        detail: "no chain block was present, so a missing tail cannot be seen",
      });
      continue;
    }
    const prev = asString(chain["prev"]);
    const claimed = asString(chain["hash"]);
    const computed = hashes[i];
    if (!prev || !isLowerHex(prev, 64) || !claimed || !isLowerHex(claimed, 64) || !computed) {
      broken = true;
      pushFailure(result, "malformed", "chain", "chain prev and hash must be 64 lowercase hex");
      continue;
    }
    if (claimed !== computed) {
      broken = true;
      pushFailure(result, "tampered", "chain", "chain hash does not match the canonical record");
      continue;
    }
    const expectedPrev = i === 0 ? null : hashes[i - 1];
    if (i === 0 && prev !== GENESIS && records.length > 1) {
      result.checks.push({
        name: "chain",
        ok: null,
        detail: "the first record does not start at the genesis hash. A missing prefix is not visible from a head witness.",
      });
    } else if (i > 0 && (broken || expectedPrev === null || prev !== expectedPrev)) {
      broken = true;
      pushFailure(result, "tampered", "chain", "prev does not match the previous record hash");
      continue;
    } else {
      const linked = i === 0 && prev === GENESIS ? "starts at the genesis hash" : "links to the previous hash";
      result.checks.push({ name: "chain", ok: true, detail: `seq ${String(chain["seq"])} ${linked}` });
    }
  }
  if (!witness) {
    for (const result of results) {
      result.checks.push({
        name: "witness",
        ok: null,
        detail: "no outside witness checkpoint was supplied, so a cut tail or a replayed head is not visible",
      });
    }
    return;
  }
  const head = hashes[hashes.length - 1];
  const expectedHead = asString(witness["headHash"]);
  const length = witness["length"];
  const logId = asString(witness["logId"]);
  let detail = "";
  let ok = true;
  let verdict: Verdict = "tampered";
  if (!logId || !expectedHead || !isLowerHex(expectedHead, 64) || typeof length !== "number" || !Number.isSafeInteger(length)) {
    ok = false;
    verdict = "malformed";
    detail = "witness needs logId, a 64 hex headHash, and an integer length";
  } else if (length !== records.length || head !== expectedHead) {
    ok = false;
    detail = "witness head does not match this chain. A shorter file and an older head fail this same check.";
  } else {
    detail = `witness log ${logId} matches head ${expectedHead.slice(0, 12)} and length ${length}. The checkpoint URL was not contacted.`;
  }
  for (const result of results) {
    if (!ok) pushFailure(result, verdict, "witness", detail);
    else result.checks.push({ name: "witness", ok: true, detail });
  }
}

function pushFailure(result: RecordResult, verdict: Verdict, name: string, detail: string): void {
  result.checks.push({ name, ok: false, detail });
  const next = worstVerdict([result.verdict, verdict]);
  result.verdict = next;
  result.label = labelFor(next);
  result.summary = summary(next);
}

function ed25519Ok(publicKey: unknown, payload: string, signature: Uint8Array): boolean {
  const raw = ed25519From(publicKey);
  if (!raw) return false;
  return ed25519Verify(raw, bytesOf(payload), signature);
}

function es256Ok(publicKey: unknown, payload: string, signature: Uint8Array): boolean {
  const jwk = ecFrom(publicKey);
  if (!jwk) return false;
  return es256Verify(jwk, bytesOf(payload), signature);
}

function ed25519From(value: unknown): Uint8Array | null {
  if (typeof value === "string") return parsePublicKey(value);
  return null;
}

function ecFrom(value: unknown): EcJwk | null {
  if (typeof value === "string") return parseEcPublicKey(value);
  if (!isRecord(value) || value["kty"] !== "EC" || value["crv"] !== "P-256") return null;
  if (typeof value["x"] !== "string" || typeof value["y"] !== "string") return null;
  return { kty: "EC", crv: "P-256", x: value["x"], y: value["y"] };
}

function sameKey(publicKey: unknown, material: string, alg: string): boolean {
  if (alg === "Ed25519") {
    const left = ed25519From(publicKey);
    const right = parsePublicKey(material);
    return Boolean(left && right && sameBytes(left, right));
  }
  const left = ecFrom(publicKey);
  const right = parseEcPublicKey(material);
  return Boolean(left && right && left.x === right.x && left.y === right.y);
}

function without(record: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!keys.includes(key)) out[key] = value;
  }
  return out;
}

function decodeClientData(value: string): Buffer | null {
  const decoded = base64urlDecode(value);
  if (decoded) return decoded;
  if (value.trim().startsWith("{")) return Buffer.from(value, "utf8");
  return null;
}

function blockFields(block: Record<string, unknown> | null): Record<string, string | number | boolean | null> {
  if (!block) return {};
  const fields: Record<string, string | number | boolean | null> = {};
  const tool = asString(block["tool"]);
  if (tool) fields["tool"] = tool;
  for (const name of HASH_FIELDS) {
    const value = asString(block[name]);
    if (value) fields[name] = value;
  }
  if (typeof block["amount"] === "number") fields["amount"] = block["amount"];
  const currency = asString(block["currency"]);
  if (currency) fields["currency"] = currency;
  return fields;
}

function summary(verdict: Verdict): string {
  if (verdict === "valid") return "Decision record passed the checks that were present.";
  if (verdict === "tampered") return "Decision record signature, hash, or witness head does not match.";
  if (verdict === "widened") return "Executed call is outside the mandate scope or cap.";
  if (verdict === "expired") return "Decision record or mandate is past its expiry.";
  return "Decision record is not well formed.";
}

function malformed(detail: string): RecordResult {
  return {
    index: 0,
    id: null,
    format: "gatepass",
    verdict: "malformed",
    label: labelFor("malformed"),
    checks: [{ name: "parse", ok: false, detail }],
    summary: detail,
  };
}
