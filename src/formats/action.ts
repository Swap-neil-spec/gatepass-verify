import { CanonicalError, canonicalJcs, hasNonIntegerNumber } from "../canonical.js";
import {
  base64urlDecode,
  bytesOf,
  ed25519Verify,
  isLowerHex,
  parsePublicKey,
  sha256Hex,
} from "../crypto.js";
import { labelFor, worstVerdict } from "../result.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord, parseTimestamp, sameBytes, utf16Sorted } from "../text.js";

const FIELDS = [
  "v",
  "action_id",
  "org_id",
  "session_id",
  "intent_hash",
  "agent",
  "tool",
  "args_hash",
  "outcome",
  "policy_applied",
  "timestamp",
  "public_key",
  "signature",
] as const;

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isActionDocument(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value["v"] === "action-1") return true;
  return isRecord(value["record"]) && value["record"]["v"] === "action-1";
}

function hashField(value: unknown, name: string, failures: Verdict[], checks: Check[]): string | null {
  const text = asString(value);
  if (text === null) {
    failures.push("malformed");
    checks.push({ name, ok: false, detail: "must be a string" });
    return null;
  }
  if (text !== "" && !isLowerHex(text, 64)) {
    failures.push("malformed");
    checks.push({ name, ok: false, detail: "must be empty or 64 lowercase hex characters" });
    return null;
  }
  return text;
}

function recordOf(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  if (value["v"] === "action-1") return value;
  if (isRecord(value["record"]) && value["record"]["v"] === "action-1") return value["record"];
  return null;
}

export function verifyAction(value: unknown, options: VerifyOptions): RecordResult[] {
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const record = recordOf(value);
  if (!record) {
    return [
      malformed(0, null, "ACTION-v1 record not found. The version tag must be the string action-1."),
    ];
  }

  const keys = Object.keys(record);
  const unknown = keys.filter((key) => !FIELDS.includes(key as (typeof FIELDS)[number]));
  if (unknown.length > 0) {
    failures.push("malformed");
    checks.push({
      name: "fields",
      ok: false,
      detail: `unknown fields: ${unknown.join(", ")}`,
    });
  }
  const missing = FIELDS.filter((key) => !(key in record));
  if (missing.length > 0) {
    failures.push("malformed");
    checks.push({
      name: "fields",
      ok: false,
      detail: `missing fields: ${missing.join(", ")}`,
    });
  } else if (unknown.length === 0) {
    checks.push({ name: "fields", ok: true, detail: "version action-1 field set" });
  }

  const version = record["v"];
  if (version !== "action-1") {
    failures.push("malformed");
    checks.push({ name: "version", ok: false, detail: "v must be the string action-1" });
  }

  const actionId = asString(record["action_id"]);
  if (actionId === null || !UUID.test(actionId)) {
    failures.push("malformed");
    checks.push({ name: "action_id", ok: false, detail: "must be a UUID" });
  }

  for (const name of ["org_id", "session_id", "agent"] as const) {
    if (asString(record[name]) === null) {
      failures.push("malformed");
      checks.push({ name, ok: false, detail: "must be a string" });
    }
  }

  const tool = asString(record["tool"]);
  if (tool === null || tool.length === 0) {
    failures.push("malformed");
    checks.push({ name: "tool", ok: false, detail: "must be a non-empty string" });
  }

  const outcome = asString(record["outcome"]);
  if (outcome !== "ALLOWED" && outcome !== "BLOCKED") {
    failures.push("malformed");
    checks.push({
      name: "outcome",
      ok: false,
      detail: "must be ALLOWED or BLOCKED",
    });
  } else {
    checks.push({
      name: "outcome",
      ok: true,
      detail: `${outcome}. This is the recorded decision, not a statement that the action ran.`,
    });
  }

  const intent = hashField(record["intent_hash"], "intent_hash", failures, checks);
  const argsHash = hashField(record["args_hash"], "args_hash", failures, checks);
  const sessionId = asString(record["session_id"]);
  if (sessionId === "" && intent !== null && intent !== "") {
    failures.push("malformed");
    checks.push({
      name: "intent_hash",
      ok: false,
      detail: "intent_hash must be empty when session_id is empty",
    });
  }

  const policy = record["policy_applied"];
  if (!Array.isArray(policy) || policy.some((item) => typeof item !== "string")) {
    failures.push("malformed");
    checks.push({ name: "policy_applied", ok: false, detail: "must be an array of strings" });
  } else if (!utf16Sorted(policy)) {
    failures.push("malformed");
    checks.push({
      name: "policy_applied",
      ok: false,
      detail: "must be sorted by UTF-16 code unit",
    });
  } else {
    checks.push({ name: "policy_applied", ok: true, detail: `${policy.length} policy ids` });
  }

  const timestamp = asString(record["timestamp"]);
  if (timestamp === null || parseTimestamp(timestamp) === null) {
    failures.push("malformed");
    checks.push({
      name: "timestamp",
      ok: false,
      detail: "must be an ISO 8601 datetime with an explicit offset",
    });
  }

  const publicKeyText = asString(record["public_key"]);
  const signatureText = asString(record["signature"]);
  const publicKey = publicKeyText ? base64urlDecode(publicKeyText) : null;
  const signature = signatureText ? base64urlDecode(signatureText) : null;
  if (!publicKey || publicKey.length !== 32) {
    failures.push("malformed");
    checks.push({ name: "public_key", ok: false, detail: "must be base64url of 32 bytes" });
  }
  if (!signature || signature.length !== 64) {
    failures.push("malformed");
    checks.push({ name: "signature", ok: false, detail: "must be base64url of 64 bytes" });
  }

  if (publicKey && publicKey.length === 32 && signature && signature.length === 64 && missing.length === 0 && unknown.length === 0) {
    let payload: string;
    try {
      const body: Record<string, unknown> = {};
      for (const key of FIELDS) {
        if (key === "signature") continue;
        body[key] = record[key];
      }
      payload = canonicalJcs(body);
    } catch (err) {
      const detail = err instanceof CanonicalError ? err.message : "canonicalization failed";
      failures.push("malformed");
      checks.push({ name: "signature", ok: false, detail });
      payload = "";
    }
    if (payload) {
      const signed = ed25519Verify(publicKey, bytesOf(payload), signature);
      if (!signed) {
        failures.push("tampered");
        checks.push({
          name: "signature",
          ok: false,
          detail: "Ed25519 signature does not verify against the embedded public key",
        });
      } else {
        checks.push({
          name: "signature",
          ok: true,
          detail:
            "Ed25519 signature matches the embedded public key. This is the integrity check. It does not pin an issuer.",
        });
      }
    }
  }

  const pinned = pinnedKey(options);
  if (pinned && publicKey && publicKey.length === 32) {
    if (!sameBytes(pinned, publicKey)) {
      failures.push("tampered");
      checks.push({
        name: "pinned_key",
        ok: false,
        detail: "embedded public key does not match the pinned key",
      });
    } else {
      checks.push({ name: "pinned_key", ok: true, detail: "embedded public key matches the pinned key" });
    }
  } else if (!pinned) {
    checks.push({
      name: "pinned_key",
      ok: null,
      detail: "no pinned issuer key supplied. The embedded-key check does not identify the issuer.",
    });
  }

  const args = isRecord(value) && value["v"] !== "action-1" ? value["args"] : undefined;
  if (args !== undefined) {
    if (hasNonIntegerNumber(args)) {
      failures.push("malformed");
      checks.push({
        name: "args_hash",
        ok: false,
        detail: "arguments contain a number this verifier will not hash",
      });
    } else {
      try {
        const digest = sha256Hex(bytesOf(canonicalJcs(args)));
        if (argsHash && digest === argsHash) {
          checks.push({ name: "args_hash", ok: true, detail: "supplied arguments match args_hash" });
        } else if (argsHash) {
          failures.push("tampered");
          checks.push({
            name: "args_hash",
            ok: false,
            detail: "supplied arguments do not match args_hash",
          });
        }
      } catch (err) {
        const detail = err instanceof CanonicalError ? err.message : "argument canonicalization failed";
        failures.push("malformed");
        checks.push({ name: "args_hash", ok: false, detail });
      }
    }
  } else if (argsHash && isLowerHex(argsHash, 64)) {
    checks.push({
      name: "args_hash",
      ok: null,
      detail: "argument preimage was not supplied, so args_hash was not recomputed",
    });
  }

  const verdict = worstVerdict(failures);
  const id = actionId && UUID.test(actionId) ? actionId : null;
  return [
    {
      index: 0,
      id,
      format: "action-v1",
      verdict,
      label: labelFor(verdict),
      checks,
      summary: summary(verdict, tool, outcome),
    },
  ];
}

function pinnedKey(options: VerifyOptions): Uint8Array | null {
  const material = options.keys?.["action-v1"];
  if (!material) return null;
  return parsePublicKey(material);
}

function summary(verdict: Verdict, tool: string | null, outcome: string | null): string {
  if (verdict === "malformed") return "ACTION-v1 record is not well formed.";
  if (verdict === "tampered") return "ACTION-v1 signature or argument binding failed.";
  const name = tool && tool.length > 0 ? tool : "action";
  const decision = outcome === "ALLOWED" || outcome === "BLOCKED" ? outcome : "recorded";
  return `${name} ${decision}. Integrity only: the signature matches the embedded key. An issuer pin is a separate check.`;
}

function malformed(index: number, id: string | null, detail: string): RecordResult {
  return {
    index,
    id,
    format: "action-v1",
    verdict: "malformed",
    label: labelFor("malformed"),
    checks: [{ name: "parse", ok: false, detail }],
    summary: detail,
  };
}
