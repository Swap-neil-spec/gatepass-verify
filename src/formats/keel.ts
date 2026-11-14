import {
  CanonicalError,
  canonicalCodePoint,
  stripWireBody,
} from "../canonical.js";
import {
  base64Decode,
  bytesOf,
  ed25519Verify,
  hexEqual,
  isLowerHex,
  parsePublicKey,
  sha256Hex,
} from "../crypto.js";
import { labelFor, worstVerdict } from "../result.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord, isUuid, parseTimestamp } from "../text.js";

const PERMIT_FIELDS = new Set([
  "id",
  "project_id",
  "decision",
  "reason",
  "actions_json",
  "subject_type",
  "subject_id",
  "action_name",
  "resource_provider",
  "resource_model",
  "estimated_input_tokens",
  "estimated_output_tokens",
  "request_fingerprint",
  "idempotency_key",
  "policy_id",
  "policy_version",
  "created_at",
  "binding_request_hash",
  "parent_permit_id",
  "delegation_depth",
  "authority_envelope",
  "authority_envelope_version",
  "expires_at",
  "decision_details",
  "status",
  "constraints_json",
]);

const ENVELOPE_FIELDS = [
  "actions",
  "tools",
  "providers",
  "models",
  "data_classes",
  "regions",
  "expires_at",
] as const;

const REVOCATION_FIELDS = [
  "permit_id",
  "project_id",
  "actor_id",
  "actor_kind",
  "reason_code",
  "revoked_at",
  "effective_at",
  "signature",
] as const;

const ACTOR_KINDS = new Set(["user", "service_account", "system", "api_key"]);

export function isKeelDocument(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value["profile"] === "draft-munoz-scitt-permit-profile-01") return true;
  if (Array.isArray(value["permits"])) return true;
  return isPermit(value);
}

function isPermit(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value["id"] === "string" &&
    typeof value["decision"] === "string" &&
    "binding_request_hash" in value
  );
}

interface Revocation {
  permitId: string;
  projectId: string;
  verified: boolean;
  detail: string;
}

type Relation = "equal" | "narrower" | "widened";

export function verifyKeel(value: unknown, options: VerifyOptions): RecordResult[] {
  const bundle = normalize(value);
  if ("error" in bundle) return [malformed(0, null, bundle.error)];

  const keys = collectKeys(bundle.keys, options);
  const revocations = bundle.revocations.map((event) => readRevocation(event, keys));
  const byId = new Map<string, Record<string, unknown>>();
  for (const permit of bundle.permits) {
    const id = asString(permit["id"]);
    if (id && !byId.has(id)) byId.set(id, permit);
  }

  return bundle.permits.map((permit, index) =>
    verifyPermit(permit, index, bundle, byId, revocations, options.now ?? new Date()),
  );
}

function verifyPermit(
  permit: Record<string, unknown>,
  index: number,
  bundle: Bundle,
  byId: Map<string, Record<string, unknown>>,
  revocations: Revocation[],
  now: Date,
): RecordResult {
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const shape = checkShape(permit, checks, failures);
  const id = asString(permit["id"]);
  if (!shape) {
    const verdict = worstVerdict(failures);
    return finish(index, id, verdict, checks, "Permit is not a well-formed permit-v1 object.");
  }

  const decision = asString(permit["decision"]) ?? "";
  const binding = permit["binding_request_hash"];
  checkEnvelopeClock(permit, checks, failures);
  checkBinding(id ?? "", decision, binding, bundle.requests, checks, failures);
  checkExpiry(permit, now, checks, failures);
  checkLineage(permit, byId, checks, failures);
  checkRevocation(permit, byId, revocations, checks, failures);

  const verdict = worstVerdict(failures);
  return finish(index, id, verdict, checks, keelSummary(verdict, decision));
}

function checkShape(permit: Record<string, unknown>, checks: Check[], failures: Verdict[]): boolean {
  const unknown = Object.keys(permit).filter((key) => !PERMIT_FIELDS.has(key));
  if (unknown.length > 0) {
    failures.push("malformed");
    checks.push({ name: "fields", ok: false, detail: `unknown fields: ${unknown.join(", ")}` });
    return false;
  }
  const required = [
    "id",
    "project_id",
    "decision",
    "reason",
    "actions_json",
    "subject_type",
    "subject_id",
    "action_name",
    "resource_provider",
    "resource_model",
    "estimated_input_tokens",
    "estimated_output_tokens",
    "request_fingerprint",
    "idempotency_key",
    "policy_id",
    "policy_version",
    "created_at",
    "binding_request_hash",
  ];
  const missing = required.filter((key) => !(key in permit));
  if (missing.length > 0) {
    failures.push("malformed");
    checks.push({ name: "fields", ok: false, detail: `missing fields: ${missing.join(", ")}` });
    return false;
  }
  const id = asString(permit["id"]);
  const project = asString(permit["project_id"]);
  if (!id || !isUuid(id) || !project || !isUuid(project)) {
    failures.push("malformed");
    checks.push({ name: "fields", ok: false, detail: "id and project_id must be UUIDs" });
    return false;
  }
  const decision = asString(permit["decision"]);
  if (decision !== "allow" && decision !== "deny" && decision !== "challenge") {
    failures.push("malformed");
    checks.push({ name: "decision", ok: false, detail: "decision must be allow, deny, or challenge" });
    return false;
  }
  if (!Array.isArray(permit["actions_json"])) {
    failures.push("malformed");
    checks.push({ name: "fields", ok: false, detail: "actions_json must be an array" });
    return false;
  }
  for (const name of ["estimated_input_tokens", "estimated_output_tokens"] as const) {
    const value = permit[name];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
      failures.push("malformed");
      checks.push({ name, ok: false, detail: "must be an integer >= 0" });
      return false;
    }
  }
  const fingerprint = asString(permit["request_fingerprint"]);
  if (!fingerprint || !isLowerHex(fingerprint, 64)) {
    failures.push("malformed");
    checks.push({ name: "request_fingerprint", ok: false, detail: "must be 64 lowercase hex characters" });
    return false;
  }
  if (parseTimestamp(asString(permit["created_at"]) ?? "") === null) {
    failures.push("malformed");
    checks.push({ name: "created_at", ok: false, detail: "must be an RFC 3339 timestamp" });
    return false;
  }
  const binding = permit["binding_request_hash"];
  if (binding !== null && (typeof binding !== "string" || !isLowerHex(binding, 64))) {
    failures.push("malformed");
    checks.push({
      name: "binding_request_hash",
      ok: false,
      detail: "must be null or 64 lowercase hex characters",
    });
    return false;
  }
  if ((decision === "deny" || decision === "challenge") && binding !== null) {
    failures.push("malformed");
    checks.push({
      name: "binding_request_hash",
      ok: false,
      detail: `${decision} permits must not carry a binding hash`,
    });
    return false;
  }
  checks.push({ name: "fields", ok: true, detail: "permit-v1 required fields are present" });
  return true;
}

function checkBinding(
  id: string,
  decision: string,
  binding: unknown,
  requests: Record<string, unknown>,
  checks: Check[],
  failures: Verdict[],
): void {
  if (decision !== "allow") {
    checks.push({
      name: "binding_request_hash",
      ok: true,
      detail: `${decision} permit has no dispatch binding`,
    });
    return;
  }
  if (typeof binding !== "string") {
    failures.push("malformed");
    checks.push({
      name: "binding_request_hash",
      ok: false,
      detail: "allow permit is missing binding_request_hash",
    });
    return;
  }
  if (!(id in requests)) {
    failures.push("malformed");
    checks.push({
      name: "binding_request_hash",
      ok: false,
      detail: "request bytes were not supplied, so the binding cannot be checked",
    });
    return;
  }
  try {
    const digest = sha256Hex(bytesOf(canonicalCodePoint(stripWireBody(requests[id]))));
    if (hexEqual(digest, binding)) {
      checks.push({
        name: "binding_request_hash",
        ok: true,
        detail: "request bytes match binding_request_hash",
      });
    } else {
      failures.push("tampered");
      checks.push({
        name: "binding_request_hash",
        ok: false,
        detail: "request bytes do not match binding_request_hash",
      });
    }
  } catch (err) {
    const detail = err instanceof CanonicalError ? err.message : "request canonicalization failed";
    failures.push("malformed");
    checks.push({ name: "binding_request_hash", ok: false, detail });
  }
}

function checkEnvelopeClock(
  permit: Record<string, unknown>,
  checks: Check[],
  failures: Verdict[],
): void {
  if (!isRecord(permit["authority_envelope"])) return;
  const envelopeExpiry = asString(permit["authority_envelope"]["expires_at"]);
  const permitExpiry = asString(permit["expires_at"]);
  if (!envelopeExpiry || !permitExpiry) return;
  const left = parseTimestamp(envelopeExpiry);
  const right = parseTimestamp(permitExpiry);
  if (left === null || right === null || left !== right) {
    failures.push("malformed");
    checks.push({
      name: "authority_envelope",
      ok: false,
      detail: "authority_envelope.expires_at and permit expires_at disagree",
    });
  }
}

function checkExpiry(
  permit: Record<string, unknown>,
  now: Date,
  checks: Check[],
  failures: Verdict[],
): void {
  const expires = asString(permit["expires_at"]);
  if (expires === null) {
    checks.push({ name: "expiry", ok: null, detail: "permit has no expires_at" });
    return;
  }
  const ms = parseTimestamp(expires);
  if (ms === null) {
    failures.push("malformed");
    checks.push({ name: "expiry", ok: false, detail: "expires_at is not RFC 3339" });
    return;
  }
  if (now.getTime() >= ms) {
    failures.push("expired");
    checks.push({ name: "expiry", ok: false, detail: `expired at ${expires}` });
  } else {
    checks.push({ name: "expiry", ok: true, detail: `expires at ${expires}` });
  }
}

function checkLineage(
  permit: Record<string, unknown>,
  byId: Map<string, Record<string, unknown>>,
  checks: Check[],
  failures: Verdict[],
): void {
  const parentId = asString(permit["parent_permit_id"]);
  if (parentId === null) {
    checks.push({ name: "attenuation", ok: true, detail: "root permit. No parent to compare." });
    return;
  }
  if (!isUuid(parentId)) {
    failures.push("malformed");
    checks.push({ name: "attenuation", ok: false, detail: "parent_permit_id is not a UUID" });
    return;
  }
  const parent = byId.get(parentId);
  if (!parent || parent === permit) {
    failures.push("malformed");
    checks.push({
      name: "attenuation",
      ok: false,
      detail: "parent permit is not in the supplied set. Attenuation cannot be confirmed.",
    });
    return;
  }
  if (asString(parent["project_id"]) !== asString(permit["project_id"])) {
    failures.push("malformed");
    checks.push({ name: "attenuation", ok: false, detail: "parent is in a different project" });
    return;
  }
  const childDepth = permit["delegation_depth"];
  const parentDepth = parent["delegation_depth"];
  if (
    typeof childDepth !== "number" ||
    typeof parentDepth !== "number" ||
    !Number.isSafeInteger(childDepth) ||
    !Number.isSafeInteger(parentDepth) ||
    childDepth !== parentDepth + 1
  ) {
    failures.push("malformed");
    checks.push({
      name: "attenuation",
      ok: false,
      detail: "delegation_depth must be the parent depth plus one",
    });
    return;
  }
  if (
    permit["authority_envelope_version"] !== "authority-envelope.v0" ||
    parent["authority_envelope_version"] !== "authority-envelope.v0"
  ) {
    failures.push("malformed");
    checks.push({
      name: "attenuation",
      ok: false,
      detail: "only comparator authority-envelope.v0 is implemented",
    });
    return;
  }
  const relation = compareEnvelopes(permit["authority_envelope"], parent["authority_envelope"]);
  if (relation === "malformed") {
    failures.push("malformed");
    checks.push({
      name: "attenuation",
      ok: false,
      detail: "authority envelopes are not comparable under authority-envelope.v0",
    });
    return;
  }
  const childExpiry = asString(permit["expires_at"]);
  const parentExpiry = asString(parent["expires_at"]);
  if (childExpiry && parentExpiry) {
    const childMs = parseTimestamp(childExpiry);
    const parentMs = parseTimestamp(parentExpiry);
    if (childMs === null || parentMs === null) {
      failures.push("malformed");
      checks.push({ name: "attenuation", ok: false, detail: "lineage expiry is not RFC 3339" });
      return;
    }
    if (childMs > parentMs) {
      failures.push("widened");
      checks.push({
        name: "attenuation",
        ok: false,
        detail: "child expires_at is later than the parent",
      });
      return;
    }
  }
  if (relation === "widened") {
    failures.push("widened");
    checks.push({
      name: "attenuation",
      ok: false,
      detail: "child authority is wider than the parent under authority-envelope.v0",
    });
    return;
  }
  checks.push({
    name: "attenuation",
    ok: true,
    detail:
      relation === "equal"
        ? "child authority is equal to the parent under authority-envelope.v0"
        : "child authority is narrower than the parent under authority-envelope.v0",
  });
}

function compareEnvelopes(child: unknown, parent: unknown): Relation | "malformed" {
  if (!isRecord(child) || !isRecord(parent)) return "malformed";
  const childKeys = Object.keys(child);
  const parentKeys = Object.keys(parent);
  if (
    childKeys.length !== ENVELOPE_FIELDS.length ||
    parentKeys.length !== ENVELOPE_FIELDS.length ||
    ENVELOPE_FIELDS.some((field) => !(field in child) || !(field in parent))
  ) {
    return "malformed";
  }
  let narrowed = false;
  for (const field of ENVELOPE_FIELDS) {
    if (field === "expires_at") {
      const childMs = parseTimestamp(asString(child[field]) ?? "");
      const parentMs = parseTimestamp(asString(parent[field]) ?? "");
      if (childMs === null || parentMs === null) return "malformed";
      if (childMs > parentMs) return "widened";
      if (childMs < parentMs) narrowed = true;
      continue;
    }
    const relation = compareSet(child[field], parent[field]);
    if (relation === "malformed" || relation === "widened") return relation;
    if (relation === "narrower") narrowed = true;
  }
  return narrowed ? "narrower" : "equal";
}

function compareSet(child: unknown, parent: unknown): Relation | "malformed" {
  if (!Array.isArray(child) || !Array.isArray(parent)) return "malformed";
  if (child.some((item) => typeof item !== "string") || parent.some((item) => typeof item !== "string")) {
    return "malformed";
  }
  const childValues = child as string[];
  const parentValues = parent as string[];
  if (new Set(childValues).size !== childValues.length) return "malformed";
  if (new Set(parentValues).size !== parentValues.length) return "malformed";
  const parentSet = new Set(parentValues);
  const childSet = new Set(childValues);
  for (const item of childValues) {
    if (!parentSet.has(item)) return "widened";
  }
  for (const item of parentValues) {
    if (!childSet.has(item)) return "narrower";
  }
  return "equal";
}

function checkRevocation(
  permit: Record<string, unknown>,
  byId: Map<string, Record<string, unknown>>,
  revocations: Revocation[],
  checks: Check[],
  failures: Verdict[],
): void {
  const ids = ancestorIds(permit, byId);
  if (ids === null) {
    failures.push("malformed");
    checks.push({ name: "revocation", ok: false, detail: "lineage has a cycle or a missing parent" });
    return;
  }
  const status = asString(permit["status"]);
  const named = revocations.filter((event) => ids.includes(event.permitId));
  if (status === "revoked" && named.length === 0) {
    failures.push("malformed");
    checks.push({
      name: "revocation",
      ok: false,
      detail: "status is revoked but no permit.revoked event was supplied",
    });
    return;
  }
  if (named.length === 0) {
    checks.push({ name: "revocation", ok: true, detail: "no revocation event for this permit or its parents" });
    return;
  }
  const bad = named.find((event) => !event.verified);
  if (bad) {
    failures.push("malformed");
    checks.push({ name: "revocation", ok: false, detail: bad.detail });
    return;
  }
  const project = asString(permit["project_id"]);
  const mismatch = named.find((event) => event.projectId !== project);
  if (mismatch) {
    failures.push("malformed");
    checks.push({
      name: "revocation",
      ok: false,
      detail: "revocation project_id does not match the permit",
    });
    return;
  }
  failures.push("revoked");
  const own = named.some((event) => event.permitId === asString(permit["id"]));
  checks.push({
    name: "revocation",
    ok: false,
    detail: own
      ? "a signed permit.revoked event names this permit"
      : "a signed permit.revoked event names a parent permit",
  });
}

function ancestorIds(
  permit: Record<string, unknown>,
  byId: Map<string, Record<string, unknown>>,
): string[] | null {
  const ids: string[] = [];
  const seen = new Set<string>();
  let current: Record<string, unknown> | undefined = permit;
  while (current) {
    const id = asString(current["id"]);
    if (!id || seen.has(id)) return null;
    seen.add(id);
    ids.push(id);
    const parentId = asString(current["parent_permit_id"]);
    if (!parentId) return ids;
    current = byId.get(parentId);
    if (!current) return ids;
  }
  return ids;
}

function readRevocation(value: unknown, keys: Uint8Array[]): Revocation {
  if (!isRecord(value)) {
    return { permitId: "", projectId: "", verified: false, detail: "revocation event is not an object" };
  }
  const unknown = Object.keys(value).filter(
    (key) => !REVOCATION_FIELDS.includes(key as (typeof REVOCATION_FIELDS)[number]),
  );
  if (unknown.length > 0) {
    return {
      permitId: asString(value["permit_id"]) ?? "",
      projectId: asString(value["project_id"]) ?? "",
      verified: false,
      detail: `revocation event has unknown fields: ${unknown.join(", ")}`,
    };
  }
  const permitId = asString(value["permit_id"]);
  const projectId = asString(value["project_id"]);
  const actorId = asString(value["actor_id"]);
  const actorKind = asString(value["actor_kind"]);
  const reason = asString(value["reason_code"]);
  const revokedAt = asString(value["revoked_at"]);
  const effectiveAt = asString(value["effective_at"]);
  const signature = asString(value["signature"]);
  if (!permitId || !isUuid(permitId) || !projectId || !isUuid(projectId)) {
    return { permitId: permitId ?? "", projectId: projectId ?? "", verified: false, detail: "revocation ids are not UUIDs" };
  }
  if (!actorId || !isUuid(actorId) || actorId.includes("@")) {
    return { permitId, projectId, verified: false, detail: "revocation actor_id must be an opaque UUID" };
  }
  if (!actorKind || !ACTOR_KINDS.has(actorKind)) {
    return { permitId, projectId, verified: false, detail: "revocation actor_kind is not recognized" };
  }
  if (!reason || reason.length === 0) {
    return { permitId, projectId, verified: false, detail: "revocation reason_code is missing" };
  }
  if (!revokedAt || !effectiveAt || revokedAt !== effectiveAt || parseTimestamp(revokedAt) === null) {
    return {
      permitId,
      projectId,
      verified: false,
      detail: "revocation effective_at must equal revoked_at",
    };
  }
  if (!signature) {
    return { permitId, projectId, verified: false, detail: "revocation signature is missing" };
  }
  const raw = base64Decode(signature);
  if (!raw || raw.length !== 64) {
    return { permitId, projectId, verified: false, detail: "revocation signature is not 64-byte base64" };
  }
  if (keys.length === 0) {
    return {
      permitId,
      projectId,
      verified: false,
      detail: "revocation event cannot be checked because no public key was supplied",
    };
  }
  let digest: string;
  try {
    const payload = { ...value };
    delete payload["signature"];
    digest = sha256Hex(bytesOf(canonicalCodePoint(payload)));
  } catch (err) {
    const detail = err instanceof CanonicalError ? err.message : "revocation canonicalization failed";
    return { permitId, projectId, verified: false, detail };
  }
  const ok = keys.some((key) => ed25519Verify(key, bytesOf(digest), raw));
  if (!ok) {
    return { permitId, projectId, verified: false, detail: "revocation signature did not verify" };
  }
  return { permitId, projectId, verified: true, detail: "revocation signature verified" };
}

interface Bundle {
  permits: Record<string, unknown>[];
  revocations: unknown[];
  requests: Record<string, unknown>;
  keys: Record<string, string>;
}

function normalize(value: unknown): Bundle | { error: string } {
  if (!isRecord(value)) return { error: "Keel input must be a JSON object" };
  if (isPermit(value)) {
    return { permits: [value], revocations: [], requests: {}, keys: {} };
  }
  const allowed = new Set(["profile", "comparator", "permits", "revocations", "requests", "keys"]);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) return { error: `unknown bundle fields: ${unknown.join(", ")}` };
  if (value["profile"] !== undefined && value["profile"] !== "draft-munoz-scitt-permit-profile-01") {
    return { error: "profile is not draft-munoz-scitt-permit-profile-01" };
  }
  if (value["comparator"] !== undefined && value["comparator"] !== "authority-envelope.v0") {
    return { error: "only comparator authority-envelope.v0 is implemented" };
  }
  if (!Array.isArray(value["permits"]) || value["permits"].some((item) => !isRecord(item))) {
    return { error: "permits must be an array of objects" };
  }
  const revocations = value["revocations"] ?? [];
  if (!Array.isArray(revocations)) return { error: "revocations must be an array" };
  const requests = value["requests"] ?? {};
  if (!isRecord(requests)) return { error: "requests must be an object" };
  const keys = value["keys"] ?? {};
  if (!isRecord(keys) || Object.values(keys).some((item) => typeof item !== "string")) {
    return { error: "keys must be an object of strings" };
  }
  return {
    permits: value["permits"] as Record<string, unknown>[],
    revocations,
    requests,
    keys: keys as Record<string, string>,
  };
}

function collectKeys(bundleKeys: Record<string, string>, options: VerifyOptions): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const material of [...Object.values(bundleKeys), ...Object.values(options.keys ?? {})]) {
    const parsed = parsePublicKey(material);
    if (parsed) out.push(parsed);
  }
  return out;
}

function finish(
  index: number,
  id: string | null,
  verdict: Verdict,
  checks: Check[],
  summary: string,
): RecordResult {
  return {
    index,
    id,
    format: "keel-permit",
    verdict,
    label: labelFor(verdict),
    checks,
    summary,
  };
}

function malformed(index: number, id: string | null, detail: string): RecordResult {
  return finish(index, id, "malformed", [{ name: "parse", ok: false, detail }], detail);
}

function keelSummary(verdict: Verdict, decision: string): string {
  if (verdict === "valid") return `Permit decision ${decision} passed the checks that were supplied.`;
  if (verdict === "tampered") return "Request bytes do not match the permit binding.";
  if (verdict === "widened") return "Child authority is wider than its parent.";
  if (verdict === "revoked") return "A signed revocation covers this permit or a parent.";
  if (verdict === "expired") return "The permit expiry is not after the verification time.";
  return "Permit input is not well formed.";
}
