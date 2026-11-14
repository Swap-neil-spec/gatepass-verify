/**
 * Writes the Keel and ACTION-v1 fixtures that are not copied from a published vector.
 * Run after `npm run build`. The fixture signing key is derived from a public string.
 * It is published with the fixtures and must not be used for real records.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalCodePoint, canonicalJcs, stripWireBody } from "../dist/src/canonical.js";
import { sha256Hex } from "../dist/src/crypto.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const seed = createHash("sha256").update("gatepass-verify fixture key").digest();
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  seed,
]);
const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
const publicDer = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
const publicRaw = publicDer.subarray(publicDer.length - 32);
const publicB64 = publicRaw.toString("base64url");

const PROJECT = "11111111-1111-4111-8111-111111111111";
const PARENT = "22222222-2222-4222-8222-222222222222";
const CHILD = "33333333-3333-4333-8333-333333333333";
const ACTOR = "44444444-4444-4444-8444-444444444444";

function envelope(expiresAt, regions, tools) {
  return {
    actions: ["payment.transfer"],
    tools,
    providers: ["treasury"],
    models: ["ops-1"],
    data_classes: ["account"],
    regions,
    expires_at: expiresAt,
  };
}

function requestFor(amount, destination) {
  return {
    tool: "bank.transfer",
    arguments: {
      amount,
      currency: "USD",
      destination,
    },
  };
}

function binding(body) {
  return sha256Hex(Buffer.from(canonicalCodePoint(stripWireBody(body)), "utf8"));
}

function fingerprint(body) {
  return sha256Hex(Buffer.from(canonicalCodePoint({ tool: body.tool, destination: body.arguments.destination }), "utf8"));
}

function permit(opts) {
  const body = opts.request;
  return {
    id: opts.id,
    project_id: PROJECT,
    decision: opts.decision,
    reason: opts.reason,
    actions_json: [],
    subject_type: "agent",
    subject_id: "treasury-ops",
    action_name: "payment.transfer",
    resource_provider: "treasury",
    resource_model: "ops-1",
    estimated_input_tokens: 0,
    estimated_output_tokens: 0,
    request_fingerprint: body ? fingerprint(body) : "a".repeat(64),
    idempotency_key: opts.id,
    policy_id: "treasury-wire",
    policy_version: "1",
    created_at: "2026-05-01T00:00:00Z",
    binding_request_hash: opts.decision === "allow" && body ? binding(opts.boundRequest ?? body) : null,
    parent_permit_id: opts.parentId,
    delegation_depth: opts.depth,
    authority_envelope: opts.envelope,
    authority_envelope_version: "authority-envelope.v0",
    expires_at: opts.expiresAt,
    decision_details: {
      decision: opts.decision,
      code: opts.code,
      reason: opts.reason,
      approver: "R. Okonkwo",
      gate: "decision",
    },
    status: opts.status,
  };
}

function withoutEmpty(permitObject) {
  const copy = { ...permitObject };
  if (!copy.parent_permit_id) delete copy.parent_permit_id;
  if (!copy.status) delete copy.status;
  return copy;
}

function revocation(permitId, when) {
  const event = {
    permit_id: permitId,
    project_id: PROJECT,
    actor_id: ACTOR,
    actor_kind: "user",
    reason_code: "mandate-withdrawn",
    revoked_at: when,
    effective_at: when,
  };
  const digest = sha256Hex(Buffer.from(canonicalCodePoint(event), "utf8"));
  const signature = sign(null, Buffer.from(digest, "utf8"), privateKey).toString("base64");
  return { ...event, signature };
}

function bundle(name, permits, requests, revocations = []) {
  const body = {
    profile: "draft-munoz-scitt-permit-profile-01",
    comparator: "authority-envelope.v0",
    permits: permits.map(withoutEmpty),
    revocations,
    requests,
    keys: { fixture: publicB64 },
  };
  const path = join(root, "fixtures", "keel", name);
  writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
}

const parentExpiry = "2026-12-31T00:00:00Z";
const parentEnvelope = envelope(parentExpiry, ["eu", "us"], ["bank.transfer"]);
const parentRequest = requestFor("100.00", "acct-operating");
const parent = permit({
  id: PARENT,
  decision: "allow",
  reason: "playbook allows a treasury transfer",
  code: "policy.allow",
  request: parentRequest,
  depth: 0,
  envelope: parentEnvelope,
  expiresAt: parentExpiry,
  status: "bound",
});

function childPermit(opts) {
  const request = opts.request ?? requestFor(opts.amount ?? "40.00", opts.destination ?? "acct-payroll");
  return permit({
    id: CHILD,
    decision: opts.decision ?? "allow",
    reason: opts.reason,
    code: opts.code ?? "policy.allow",
    request,
    boundRequest: opts.boundRequest,
    parentId: PARENT,
    depth: 1,
    envelope: opts.envelope,
    expiresAt: opts.expiresAt,
    status: opts.status ?? "bound",
  });
}

const narrowEnvelope = envelope(parentExpiry, ["eu"], ["bank.transfer"]);
const narrowRequest = requestFor("40.00", "acct-payroll");
bundle(
  "narrow.json",
  [parent, childPermit({ reason: "payroll transfer inside the parent regions", envelope: narrowEnvelope, request: narrowRequest, expiresAt: parentExpiry })],
  { [PARENT]: parentRequest, [CHILD]: narrowRequest },
);

const equalRequest = requestFor("100.00", "acct-operating");
bundle(
  "equal.json",
  [parent, childPermit({ reason: "same authority as the parent", envelope: parentEnvelope, request: equalRequest, expiresAt: parentExpiry })],
  { [PARENT]: parentRequest, [CHILD]: equalRequest },
);

const wideEnvelope = envelope(parentExpiry, ["eu", "us"], ["bank.transfer", "bank.wire"]);
const wideRequest = requestFor("40.00", "acct-payroll");
bundle(
  "widened.json",
  [parent, childPermit({ reason: "adds an international wire tool", envelope: wideEnvelope, request: wideRequest, expiresAt: parentExpiry })],
  { [PARENT]: parentRequest, [CHILD]: wideRequest },
);

const tamperedRequest = requestFor("40.00", "acct-payroll");
const original = requestFor("40.00", "acct-vendor");
bundle(
  "tampered-binding.json",
  [
    parent,
    childPermit({
      reason: "payroll transfer inside the parent regions",
      envelope: narrowEnvelope,
      request: tamperedRequest,
      boundRequest: original,
      expiresAt: parentExpiry,
    }),
  ],
  { [PARENT]: parentRequest, [CHILD]: tamperedRequest },
);

const early = "2026-01-01T00:00:00Z";
const earlyEnvelope = envelope(early, ["eu"], ["bank.transfer"]);
const earlyRequest = requestFor("40.00", "acct-payroll");
const earlyParentEnvelope = envelope(early, ["eu", "us"], ["bank.transfer"]);
const earlyParent = permit({
  id: PARENT,
  decision: "allow",
  reason: "playbook allows a treasury transfer",
  code: "policy.allow",
  request: parentRequest,
  depth: 0,
  envelope: earlyParentEnvelope,
  expiresAt: early,
  status: "bound",
});
bundle(
  "expired.json",
  [
    earlyParent,
    childPermit({
      reason: "payroll transfer inside an expired mandate",
      envelope: earlyEnvelope,
      request: earlyRequest,
      expiresAt: early,
    }),
  ],
  { [PARENT]: parentRequest, [CHILD]: earlyRequest },
);

bundle(
  "revoked-parent.json",
  [
    { ...parent, status: "revoked" },
    childPermit({
      reason: "payroll transfer under a revoked parent",
      envelope: narrowEnvelope,
      request: narrowRequest,
      expiresAt: parentExpiry,
    }),
  ],
  { [PARENT]: parentRequest, [CHILD]: narrowRequest },
  [revocation(PARENT, "2026-05-15T00:00:00Z")],
);

const pending = permit({
  id: PARENT,
  decision: "challenge",
  reason: "waiting on the named approver",
  code: "needs.approval",
  depth: 0,
  envelope: parentEnvelope,
  expiresAt: parentExpiry,
  status: "pending",
});
bundle("pending.json", [pending], {});

const denied = permit({
  id: PARENT,
  decision: "deny",
  reason: "destination is outside the playbook",
  code: "policy.deny",
  depth: 0,
  envelope: parentEnvelope,
  expiresAt: parentExpiry,
  status: "evaluated",
});
bundle("denied.json", [denied], {});

writeFileSync(
  join(root, "fixtures", "keel", "malformed.json"),
  `${JSON.stringify({ profile: "draft-munoz-scitt-permit-profile-01", permits: [{ decision: "allow" }] }, null, 2)}\n`,
);

const intent = JSON.parse(
  readFileSync(join(root, "fixtures/haps/published/action-intent.payment.transfer.sample.json"), "utf8"),
);
const claims = JSON.parse(
  readFileSync(join(root, "fixtures/haps/published/consent-credential.webauthn-uv.sample.json"), "utf8"),
);
const view = JSON.parse(
  readFileSync(join(root, "fixtures/haps/published/signing-view.payment.transfer.sample.json"), "utf8"),
);

function haps(name, action, extra = {}) {
  const body = {
    profile: "haps-v0.4",
    claims,
    action,
    presentation: view,
    ...extra,
  };
  writeFileSync(join(root, "fixtures/haps", name), `${JSON.stringify(body, null, 2)}\n`);
}

mkdirSync(join(root, "fixtures/haps"), { recursive: true });
haps("valid.json", intent);
const changed = JSON.parse(JSON.stringify(intent));
changed.action.parameters.amount.value = "999.00";
haps("tampered-args.json", changed);
haps("expired.json", intent);
const missingJti = { ...claims };
delete missingJti.jti;
writeFileSync(
  join(root, "fixtures/haps/malformed.json"),
  `${JSON.stringify({ profile: "haps-v0.4", claims: missingJti, action: intent }, null, 2)}\n`,
);

function actionRecord(args, outcome) {
  const argsHash = sha256Hex(Buffer.from(canonicalJcs(args), "utf8"));
  const record = {
    v: "action-1",
    action_id: "55555555-5555-4555-8555-555555555555",
    org_id: "org-fixture",
    session_id: "sess-fixture",
    intent_hash: "b".repeat(64),
    agent: "fixture-caller",
    tool: "github.merge_pull_request",
    args_hash: argsHash,
    outcome,
    policy_applied: ["production_change_review"],
    timestamp: "2026-08-22T14:03:11Z",
    public_key: publicB64,
  };
  const signature = sign(null, Buffer.from(canonicalJcs(record), "utf8"), privateKey).toString("base64url");
  return { ...record, signature };
}

const allowedArgs = { merge_method: "squash", pull_number: 18 };
const allowed = actionRecord(allowedArgs, "ALLOWED");
mkdirSync(join(root, "fixtures/action"), { recursive: true });
writeFileSync(
  join(root, "fixtures/action/args-match.json"),
  `${JSON.stringify({ profile: "action-v1", args: allowedArgs, record: allowed }, null, 2)}\n`,
);
writeFileSync(
  join(root, "fixtures/action/args-mismatch.json"),
  `${JSON.stringify(
    { profile: "action-v1", args: { merge_method: "squash", pull_number: 99 }, record: allowed },
    null,
    2,
  )}\n`,
);

const lines = readFileSync(join(root, "fixtures/afr/published/flight.jsonl"), "utf8")
  .split("\n")
  .filter((line) => line.length > 0);
const broken = [lines[0], "{not json", lines[1]].join("\n") + "\n";
writeFileSync(join(root, "fixtures/afr/broken.jsonl"), broken);

console.log(`wrote fixtures with public key ${publicB64}`);
