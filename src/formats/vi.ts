import { canonicalJcs } from "../canonical.js";
import { parseEcPublicKey, sha256Base64url, type EcJwk } from "../crypto.js";
import { fact, type EvidenceView } from "../facts.js";
import { labelFor, worstVerdict } from "../result.js";
import {
  disclosureDigest,
  reconstructSdJwt,
  splitSdJwt,
  verifyEs256Jwt,
  type DecodedDisclosure,
  type ReconstructedSdJwt,
} from "../sdjwt.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord } from "../text.js";

const PROFILE = "verifiable-intent-v0.1";
const CARD_VCT = "https://credentials.mastercard.com/card";
const SKEW_MS = 300_000;
const HOUR_SECONDS = 3600;

const OPEN_PAYMENT = "mandate.payment.open.1";
const CLOSED_PAYMENT = "mandate.payment.1";
const OPEN_CHECKOUT = "mandate.checkout.open.1";
const CLOSED_CHECKOUT = "mandate.checkout.1";

const KNOWN = new Set([
  "mandate.checkout.allowed_merchants",
  "mandate.checkout.line_items",
  "mandate.payment.allowed_payees",
  "mandate.payment.amount_range",
  "mandate.payment.budget",
  "mandate.payment.recurrence",
  "mandate.payment.agent_recurrence",
  "mandate.payment.reference",
]);

interface Layer {
  raw: string;
  issuerJwt: string;
  rebuilt: ReconstructedSdJwt;
  disclosures: DecodedDisclosure[];
}

interface Presentation {
  l1: Layer;
  l2: Layer;
  l3a: Layer | null;
  l3b: Layer | null;
}

/** SHA-256 of the selective layer 2 presentation a layer 3 credential binds to. */
export function l3PresentationHash(l2: string, vct: string): string | null {
  const loaded = layer(l2, "l2");
  if ("error" in loaded) return null;
  return selectiveHash(loaded, vct);
}

export function isViDocument(value: unknown): boolean {
  return isRecord(value) && value["profile"] === PROFILE;
}

export function verifyVi(value: unknown, _text: string, options: VerifyOptions): RecordResult[] {
  const presentation = load(value);
  if ("error" in presentation) return [malformed(presentation.error)];
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const now = options.now ?? new Date();
  const mode = checkLayers(presentation, options, now, checks, failures);
  if (mode) checkMandates(presentation, mode, now, checks, failures);
  const verdict = worstVerdict(failures);
  const id = presentationId(presentation);
  return [finish(id, verdict, checks, summary(verdict))];
}

export function describeVi(value: unknown): EvidenceView {
  const presentation = load(value);
  if ("error" in presentation) {
    return {
      approved: fact(presentation.error),
      approver: fact("The credential could not be read."),
      when: fact("No time could be read."),
      executed: fact("No layer 3 mandate could be read."),
      unsupported: ["Verifiable Intent presentation did not parse"],
    };
  }
  const mandates = mandatesOf(presentation.l2);
  const payment = mandates.find((item) => String(item["vct"]).startsWith("mandate.payment"));
  const amount = isRecord(payment?.["payment_amount"]) ? payment["payment_amount"] : null;
  const l3payment = presentation.l3a ? mandatesOf(presentation.l3a).find((item) => item["vct"] === CLOSED_PAYMENT) : null;
  const l3amount = isRecord(l3payment?.["payment_amount"]) ? l3payment["payment_amount"] : null;
  const approvedFields: Record<string, string | number | boolean | null> = {};
  if (payment) approvedFields["vct"] = asString(payment["vct"]);
  if (amount && typeof amount["amount"] === "number") approvedFields["amount"] = amount["amount"];
  if (amount) approvedFields["currency"] = asString(amount["currency"]);
  const holder = jwkOf(presentation.l1.rebuilt.payload["cnf"]);
  const approverFields: Record<string, string | number | boolean | null> = {
    issuer: asString(presentation.l1.rebuilt.payload["iss"]),
    subject: asString(presentation.l1.rebuilt.payload["sub"]),
  };
  if (holder) approverFields["holderKeyThumbprint"] = sha256Base64url(canonicalJcs({
    crv: holder.crv,
    kty: holder.kty,
    x: holder.x,
    y: holder.y,
  }));
  const whenFields: Record<string, string | number | boolean | null> = {
    l1exp: unix(presentation.l1.rebuilt.payload["exp"]),
    l2exp: unix(presentation.l2.rebuilt.payload["exp"]),
  };
  const executedFields: Record<string, string | number | boolean | null> = {};
  if (l3amount && typeof l3amount["amount"] === "number") executedFields["amount"] = l3amount["amount"];
  if (l3payment && isRecord(l3payment["payee"])) executedFields["payee"] = asString(l3payment["payee"]["name"]);
  return {
    approved: fact("Layer 2 is the user mandate. Final values are there in immediate mode, and constraints are there in autonomous mode.", approvedFields),
    approver: fact("Layer 1 binds a subject to a holder key. The issuer signature is checked only when a key is supplied.", approverFields),
    when: fact("Expiry uses the 300 second skew stated in the credential format.", whenFields),
    executed: fact(
      l3payment
        ? "Layer 3 is the closed mandate the holder key delegated. It is not a settlement record."
        : "No layer 3 mandate was in the file.",
      executedFields,
    ),
    unsupported: [
      "Issuer JWKS is not contacted. Pass --key verifiable-intent=<P-256 jwk or pem>.",
      "checkout_jwt merchant signature is implementation-defined in v0.1 and is not a MUST.",
      "Cumulative budget and recurrence counts need payment-network state that is not in the file.",
      "Nonce replay is not tracked.",
    ],
  };
}

function load(value: unknown): Presentation | { error: string } {
  if (!isRecord(value) || value["profile"] !== PROFILE) return { error: "verifiable-intent object was not found" };
  const l1 = layer(asString(value["l1"]), "l1");
  if ("error" in l1) return l1;
  const l2 = layer(asString(value["l2"]), "l2");
  if ("error" in l2) return l2;
  const l3aRaw = value["l3a"];
  const l3bRaw = value["l3b"];
  const l3a = l3aRaw === undefined ? null : layer(asString(l3aRaw), "l3a");
  if (l3a && "error" in l3a) return l3a;
  const l3b = l3bRaw === undefined ? null : layer(asString(l3bRaw), "l3b");
  if (l3b && "error" in l3b) return l3b;
  return { l1, l2, l3a, l3b };
}

function layer(token: string | null, name: string): Layer | { error: string } {
  if (!token) return { error: `${name} must be a serialized SD-JWT string` };
  const parts = splitSdJwt(token);
  if ("error" in parts) return { error: `${name}: ${parts.error}` };
  if (parts.kbJwt) return { error: `${name} uses a separate key-binding JWT. This profile puts the binding in the layer JWT.` };
  const rebuilt = reconstructSdJwt(parts);
  if ("error" in rebuilt) return { error: `${name}: ${rebuilt.error}` };
  return { raw: token, issuerJwt: parts.issuerJwt, rebuilt, disclosures: rebuilt.disclosures };
}

function checkLayers(
  presentation: Presentation,
  options: VerifyOptions,
  now: Date,
  checks: Check[],
  failures: Verdict[],
): "immediate" | "autonomous" | null {
  const l1 = presentation.l1.rebuilt;
  if (l1.header["alg"] !== "ES256" || l1.header["typ"] !== "sd+jwt") {
    failures.push("malformed");
    checks.push({ name: "l1_header", ok: false, detail: "layer 1 alg must be ES256 and typ must be sd+jwt" });
  } else {
    checks.push({ name: "l1_header", ok: true, detail: "layer 1 header is ES256 sd+jwt" });
  }
  if ("sd_hash" in l1.payload) {
    failures.push("malformed");
    checks.push({ name: "l1_sd_hash", ok: false, detail: "layer 1 must not contain sd_hash" });
  }
  const vct = asString(l1.payload["vct"]);
  const missing = ["iss", "sub", "iat", "exp", "vct", "cnf", "_sd_alg"].filter((key) => l1.payload[key] === undefined);
  if (l1.payload["_sd_alg"] !== undefined && l1.payload["_sd_alg"] !== "sha-256") missing.push("_sd_alg value");
  if (!vct || !vct.includes(":")) missing.push("vct URI");
  if (vct === CARD_VCT) {
    if (typeof l1.payload["pan_last_four"] !== "string") missing.push("pan_last_four");
    if (typeof l1.payload["scheme"] !== "string") missing.push("scheme");
  }
  if (missing.length > 0) {
    failures.push("malformed");
    checks.push({ name: "l1_claims", ok: false, detail: `layer 1 is missing ${missing.join(", ")}` });
  } else if (vct !== CARD_VCT) {
    checks.push({
      name: "l1_claims",
      ok: null,
      detail: "structural layer 1 claims are present. Profile-specific claims for this vct are not in the Mastercard reference profile, so they were not checked.",
    });
  } else {
    checks.push({ name: "l1_claims", ok: true, detail: "Mastercard reference profile claims are present" });
  }
  checkClock("l1", l1.payload, now, checks, failures);
  const holder = jwkOf(l1.payload["cnf"]);
  if (!holder) {
    failures.push("malformed");
    checks.push({ name: "l1_cnf", ok: false, detail: "layer 1 cnf.jwk must be a P-256 key" });
  } else {
    checks.push({ name: "l1_cnf", ok: true, detail: "layer 1 binds a P-256 holder key" });
  }
  const material = options.keys?.["verifiable-intent"] ?? options.keys?.["vi"];
  if (!material) {
    checks.push({
      name: "l1_signature",
      ok: null,
      detail: "issuer signature not checked. Pass --key verifiable-intent=<P-256 jwk or pem>. JWKS is not fetched.",
    });
  } else if (l1.header["alg"] === "ES256") {
    const key = parseEcPublicKey(material);
    if (!key) {
      failures.push("malformed");
      checks.push({ name: "l1_signature", ok: false, detail: "verifiable-intent key is not a P-256 public key" });
    } else {
      const verified = verifyEs256Jwt(presentation.l1.issuerJwt, key);
      if ("error" in verified) {
        failures.push("tampered");
        checks.push({ name: "l1_signature", ok: false, detail: verified.error });
      } else {
        checks.push({ name: "l1_signature", ok: true, detail: "layer 1 ES256 signature verified with the supplied key" });
      }
    }
  }
  const l2 = presentation.l2.rebuilt;
  const l2Typ = asString(l2.header["typ"]);
  const mandates = mandatesOf(presentation.l2);
  const open = mandates.some((item) => item["vct"] === OPEN_PAYMENT || item["vct"] === OPEN_CHECKOUT);
  const closed = mandates.some((item) => item["vct"] === CLOSED_PAYMENT || item["vct"] === CLOSED_CHECKOUT);
  if (open && closed) {
    failures.push("malformed");
    checks.push({ name: "l2_mode", ok: false, detail: "layer 2 mixes open and final mandate types" });
    return null;
  }
  if (!open && !closed) {
    failures.push("malformed");
    checks.push({ name: "l2_mode", ok: false, detail: "layer 2 disclosures have no checkout or payment mandate" });
    return null;
  }
  const mode = open ? "autonomous" : "immediate";
  const expectedTyp = mode === "autonomous" ? "kb-sd-jwt+kb" : "kb-sd-jwt";
  if (l2.header["alg"] !== "ES256" || l2Typ !== expectedTyp) {
    failures.push("malformed");
    checks.push({
      name: "l2_header",
      ok: false,
      detail: `layer 2 must be ES256 ${expectedTyp} for ${mode} mode`,
    });
  } else {
    checks.push({ name: "l2_header", ok: true, detail: `layer 2 header matches ${mode} mode` });
  }
  if (holder && l2.header["alg"] === "ES256") {
    const verified = verifyEs256Jwt(presentation.l2.issuerJwt, holder);
    if ("error" in verified) {
      failures.push("tampered");
      checks.push({ name: "l2_signature", ok: false, detail: verified.error });
    } else {
      checks.push({ name: "l2_signature", ok: true, detail: "layer 2 signature matches the layer 1 holder key" });
    }
  }
  const sdHash = asString(l2.payload["sd_hash"]);
  const expectedHash = sha256Base64url(presentation.l1.raw);
  if (!sdHash) {
    failures.push("malformed");
    checks.push({ name: "l2_sd_hash", ok: false, detail: "layer 2 sd_hash is required" });
  } else if (sdHash !== expectedHash) {
    failures.push("tampered");
    checks.push({
      name: "l2_sd_hash",
      ok: false,
      detail: "layer 2 sd_hash is not the SHA-256 of the l1 string in this file",
    });
  } else {
    checks.push({
      name: "l2_sd_hash",
      ok: true,
      detail: "layer 2 sd_hash matches the serialized l1 string, including its trailing tilde when present",
    });
  }
  checkClock("l2", l2.payload, now, checks, failures);
  if ((presentation.l3a || presentation.l3b) && mode === "immediate") {
    failures.push("malformed");
    checks.push({ name: "l3", ok: false, detail: "immediate mode has no layer 3" });
  }
  return mode;
}

function checkMandates(
  presentation: Presentation,
  mode: "immediate" | "autonomous",
  now: Date,
  checks: Check[],
  failures: Verdict[],
): void {
  const mandates = mandatesOf(presentation.l2);
  if (mode === "immediate") checkImmediate(mandates, checks, failures);
  else checkAutonomous(presentation, mandates, now, checks, failures);
}

function checkImmediate(mandates: Record<string, unknown>[], checks: Check[], failures: Verdict[]): void {
  const checkouts = mandates.filter((item) => item["vct"] === CLOSED_CHECKOUT);
  const payments = mandates.filter((item) => item["vct"] === CLOSED_PAYMENT);
  if (checkouts.length === 0 || payments.length === 0) {
    failures.push("malformed");
    checks.push({ name: "mandate_pair", ok: false, detail: "immediate mode needs a checkout mandate and a payment mandate" });
    return;
  }
  for (const mandate of mandates) {
    if ("cnf" in mandate || "constraints" in mandate) {
      failures.push("malformed");
      checks.push({ name: "mandate_shape", ok: false, detail: "immediate mandates must not contain cnf or constraints" });
      return;
    }
  }
  const seen = new Set<string>();
  for (const checkout of checkouts) {
    const jwt = asString(checkout["checkout_jwt"]);
    const hash = asString(checkout["checkout_hash"]);
    if (!jwt || !hash) {
      failures.push("malformed");
      checks.push({ name: "checkout_hash", ok: false, detail: "checkout mandate needs checkout_jwt and checkout_hash" });
      return;
    }
    const computed = sha256Base64url(jwt);
    if (hash !== computed) {
      failures.push("tampered");
      checks.push({ name: "checkout_hash", ok: false, detail: "checkout_hash is not the SHA-256 of checkout_jwt" });
      return;
    }
    if (seen.has(hash)) {
      failures.push("malformed");
      checks.push({ name: "mandate_pair", ok: false, detail: "duplicate checkout_hash" });
      return;
    }
    seen.add(hash);
    const payment = payments.filter((item) => item["transaction_id"] === hash);
    if (payment.length !== 1) {
      failures.push("malformed");
      checks.push({ name: "mandate_pair", ok: false, detail: "checkout_hash does not match exactly one transaction_id" });
      return;
    }
    if (!validPaymentFields(payment[0]!)) {
      failures.push("malformed");
      checks.push({ name: "payment_fields", ok: false, detail: "payment mandate is missing amount, currency, payee, or instrument" });
      return;
    }
  }
  if (payments.length !== checkouts.length) {
    failures.push("malformed");
    checks.push({ name: "mandate_pair", ok: false, detail: "a payment mandate has no checkout partner" });
    return;
  }
  checks.push({
    name: "mandate_pair",
    ok: true,
    detail: "checkout_hash, transaction_id, and the checkout_jwt digest match. Merchant signature on checkout_jwt was not checked.",
  });
  checks.push({
    name: "checkout_jwt_signature",
    ok: null,
    detail: "v0.1 leaves the checkout_jwt signature implementation-defined. It is not a MUST, and no merchant key was applied.",
  });
}

function checkAutonomous(
  presentation: Presentation,
  mandates: Record<string, unknown>[],
  now: Date,
  checks: Check[],
  failures: Verdict[],
): void {
  const checkouts = mandates.filter((item) => item["vct"] === OPEN_CHECKOUT);
  const payments = mandates.filter((item) => item["vct"] === OPEN_PAYMENT);
  if (checkouts.length === 0 || payments.length === 0) {
    failures.push("malformed");
    checks.push({ name: "mandate_pair", ok: false, detail: "autonomous mode needs an open checkout and an open payment mandate" });
    return;
  }
  const holder = jwkOf(checkouts[0]?.["cnf"]);
  const kid = kidOf(checkouts[0]?.["cnf"]);
  if (!holder || !kid) {
    failures.push("malformed");
    checks.push({ name: "delegation_key", ok: false, detail: "open checkout mandate needs cnf.jwk with kid" });
    return;
  }
  for (const payment of payments) {
    if (!sameJwk(jwkOf(payment["cnf"]), holder) || kidOf(payment["cnf"]) !== kid) {
      failures.push("tampered");
      checks.push({ name: "delegation_key", ok: false, detail: "checkout and payment cnf keys differ" });
      return;
    }
  }
  checks.push({ name: "delegation_key", ok: true, detail: "open mandates share one P-256 delegation key and kid" });
  for (const payment of payments) {
    const reference = referenceOf(payment);
    if (!reference) {
      failures.push("malformed");
      checks.push({ name: "mandate.payment.reference", ok: false, detail: "open payment mandate needs mandate.payment.reference" });
      return;
    }
    const checkout = checkoutForReference(presentation.l2, reference);
    if (!checkout) {
      failures.push("malformed");
      checks.push({
        name: "mandate.payment.reference",
        ok: false,
        detail: "conditional_transaction_id does not match a checkout disclosure digest",
      });
      return;
    }
  }
  checks.push({
    name: "mandate.payment.reference",
    ok: true,
    detail: "each payment reference matches a checkout disclosure digest",
  });
  if (!presentation.l3a || !presentation.l3b) {
    checks.push({
      name: "l3",
      ok: null,
      detail: "layer 3 was not supplied, so closed values were not compared with the constraints",
    });
    return;
  }
  const l3aMandates = mandatesOf(presentation.l3a);
  const l3bMandates = mandatesOf(presentation.l3b);
  const closedPayment = l3aMandates.find((item) => item["vct"] === CLOSED_PAYMENT);
  const closedCheckout = l3bMandates.find((item) => item["vct"] === CLOSED_CHECKOUT);
  if (!closedPayment || !closedCheckout) {
    failures.push("malformed");
    checks.push({ name: "l3_mandate", ok: false, detail: "layer 3 must disclose mandate.payment.1 and mandate.checkout.1" });
    return;
  }
  if (hasCnf(presentation.l3a.rebuilt.payload) || hasCnf(presentation.l3b.rebuilt.payload)) {
    failures.push("malformed");
    checks.push({ name: "l3_cnf", ok: false, detail: "layer 3 must not contain cnf" });
  }
  for (const [name, layerValue] of [["l3a", presentation.l3a], ["l3b", presentation.l3b]] as const) {
    const header = layerValue.rebuilt.header;
    if (header["alg"] !== "ES256" || header["typ"] !== "kb-sd-jwt" || header["kid"] !== kid) {
      failures.push("malformed");
      checks.push({ name: `${name}_header`, ok: false, detail: `${name} must be ES256 kb-sd-jwt with kid ${kid}` });
      continue;
    }
    const verified = verifyEs256Jwt(layerValue.issuerJwt, holder);
    if ("error" in verified) {
      failures.push("tampered");
      checks.push({ name: `${name}_signature`, ok: false, detail: verified.error });
    } else {
      checks.push({ name: `${name}_signature`, ok: true, detail: `${name} signature matches the delegated key` });
    }
    checkClock(name, layerValue.rebuilt.payload, now, checks, failures);
    const iat = unix(layerValue.rebuilt.payload["iat"]);
    const exp = unix(layerValue.rebuilt.payload["exp"]);
    if (iat !== null && exp !== null && exp - iat > HOUR_SECONDS) {
      failures.push("malformed");
      checks.push({ name: `${name}_lifetime`, ok: false, detail: "layer 3 lifetime exceeds the 1 hour maximum" });
    }
    const bound = name === "l3a" ? selectiveHash(presentation.l2, OPEN_PAYMENT) : selectiveHash(presentation.l2, OPEN_CHECKOUT);
    const actual = asString(layerValue.rebuilt.payload["sd_hash"]);
    if (!bound || actual !== bound) {
      failures.push("tampered");
      checks.push({
        name: `${name}_sd_hash`,
        ok: false,
        detail: `${name} sd_hash does not match the selective layer 2 presentation (base JWT, mandate disclosure, then nested disclosures, each joined by ~)`,
      });
    } else {
      checks.push({ name: `${name}_sd_hash`, ok: true, detail: `${name} sd_hash matches the selective layer 2 presentation` });
    }
  }
  const jwt = asString(closedCheckout["checkout_jwt"]);
  const hash = asString(closedCheckout["checkout_hash"]);
  if (!jwt || !hash || hash !== sha256Base64url(jwt) || closedPayment["transaction_id"] !== hash) {
    failures.push("tampered");
    checks.push({ name: "checkout_hash", ok: false, detail: "layer 3 checkout_hash, checkout_jwt digest, and transaction_id disagree" });
  } else {
    checks.push({ name: "checkout_hash", ok: true, detail: "layer 3 checkout_hash and transaction_id match the checkout_jwt digest" });
  }
  checks.push({
    name: "checkout_jwt_signature",
    ok: null,
    detail: "v0.1 leaves the checkout_jwt signature implementation-defined. It was not checked.",
  });
  evaluate(checkouts[0]!, payments[0]!, closedCheckout, closedPayment, now, checks, failures);
}

function evaluate(
  openCheckout: Record<string, unknown>,
  openPayment: Record<string, unknown>,
  closedCheckout: Record<string, unknown>,
  closedPayment: Record<string, unknown>,
  now: Date,
  checks: Check[],
  failures: Verdict[],
): void {
  const groups: Array<[Record<string, unknown>, "checkout" | "payment"]> = [
    [openCheckout, "checkout"],
    [openPayment, "payment"],
  ];
  for (const [mandate, kind] of groups) {
    const list = mandate["constraints"];
    if (!Array.isArray(list) || list.length === 0) {
      failures.push("malformed");
      checks.push({ name: "constraints", ok: false, detail: `${kind} mandate needs a non-empty constraints array` });
      continue;
    }
    for (const constraint of list) {
      if (!isRecord(constraint) || typeof constraint["type"] !== "string") {
        failures.push("malformed");
        checks.push({ name: "constraint", ok: false, detail: "constraint is missing type" });
        continue;
      }
      const outcome = oneConstraint(constraint, closedCheckout, closedPayment, list, now);
      checks.push(outcome.check);
      if (outcome.verdict) failures.push(outcome.verdict);
    }
  }
}

function oneConstraint(
  constraint: Record<string, unknown>,
  checkout: Record<string, unknown>,
  payment: Record<string, unknown>,
  siblings: unknown[],
  now: Date,
): { check: Check; verdict: Verdict | null } {
  const type = String(constraint["type"]);
  const name = `constraint:${type}`;
  if (!KNOWN.has(type)) {
    return { check: { name, ok: false, detail: "unknown constraint type in an open mandate" }, verdict: "widened" };
  }
  if (type === "mandate.payment.amount_range") return amountRange(name, constraint, payment);
  if (type === "mandate.payment.allowed_payees") return allowlist(name, constraint, payment["payee"], "payee");
  if (type === "mandate.checkout.allowed_merchants") return merchants(name, constraint, checkout);
  if (type === "mandate.checkout.line_items") return lineItems(name, constraint, checkout);
  if (type === "mandate.payment.budget") return budget(name, constraint, payment);
  if (type === "mandate.payment.reference") {
    return { check: { name, ok: true, detail: "reference binding is checked with the disclosure digest" }, verdict: null };
  }
  if (type === "mandate.payment.recurrence") {
    return {
      check: {
        name,
        ok: null,
        detail: "merchant recurrence metadata is implementation-defined in v0.1 and was not in the file",
      },
      verdict: null,
    };
  }
  return agentRecurrence(name, constraint, siblings, now);
}

function amountRange(name: string, constraint: Record<string, unknown>, payment: Record<string, unknown>): { check: Check; verdict: Verdict | null } {
  const amount = payment["payment_amount"];
  if (!isRecord(amount) || typeof amount["amount"] !== "number" || !Number.isSafeInteger(amount["amount"]) || amount["amount"] < 0) {
    return { check: { name, ok: false, detail: "payment_amount.amount must be a non-negative integer minor unit" }, verdict: "malformed" };
  }
  if (constraint["currency"] !== amount["currency"]) {
    return { check: { name, ok: false, detail: "currency does not match the amount range" }, verdict: "widened" };
  }
  const max = constraint["max"];
  const min = constraint["min"];
  if (max !== undefined && (typeof max !== "number" || !Number.isSafeInteger(max) || amount["amount"] > max)) {
    return { check: { name, ok: false, detail: `amount ${amount["amount"]} is above max` }, verdict: "widened" };
  }
  if (min !== undefined && (typeof min !== "number" || !Number.isSafeInteger(min) || amount["amount"] < min)) {
    return { check: { name, ok: false, detail: `amount ${amount["amount"]} is below min` }, verdict: "widened" };
  }
  return { check: { name, ok: true, detail: `amount ${amount["amount"]} is inside the range` }, verdict: null };
}

function allowlist(
  name: string,
  constraint: Record<string, unknown>,
  candidate: unknown,
  label: string,
): { check: Check; verdict: Verdict | null } {
  const allowed = constraint["allowed"];
  if (!Array.isArray(allowed)) return { check: { name, ok: false, detail: "allowed must be an array" }, verdict: "malformed" };
  if (allowed.length === 0) return { check: { name, ok: false, detail: `empty ${label} allowlist` }, verdict: "widened" };
  const revealed = allowed.filter((item) => isRecord(item) && !("..." in item));
  if (revealed.length === 0) {
    return { check: { name, ok: null, detail: `no ${label} entries were disclosed, so the allowlist was not evaluated` }, verdict: null };
  }
  if (!isRecord(candidate)) return { check: { name, ok: false, detail: `closed mandate has no ${label}` }, verdict: "widened" };
  const ok = revealed.some((item) => partyMatch(item, candidate));
  if (!ok) return { check: { name, ok: false, detail: `${label} is not in the disclosed allowlist` }, verdict: "widened" };
  return { check: { name, ok: true, detail: `${label} matches a disclosed allowlist entry` }, verdict: null };
}

function merchants(name: string, constraint: Record<string, unknown>, checkout: Record<string, unknown>): { check: Check; verdict: Verdict | null } {
  const allowed = constraint["allowed"];
  if (!Array.isArray(allowed) || allowed.length === 0) {
    return { check: { name, ok: false, detail: "merchant allowlist is missing or empty" }, verdict: "widened" };
  }
  const revealed = allowed.filter((item) => isRecord(item) && !("..." in item));
  if (revealed.length === 0) {
    return { check: { name, ok: null, detail: "no merchants were disclosed, so the allowlist was not evaluated" }, verdict: null };
  }
  const token = asString(checkout["checkout_jwt"]);
  const merchant = token ? merchantFromJwt(token) : null;
  if (!merchant || typeof merchant["id"] !== "string") {
    return {
      check: {
        name,
        ok: null,
        detail: "checkout_jwt has no merchant.id, so the allowlist cannot be validated. The merchant signature was not checked.",
      },
      verdict: null,
    };
  }
  const ok = revealed.some((item) => partyMatch(item, merchant));
  if (!ok) return { check: { name, ok: false, detail: "merchant is not in the disclosed allowlist" }, verdict: "widened" };
  return {
    check: { name, ok: true, detail: "merchant.id matches a disclosed merchant. The checkout_jwt signature was not checked." },
    verdict: null,
  };
}

function lineItems(name: string, constraint: Record<string, unknown>, checkout: Record<string, unknown>): { check: Check; verdict: Verdict | null } {
  const items = constraint["items"];
  const mode = constraint["match_mode"] === undefined ? "minimum" : constraint["match_mode"];
  if (mode !== "minimum" && mode !== "exact") {
    return { check: { name, ok: false, detail: "match_mode must be minimum or exact" }, verdict: "widened" };
  }
  if (!Array.isArray(items) || items.length === 0) {
    return { check: { name, ok: false, detail: "line item allowlist is empty" }, verdict: "widened" };
  }
  const cart = Array.isArray(checkout["line_items"]) ? checkout["line_items"] : null;
  if (!cart || cart.length === 0) return { check: { name, ok: false, detail: "layer 3 checkout has no line_items" }, verdict: "widened" };
  const entries: Array<{ ids: string[]; qty: number }> = [];
  for (const item of items) {
    if (!isRecord(item) || typeof item["id"] !== "string" || !Array.isArray(item["acceptable_items"])) {
      return { check: { name, ok: false, detail: "line item entry needs id and acceptable_items" }, verdict: "malformed" };
    }
    if (typeof item["quantity"] !== "number" || !Number.isSafeInteger(item["quantity"])) {
      return { check: { name, ok: false, detail: "line item quantity must be an integer" }, verdict: "malformed" };
    }
    const ids: string[] = [];
    for (const acceptable of item["acceptable_items"]) {
      if (!isRecord(acceptable)) continue;
      if (typeof acceptable["title"] !== "string") {
        return { check: { name, ok: false, detail: "acceptable item is missing title" }, verdict: "widened" };
      }
      if (typeof acceptable["id"] === "string") ids.push(acceptable["id"]);
    }
    entries.push({ ids, qty: item["quantity"] });
  }
  const selected: Array<{ id: string; qty: number }> = [];
  for (const line of cart) {
    if (!isRecord(line)) return { check: { name, ok: false, detail: "line item is not an object" }, verdict: "malformed" };
    const id = asString(line["id"]) ?? asString(line["sku"]);
    const qty = line["quantity"] === undefined ? 1 : line["quantity"];
    if (!id || typeof qty !== "number" || !Number.isSafeInteger(qty) || qty < 1) {
      return { check: { name, ok: false, detail: "line item needs an id or sku and a positive quantity" }, verdict: "malformed" };
    }
    selected.push({ id, qty });
  }
  const totalCap = entries.reduce((sum, entry) => sum + entry.qty, 0);
  const totalSelected = selected.reduce((sum, line) => sum + line.qty, 0);
  if (totalSelected > totalCap) {
    return { check: { name, ok: false, detail: "selected quantity exceeds the constraint" }, verdict: "widened" };
  }
  for (const line of selected) {
    const holders = entries.filter((entry) => entry.ids.length === 0 || entry.ids.includes(line.id));
    if (holders.length === 0) return { check: { name, ok: false, detail: `${line.id} is not an acceptable item` }, verdict: "widened" };
    const cap = holders.reduce((sum, entry) => sum + entry.qty, 0);
    if (line.qty > cap) return { check: { name, ok: false, detail: `${line.id} quantity exceeds its cap` }, verdict: "widened" };
  }
  if (mode === "exact") {
    for (const entry of entries) {
      const hit = selected.some((line) => entry.ids.includes(line.id) && line.qty > 0);
      if (!hit) return { check: { name, ok: false, detail: "exact match is missing an allowed item" }, verdict: "widened" };
    }
  }
  return { check: { name, ok: true, detail: `line items satisfy ${mode} mode` }, verdict: null };
}

function budget(name: string, constraint: Record<string, unknown>, payment: Record<string, unknown>): { check: Check; verdict: Verdict | null } {
  const amount = payment["payment_amount"];
  const max = constraint["max"];
  if (!isRecord(amount) || amount["currency"] !== constraint["currency"]) {
    return { check: { name, ok: false, detail: "budget currency does not match the payment" }, verdict: "widened" };
  }
  if (typeof amount["amount"] !== "number" || typeof max !== "number" || !Number.isSafeInteger(max)) {
    return { check: { name, ok: false, detail: "budget max must be an integer minor unit" }, verdict: "malformed" };
  }
  const min = constraint["min"];
  if (typeof min === "number" && amount["amount"] < min) {
    return { check: { name, ok: false, detail: "amount is below the budget minimum" }, verdict: "widened" };
  }
  if (amount["amount"] > max) {
    return { check: { name, ok: false, detail: "this payment alone exceeds the budget max" }, verdict: "widened" };
  }
  return {
    check: {
      name,
      ok: null,
      detail: "this payment does not exceed the cap by itself. Cumulative spend is not in the file.",
    },
    verdict: null,
  };
}

function agentRecurrence(
  name: string,
  constraint: Record<string, unknown>,
  siblings: unknown[],
  now: Date,
): { check: Check; verdict: Verdict | null } {
  const start = asString(constraint["start_date"]);
  const end = asString(constraint["end_date"]);
  if (!start || !end || !/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    return { check: { name, ok: false, detail: "agent recurrence needs start_date and end_date" }, verdict: "malformed" };
  }
  const types = new Set(siblings.filter(isRecord).map((item) => item["type"]));
  if (!types.has("mandate.payment.amount_range") || !types.has("mandate.payment.budget")) {
    return {
      check: { name, ok: false, detail: "agent recurrence requires amount_range and budget constraints" },
      verdict: "widened",
    };
  }
  const day = now.toISOString().slice(0, 10);
  if (day < start) return { check: { name, ok: false, detail: "verification clock is before start_date" }, verdict: "widened" };
  if (day > end) return { check: { name, ok: false, detail: "verification clock is after end_date" }, verdict: "expired" };
  return {
    check: {
      name,
      ok: null,
      detail: "the date window and the required companion constraints hold. Occurrence count is not in the file.",
    },
    verdict: null,
  };
}

function checkClock(name: string, payload: Record<string, unknown>, now: Date, checks: Check[], failures: Verdict[]): void {
  const exp = unix(payload["exp"]);
  const iat = unix(payload["iat"]);
  if (exp === null) {
    failures.push("malformed");
    checks.push({ name: `${name}_exp`, ok: false, detail: `${name} exp must be an integer` });
    return;
  }
  if (now.getTime() > exp * 1000 + SKEW_MS) {
    failures.push("expired");
    checks.push({ name: `${name}_exp`, ok: false, detail: `${name} exp is past, allowing the stated 300 second skew` });
    return;
  }
  if (iat !== null && iat * 1000 > now.getTime() + SKEW_MS) {
    failures.push("malformed");
    checks.push({ name: `${name}_iat`, ok: false, detail: `${name} iat is after the verification clock plus 300 seconds` });
    return;
  }
  checks.push({ name: `${name}_exp`, ok: true, detail: `${name} exp is inside the 300 second skew` });
}

function selectiveHash(layer: Layer, vct: string): string | null {
  const mandate = layer.disclosures.find((item) => isRecord(item.value) && item.value["vct"] === vct);
  if (!mandate) return null;
  const refs = new Set<string>();
  collectRefs(mandate.value, refs);
  const nested = layer.disclosures.filter((item) => refs.has(item.digest)).map((item) => item.segment);
  let body = layer.issuerJwt;
  for (const segment of [mandate.segment, ...nested]) body += `~${segment}`;
  return sha256Base64url(`${body}~`);
}

function collectRefs(value: unknown, refs: Set<string>, seen = new Set<unknown>()): void {
  if (!value || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (isRecord(value) && Object.keys(value).length === 1 && typeof value["..."] === "string") {
    refs.add(value["..."]);
    return;
  }
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  for (const inner of entries) collectRefs(inner, refs, seen);
}

function mandatesOf(layer: Layer): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  collectMandates(layer.rebuilt.payload, found, new Set());
  return found;
}

function collectMandates(value: unknown, out: Record<string, unknown>[], seen: Set<unknown>): void {
  if (!value || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (isRecord(value) && typeof value["vct"] === "string" && value["vct"].startsWith("mandate.")) out.push(value);
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  for (const inner of entries) collectMandates(inner, out, seen);
}

function referenceOf(payment: Record<string, unknown>): string | null {
  const list = payment["constraints"];
  if (!Array.isArray(list)) return null;
  for (const item of list) {
    if (isRecord(item) && item["type"] === "mandate.payment.reference") {
      return asString(item["conditional_transaction_id"]);
    }
  }
  return null;
}

function checkoutForReference(layer: Layer, reference: string): boolean {
  return layer.disclosures.some((item) => {
    if (!isRecord(item.value) || item.value["vct"] !== OPEN_CHECKOUT) return false;
    return disclosureDigest(item.segment) === reference || item.digest === reference;
  });
}

function validPaymentFields(payment: Record<string, unknown>): boolean {
  const amount = payment["payment_amount"];
  const payee = payment["payee"];
  const instrument = payment["payment_instrument"];
  return (
    isRecord(amount) &&
    typeof amount["currency"] === "string" &&
    typeof amount["amount"] === "number" &&
    Number.isSafeInteger(amount["amount"]) &&
    isRecord(payee) &&
    typeof payee["name"] === "string" &&
    typeof payee["website"] === "string" &&
    isRecord(instrument) &&
    typeof instrument["type"] === "string" &&
    typeof instrument["id"] === "string"
  );
}

function merchantFromJwt(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as unknown;
    if (!isRecord(payload)) return null;
    if (isRecord(payload["merchant"])) return payload["merchant"];
    return null;
  } catch {
    return null;
  }
}

function partyMatch(allowed: Record<string, unknown>, candidate: Record<string, unknown>): boolean {
  if (typeof allowed["id"] === "string" && typeof candidate["id"] === "string") return allowed["id"] === candidate["id"];
  if (typeof allowed["name"] === "string" && typeof allowed["website"] === "string") {
    return allowed["name"] === candidate["name"] && allowed["website"] === candidate["website"];
  }
  return false;
}

function jwkOf(cnf: unknown): EcJwk | null {
  if (!isRecord(cnf)) return null;
  const jwk = cnf["jwk"];
  if (!isRecord(jwk) || jwk["kty"] !== "EC" || jwk["crv"] !== "P-256") return null;
  if (typeof jwk["x"] !== "string" || typeof jwk["y"] !== "string") return null;
  return { kty: "EC", crv: "P-256", x: jwk["x"], y: jwk["y"] };
}

function kidOf(cnf: unknown): string | null {
  if (!isRecord(cnf) || !isRecord(cnf["jwk"])) return null;
  return asString(cnf["jwk"]["kid"]);
}

function sameJwk(left: EcJwk | null, right: EcJwk | null): boolean {
  if (!left || !right) return false;
  return left.x === right.x && left.y === right.y;
}

function hasCnf(value: unknown, seen = new Set<unknown>()): boolean {
  if (!value || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  if (isRecord(value) && "cnf" in value) return true;
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  return entries.some((inner) => hasCnf(inner, seen));
}

function unix(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function presentationId(presentation: Presentation): string | null {
  return asString(presentation.l2.rebuilt.payload["nonce"]) ?? asString(presentation.l1.rebuilt.payload["sub"]);
}

function summary(verdict: Verdict): string {
  if (verdict === "valid") return "Verifiable Intent presentation passed the checks that could be run offline.";
  if (verdict === "tampered") return "A Verifiable Intent signature or hash binding failed.";
  if (verdict === "widened") return "A layer 3 value is outside a layer 2 constraint.";
  if (verdict === "expired") return "A Verifiable Intent credential is past exp, after the 300 second skew.";
  return "Verifiable Intent input is not well formed.";
}

function malformed(detail: string): RecordResult {
  return finish(null, "malformed", [{ name: "parse", ok: false, detail }], detail);
}

function finish(id: string | null, verdict: Verdict, checks: Check[], text: string): RecordResult {
  return {
    index: 0,
    id,
    format: "verifiable-intent",
    verdict,
    label: labelFor(verdict),
    checks,
    summary: text,
  };
}
