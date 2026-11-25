import { CanonicalError, canonicalJcs } from "../canonical.js";
import {
  parseEcPublicKey,
  sha256Base64url,
  type EcJwk,
} from "../crypto.js";
import { fact, type EvidenceView } from "../facts.js";
import { labelFor, worstVerdict } from "../result.js";
import {
  readJwt,
  reconstructSdJwt,
  splitChain,
  splitSdJwt,
  verifyEs256Jwt,
  type DecodedDisclosure,
} from "../sdjwt.js";
import type { Check, RecordResult, Verdict, VerifyOptions } from "../types.js";
import { asString, isRecord, parseTimestamp } from "../text.js";

const PROFILE = "ap2-mandate";
const OPEN_PAYMENT = "mandate.payment.open.1";
const CLOSED_PAYMENT = "mandate.payment.1";
const OPEN_CHECKOUT = "mandate.checkout.open.1";
const CLOSED_CHECKOUT = "mandate.checkout.1";

const PAYMENT_CONSTRAINTS = new Set([
  "payment.amount_range",
  "payment.allowed_payees",
  "payment.allowed_payment_instruments",
  "payment.allowed_pisps",
  "payment.agent_recurrence",
  "payment.budget",
  "payment.reference",
  "payment.execution_date",
]);

const CHECKOUT_CONSTRAINTS = new Set(["checkout.allowed_merchants", "checkout.line_items"]);

const FREQUENCIES = new Set([
  "ON_DEMAND",
  "DAILY",
  "WEEKLY",
  "BIWEEKLY",
  "MONTHLY",
  "QUARTERLY",
  "ANNUALLY",
]);

const UNCHANGED_SKIP = new Set(["vct", "constraints", "cnf", "iat", "exp"]);
const MATCH_STEP_LIMIT = 100000;
const MATCH_UNIT_LIMIT = 32;

interface Hop {
  segment: string;
  issuerJwt: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  disclosures: DecodedDisclosure[];
}

interface ParsedChain {
  hops: Hop[];
  mandates: Record<string, unknown>[];
  receipt: string | null;
}

export function isAp2Document(value: unknown, text: string): boolean {
  if (isRecord(value) && value["profile"] === PROFILE) return true;
  if (isRecord(value)) return false;
  const trimmed = text.trim();
  return trimmed.startsWith("eyJ") && trimmed.includes("~~");
}

export function verifyAp2(value: unknown, text: string, options: VerifyOptions): RecordResult[] {
  const parsed = parseChain(value, text);
  if ("error" in parsed) return [malformed(parsed.error)];
  const checks: Check[] = [];
  const failures: Verdict[] = [];
  const now = options.now ?? new Date();
  checkSignatures(parsed.hops, options, checks, failures);
  checkBindings(parsed.hops, checks, failures);
  checkMandates(parsed, now, checks, failures);
  checkReceipt(parsed, options, checks, failures);
  const verdict = worstVerdict(failures);
  const id = mandateId(parsed.mandates);
  return [finish(id, verdict, checks, summary(verdict))];
}

export function describeAp2(value: unknown, text: string): EvidenceView {
  const parsed = parseChain(value, text);
  if ("error" in parsed) {
    return {
      approved: fact(parsed.error),
      approver: fact("The mandate chain could not be read."),
      when: fact("No time could be read."),
      executed: fact("No closed mandate could be read."),
      unsupported: ["AP2 chain did not parse"],
    };
  }
  const openPayment = mandateByVct(parsed.mandates, OPEN_PAYMENT);
  const closedPayment = mandateByVct(parsed.mandates, CLOSED_PAYMENT);
  const closedCheckout = mandateByVct(parsed.mandates, CLOSED_CHECKOUT);
  const payment = closedPayment ?? openPayment;
  const amount = isRecord(payment?.["payment_amount"]) ? payment["payment_amount"] : null;
  const payee = isRecord(payment?.["payee"]) ? payment["payee"] : null;
  const approvedFields: Record<string, string | number | boolean | null> = {};
  if (payment) approvedFields["vct"] = asString(payment["vct"]);
  if (amount && typeof amount["amount"] === "number") approvedFields["amount"] = amount["amount"];
  if (amount) approvedFields["currency"] = asString(amount["currency"]);
  if (payee) approvedFields["payee"] = asString(payee["name"]);
  const constraints = openPayment && Array.isArray(openPayment["constraints"])
    ? openPayment["constraints"].length
    : 0;
  if (constraints > 0) approvedFields["constraints"] = constraints;
  const approverFields: Record<string, string | number | boolean | null> = {};
  const cnf = firstCnf(parsed.hops);
  if (cnf) approverFields["holderKeyThumbprint"] = sha256Base64url(canonicalMembers(cnf));
  const headerKid = asString(parsed.hops[0]?.header["kid"]);
  if (headerKid) approverFields["issuerKid"] = headerKid;
  const whenFields: Record<string, string | number | boolean | null> = {};
  const exp = unixOf(payment?.["exp"] ?? parsed.hops.at(-1)?.payload["exp"]);
  const iat = unixOf(payment?.["iat"] ?? parsed.hops[0]?.payload["iat"]);
  if (iat !== null) whenFields["iat"] = iat;
  if (exp !== null) whenFields["exp"] = exp;
  const executedFields: Record<string, string | number | boolean | null> = {};
  if (closedPayment) executedFields["closedPayment"] = CLOSED_PAYMENT;
  if (closedCheckout) executedFields["checkoutHash"] = asString(closedCheckout["checkout_hash"]);
  const unsupported = [
    "Issuer JWKS and x5c trust are not contacted. Pass --key ap2=<jwk or pem> to check the first hop.",
    "payment.agent_recurrence occurrence history and payment.budget cumulative spend need a presentation log that is not in the file.",
    "The checkout_jwt merchant signature is not a MUST in the checkout mandate document. The payload schema is out of scope there.",
    "ISO mdoc mandates are not checked.",
  ];
  return {
    approved: fact(
      payment
        ? "Payment mandate claims that were disclosed."
        : "No payment mandate object was disclosed.",
      approvedFields,
    ),
    approver: fact(
      cnf
        ? "The holder key is the cnf key inside the mandate. The issuer key is checked only when supplied."
        : "No cnf holder key was disclosed.",
      approverFields,
    ),
    when: fact(exp !== null ? "Times are unix seconds from the mandate." : "No exp was set.", whenFields),
    executed: fact(
      closedPayment
        ? "The closed mandate is what the signature binds. It is not a settlement record."
        : "No closed mandate was in the file, so there is no bound transaction.",
      executedFields,
    ),
    unsupported,
  };
}

function canonicalMembers(jwk: EcJwk): string {
  return canonicalJcs({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

function parseChain(value: unknown, text: string): ParsedChain | { error: string } {
  let chain = "";
  let receipt: string | null = null;
  if (isRecord(value) && value["profile"] === PROFILE) {
    const body = asString(value["chain"]) ?? asString(value["mandate"]);
    if (!body) return { error: "ap2-mandate object needs a chain string" };
    chain = body;
    receipt = asString(value["receipt"]);
  } else if (!isRecord(value)) {
    chain = text.trim();
  } else {
    return { error: "AP2 input was not recognized" };
  }
  const segments = splitChain(chain);
  if ("error" in segments) return segments;
  const hops: Hop[] = [];
  for (const segment of segments) {
    const parts = splitSdJwt(segment);
    if ("error" in parts) return { error: parts.error };
    if (parts.kbJwt) {
      return {
        error:
          "This hop ends in a separate key-binding JWT. AP2 puts that binding in the hop JWT itself.",
      };
    }
    const rebuilt = reconstructSdJwt(parts);
    if ("error" in rebuilt) return { error: rebuilt.error };
    hops.push({
      segment,
      issuerJwt: parts.issuerJwt,
      header: rebuilt.header,
      payload: rebuilt.payload,
      disclosures: rebuilt.disclosures,
    });
  }
  if (hops.length === 0) return { error: "AP2 chain has no hops" };
  const mandates: Record<string, unknown>[] = [];
  for (const hop of hops) collectMandates(hop.payload, mandates);
  return { hops, mandates, receipt };
}

function collectMandates(value: unknown, out: Record<string, unknown>[], seen = new Set<unknown>()): void {
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (isRecord(value) && typeof value["vct"] === "string" && value["vct"].startsWith("mandate.")) {
    out.push(value);
  }
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  for (const inner of entries) collectMandates(inner, out, seen);
}

function checkSignatures(
  hops: Hop[],
  options: VerifyOptions,
  checks: Check[],
  failures: Verdict[],
): void {
  const material = options.keys?.["ap2"] ?? options.keys?.["issuer"];
  const first = hops[0]!;
  if (first.header["alg"] !== "ES256") {
    failures.push("malformed");
    checks.push({
      name: "issuer_signature",
      ok: false,
      detail: "the first hop must use ES256. Other algorithms are not checked.",
    });
  } else if (!material) {
    checks.push({
      name: "issuer_signature",
      ok: null,
      detail: "issuer signature not checked. Pass --key ap2=<P-256 jwk or pem>. This tool does not fetch JWKS.",
    });
  } else {
    const key = parseEcPublicKey(material);
    if (!key) {
      failures.push("malformed");
      checks.push({
        name: "issuer_signature",
        ok: false,
        detail: "ap2 key is not a P-256 public JWK or PEM",
      });
    } else {
      const verified = verifyEs256Jwt(first.issuerJwt, key);
      if ("error" in verified) {
        failures.push("tampered");
        checks.push({ name: "issuer_signature", ok: false, detail: verified.error });
      } else {
        checks.push({
          name: "issuer_signature",
          ok: true,
          detail: "ES256 signature on the first hop verified with the supplied key. x5c was not evaluated.",
        });
      }
    }
  }

  for (let i = 1; i < hops.length; i += 1) {
    const previous = cnfFromHop(hops[i - 1]!);
    const hop = hops[i]!;
    if (!previous) {
      failures.push("malformed");
      checks.push({
        name: "hop_signature",
        ok: false,
        detail: `hop ${i + 1} has no P-256 cnf.jwk on the previous hop`,
      });
      continue;
    }
    if (hop.header["alg"] !== "ES256") {
      failures.push("malformed");
      checks.push({
        name: "hop_signature",
        ok: false,
        detail: `hop ${i + 1} alg is not ES256`,
      });
      continue;
    }
    const verified = verifyEs256Jwt(hop.issuerJwt, previous);
    if ("error" in verified) {
      failures.push("tampered");
      checks.push({ name: "hop_signature", ok: false, detail: `hop ${i + 1}: ${verified.error}` });
    } else {
      checks.push({
        name: "hop_signature",
        ok: true,
        detail: `hop ${i + 1} verified with the previous hop cnf.jwk`,
      });
    }
  }
}

function checkBindings(hops: Hop[], checks: Check[], failures: Verdict[]): void {
  if (hops.length === 1) {
    checks.push({
      name: "sd_hash",
      ok: null,
      detail: "a single hop has no preceding presentation to bind",
    });
    return;
  }
  for (let i = 1; i < hops.length; i += 1) {
    const payload = hops[i]!.payload;
    const sdHash = asString(payload["sd_hash"]);
    const issuerHash = asString(payload["issuer_jwt_hash"]);
    if (!sdHash && !issuerHash) {
      failures.push("malformed");
      checks.push({
        name: "sd_hash",
        ok: false,
        detail: `hop ${i + 1} has neither sd_hash nor issuer_jwt_hash`,
      });
      continue;
    }
    const previous = hops[i - 1]!;
    if (sdHash) {
      const expected = sha256Base64url(previous.segment);
      if (sdHash === expected) {
        checks.push({
          name: "sd_hash",
          ok: true,
          detail: `hop ${i + 1} sd_hash matches the preceding hop bytes`,
        });
      } else {
        failures.push("tampered");
        checks.push({
          name: "sd_hash",
          ok: false,
          detail: `hop ${i + 1} sd_hash does not match the preceding hop bytes`,
        });
      }
    }
    if (issuerHash) {
      const expected = sha256Base64url(previous.issuerJwt);
      if (issuerHash === expected) {
        checks.push({
          name: "issuer_jwt_hash",
          ok: true,
          detail: `hop ${i + 1} issuer_jwt_hash matches the preceding issuer JWT`,
        });
      } else {
        failures.push("tampered");
        checks.push({
          name: "issuer_jwt_hash",
          ok: false,
          detail: `hop ${i + 1} issuer_jwt_hash does not match the preceding issuer JWT`,
        });
      }
    }
  }
}

function checkMandates(parsed: ParsedChain, now: Date, checks: Check[], failures: Verdict[]): void {
  const openPayment = mandateByVct(parsed.mandates, OPEN_PAYMENT);
  const closedPayment = mandateByVct(parsed.mandates, CLOSED_PAYMENT);
  const openCheckout = mandateByVct(parsed.mandates, OPEN_CHECKOUT);
  const closedCheckout = mandateByVct(parsed.mandates, CLOSED_CHECKOUT);
  if (!openPayment && !closedPayment && !openCheckout && !closedCheckout) {
    failures.push("malformed");
    checks.push({
      name: "mandate",
      ok: false,
      detail: "no mandate.payment or mandate.checkout object was disclosed",
    });
    return;
  }
  checks.push({
    name: "mandate",
    ok: true,
    detail: `${parsed.mandates.length} mandate object${parsed.mandates.length === 1 ? "" : "s"} disclosed`,
  });
  if (closedPayment) checkClosedPayment(closedPayment, checks, failures);
  if (closedCheckout) checkClosedCheckout(closedCheckout, checks, failures);
  if (closedPayment && closedCheckout) {
    const tx = asString(closedPayment["transaction_id"]);
    const hash = asString(closedCheckout["checkout_hash"]);
    if (tx && hash && tx === hash) {
      checks.push({
        name: "checkout_hash",
        ok: true,
        detail: "payment transaction_id matches checkout_hash",
      });
    } else {
      failures.push("tampered");
      checks.push({
        name: "checkout_hash",
        ok: false,
        detail: "payment transaction_id does not match checkout_hash",
      });
    }
  }
  if (openPayment && closedPayment) {
    sameClaims(openPayment, closedPayment, "payment", checks, failures);
  }
  if (openCheckout && closedCheckout) {
    sameClaims(openCheckout, closedCheckout, "checkout", checks, failures);
  }
  checkExpiry(parsed.mandates, now, checks, failures);
  if (openPayment && closedPayment) {
    evaluateConstraints(openPayment, closedPayment, "payment", parsed, checks, failures);
  } else if (openPayment && !closedPayment) {
    checks.push({
      name: "constraints",
      ok: null,
      detail: "open payment mandate has no closed mandate in this file, so constraints were not evaluated",
    });
  }
  if (openCheckout && closedCheckout) {
    evaluateConstraints(openCheckout, closedCheckout, "checkout", parsed, checks, failures);
  } else if (openCheckout && !closedCheckout) {
    checks.push({
      name: "constraints",
      ok: null,
      detail: "open checkout mandate has no closed mandate in this file, so constraints were not evaluated",
    });
  }
}

function checkClosedPayment(mandate: Record<string, unknown>, checks: Check[], failures: Verdict[]): void {
  const amount = mandate["payment_amount"];
  const problems: string[] = [];
  if (typeof mandate["transaction_id"] !== "string") problems.push("transaction_id");
  if (!isRecord(mandate["payee"])) problems.push("payee");
  if (!isRecord(mandate["payment_instrument"])) problems.push("payment_instrument");
  if (
    !isRecord(amount) ||
    typeof amount["currency"] !== "string" ||
    typeof amount["amount"] !== "number" ||
    !Number.isSafeInteger(amount["amount"])
  ) {
    problems.push("payment_amount");
  }
  if (problems.length > 0) {
    failures.push("malformed");
    checks.push({
      name: "payment_fields",
      ok: false,
      detail: `closed payment mandate is missing or mistyped: ${problems.join(", ")}`,
    });
    return;
  }
  checks.push({
    name: "payment_fields",
    ok: true,
    detail: "closed payment mandate has the required fields from the payment mandate schema",
  });
}

function checkClosedCheckout(mandate: Record<string, unknown>, checks: Check[], failures: Verdict[]): void {
  const jwt = asString(mandate["checkout_jwt"]);
  const hash = asString(mandate["checkout_hash"]);
  if (!jwt || !hash) {
    failures.push("malformed");
    checks.push({
      name: "checkout_fields",
      ok: false,
      detail: "closed checkout mandate needs checkout_jwt and checkout_hash",
    });
    return;
  }
  const expected = sha256Base64url(jwt);
  if (hash !== expected) {
    failures.push("tampered");
    checks.push({
      name: "checkout_hash",
      ok: false,
      detail: "checkout_hash is not the SHA-256 of checkout_jwt",
    });
    return;
  }
  checks.push({
    name: "checkout_fields",
    ok: true,
    detail: "checkout_hash matches checkout_jwt. The merchant signature on that JWT is not required by the checkout mandate document.",
  });
}

function sameClaims(
  open: Record<string, unknown>,
  closed: Record<string, unknown>,
  label: string,
  checks: Check[],
  failures: Verdict[],
): void {
  for (const [key, value] of Object.entries(open)) {
    if (UNCHANGED_SKIP.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(closed, key)) {
      failures.push("tampered");
      checks.push({
        name: "unchanged_claims",
        ok: false,
        detail: `closed ${label} mandate dropped ${key}, which the open mandate set`,
      });
      return;
    }
    if (!sameValue(value, closed[key])) {
      failures.push("tampered");
      checks.push({
        name: "unchanged_claims",
        ok: false,
        detail: `closed ${label} mandate changed ${key}`,
      });
      return;
    }
  }
  checks.push({
    name: "unchanged_claims",
    ok: true,
    detail: `shared ${label} claims are unchanged from the open mandate. vct, constraints, cnf, iat, and exp may differ.`,
  });
}

function checkExpiry(mandates: Record<string, unknown>[], now: Date, checks: Check[], failures: Verdict[]): void {
  let saw = false;
  for (const mandate of mandates) {
    if (mandate["exp"] === undefined) continue;
    saw = true;
    const exp = mandate["exp"];
    if (typeof exp !== "number" || !Number.isSafeInteger(exp)) {
      failures.push("malformed");
      checks.push({ name: "exp", ok: false, detail: "exp must be an integer unix time" });
      return;
    }
    if (now.getTime() >= exp * 1000) {
      failures.push("expired");
      checks.push({
        name: "exp",
        ok: false,
        detail: `expired at unix ${exp}. The payment mandate page does not define a skew allowance.`,
      });
      return;
    }
  }
  if (!saw) {
    checks.push({ name: "exp", ok: null, detail: "no mandate exp was set" });
    return;
  }
  checks.push({ name: "exp", ok: true, detail: "mandate exp is after the verification clock" });
}

function evaluateConstraints(
  open: Record<string, unknown>,
  closed: Record<string, unknown>,
  kind: "payment" | "checkout",
  parsed: ParsedChain,
  checks: Check[],
  failures: Verdict[],
): void {
  const list = open["constraints"];
  if (list === undefined) {
    checks.push({ name: "constraints", ok: null, detail: `open ${kind} mandate has no constraints array` });
    return;
  }
  if (!Array.isArray(list)) {
    failures.push("malformed");
    checks.push({ name: "constraints", ok: false, detail: "constraints must be an array" });
    return;
  }
  const known = kind === "payment" ? PAYMENT_CONSTRAINTS : CHECKOUT_CONSTRAINTS;
  for (const constraint of list) {
    if (!isRecord(constraint) || typeof constraint["type"] !== "string") {
      failures.push("malformed");
      checks.push({ name: "constraint", ok: false, detail: "constraint is missing type" });
      continue;
    }
    const type = constraint["type"];
    if (!known.has(type)) {
      failures.push("widened");
      checks.push({
        name: `constraint:${type}`,
        ok: false,
        detail: "unknown constraint types fail evaluation, per the agent authorization rules",
      });
      continue;
    }
    const result = kind === "payment"
      ? paymentConstraint(type, constraint, closed, parsed)
      : checkoutConstraint(type, constraint, closed);
    checks.push(result.check);
    if (result.verdict) failures.push(result.verdict);
  }
}

interface ConstraintResult {
  check: Check;
  verdict: Verdict | null;
}

function paymentConstraint(
  type: string,
  constraint: Record<string, unknown>,
  closed: Record<string, unknown>,
  parsed: ParsedChain,
): ConstraintResult {
  if (type === "payment.amount_range") return amountRange(constraint, closed);
  if (type === "payment.allowed_payees") return allowedObjects(constraint, closed["payee"], "payee");
  if (type === "payment.allowed_payment_instruments") {
    return allowedObjects(constraint, closed["payment_instrument"], "payment_instrument");
  }
  if (type === "payment.allowed_pisps") return allowedObjects(constraint, closed["pisp"], "pisp");
  if (type === "payment.execution_date") return executionWindow(constraint, closed);
  if (type === "payment.reference") return paymentReference(constraint, parsed);
  if (type === "payment.agent_recurrence") return recurrenceShape(constraint);
  return budgetShape(constraint, closed);
}

function amountRange(constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  const currency = asString(constraint["currency"]);
  const max = constraint["max"];
  const min = constraint["min"];
  if (!currency || !/^[A-Z]{3}$/.test(currency)) {
    return fail("constraint:payment.amount_range", "malformed", "currency must be three uppercase letters");
  }
  if (typeof max !== "number" || !Number.isSafeInteger(max)) {
    return fail(
      "constraint:payment.amount_range",
      "malformed",
      "max must be an integer minor unit. The schema table says integer. The decimal example on that page is not evaluated as minor units.",
    );
  }
  if (min !== undefined && (typeof min !== "number" || !Number.isSafeInteger(min))) {
    return fail("constraint:payment.amount_range", "malformed", "min must be an integer minor unit when it is present");
  }
  const amount = closed["payment_amount"];
  if (!isRecord(amount) || typeof amount["amount"] !== "number" || !Number.isSafeInteger(amount["amount"])) {
    return fail("constraint:payment.amount_range", "malformed", "closed payment_amount.amount must be an integer");
  }
  if (amount["currency"] !== currency) {
    return fail("constraint:payment.amount_range", "widened", `currency is ${String(amount["currency"])}, constraint says ${currency}`);
  }
  if (amount["amount"] > max || (typeof min === "number" && amount["amount"] < min)) {
    return fail(
      "constraint:payment.amount_range",
      "widened",
      `amount ${amount["amount"]} is outside ${typeof min === "number" ? min : "no min"}..${max} ${currency}`,
    );
  }
  return pass("constraint:payment.amount_range", `amount ${amount["amount"]} ${currency} is inside the range`);
}

function allowedObjects(constraint: Record<string, unknown>, candidate: unknown, label: string): ConstraintResult {
  const name = `constraint:${String(constraint["type"])}`;
  const allowed = constraint["allowed"];
  if (!Array.isArray(allowed)) return fail(name, "malformed", "allowed must be an array");
  const revealed = allowed.filter((item) => isRecord(item) && !("..." in item));
  if (revealed.length === 0) {
    return fail(name, "widened", `no revealed ${label} entries, so membership cannot be shown`);
  }
  if (!isRecord(candidate)) return fail(name, "widened", `closed mandate has no ${label}`);
  const matched = revealed.some((item) => objectMatch(item, candidate));
  if (!matched) return fail(name, "widened", `${label} is not in the revealed allowlist`);
  return pass(name, `${label} matches a revealed allowlist entry`);
}

function objectMatch(allowed: Record<string, unknown>, candidate: Record<string, unknown>): boolean {
  if (typeof allowed["id"] === "string" && typeof candidate["id"] === "string") {
    return allowed["id"] === candidate["id"];
  }
  if (typeof allowed["name"] === "string" || typeof allowed["website"] === "string" || typeof allowed["legal_name"] === "string") {
    return Object.entries(allowed).every(([key, value]) => sameValue(value, candidate[key]));
  }
  return sameValue(allowed, candidate);
}

function executionWindow(constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  const name = "constraint:payment.execution_date";
  const when = asString(closed["execution_date"]);
  if (!when) return fail(name, "widened", "execution_date is absent, so the window cannot be shown to hold");
  const at = parseTimestamp(when);
  if (at === null) return fail(name, "malformed", "execution_date is not an ISO 8601 time with an offset");
  for (const bound of ["not_before", "not_after"] as const) {
    const text = constraint[bound];
    if (text === undefined) continue;
    if (typeof text !== "string" || parseTimestamp(text) === null) {
      return fail(name, "malformed", `${bound} is not an ISO 8601 time with an offset`);
    }
  }
  const notBefore = asString(constraint["not_before"]);
  const notAfter = asString(constraint["not_after"]);
  if (notBefore && at < parseTimestamp(notBefore)!) {
    return fail(name, "widened", "execution_date is before not_before");
  }
  if (notAfter && at > parseTimestamp(notAfter)!) {
    return fail(name, "widened", "execution_date is after not_after");
  }
  return pass(name, "execution_date is inside the window");
}

function paymentReference(constraint: Record<string, unknown>, parsed: ParsedChain): ConstraintResult {
  const name = "constraint:payment.reference";
  const expected = asString(constraint["conditional_transaction_id"]);
  if (!expected) return fail(name, "malformed", "conditional_transaction_id is required");
  const digest = parsed.hops
    .flatMap((hop) => hop.disclosures)
    .find((item) => isRecord(item.value) && item.value["vct"] === OPEN_CHECKOUT)?.digest;
  if (!digest) {
    return {
      check: {
        name,
        ok: null,
        detail: "the open checkout disclosure is not in this file, so the reference was not compared",
      },
      verdict: null,
    };
  }
  if (digest !== expected) {
    return fail(name, "tampered", "conditional_transaction_id does not match the open checkout disclosure digest");
  }
  return pass(name, "conditional_transaction_id matches the open checkout disclosure digest");
}

function recurrenceShape(constraint: Record<string, unknown>): ConstraintResult {
  const name = "constraint:payment.agent_recurrence";
  const frequency = asString(constraint["frequency"]);
  if (!frequency || !FREQUENCIES.has(frequency)) {
    return fail(name, "malformed", "frequency is not one of the published enum values");
  }
  const max = constraint["max_occurrences"];
  if (max !== undefined && (typeof max !== "number" || !Number.isSafeInteger(max) || max < 0)) {
    return fail(name, "malformed", "max_occurrences must be a non-negative integer when present");
  }
  return {
    check: {
      name,
      ok: null,
      detail: "frequency shape was checked. Spacing and occurrence count need prior presentations, which are not in the file.",
    },
    verdict: null,
  };
}

function budgetShape(constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  const name = "constraint:payment.budget";
  const currency = asString(constraint["currency"]);
  const max = constraint["max"];
  if (!currency || typeof max !== "number" || !Number.isFinite(max)) {
    return fail(name, "malformed", "budget needs a currency and a finite max");
  }
  const amount = closed["payment_amount"];
  if (isRecord(amount) && amount["currency"] !== currency) {
    return fail(name, "widened", `payment currency ${String(amount["currency"])} does not match budget ${currency}`);
  }
  if (
    isRecord(amount) &&
    typeof amount["amount"] === "number" &&
    Number.isSafeInteger(amount["amount"]) &&
    Number.isSafeInteger(max) &&
    amount["amount"] > max
  ) {
    return fail(name, "widened", `amount ${amount["amount"]} already exceeds integer budget max ${max}`);
  }
  return {
    check: {
      name,
      ok: null,
      detail:
        "cumulative spend is not in the file. A decimal budget max is not compared with integer minor units, because the published example and the amount schema disagree.",
    },
    verdict: null,
  };
}

function checkoutConstraint(type: string, constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  if (type === "checkout.allowed_merchants") return allowedMerchants(constraint, closed);
  return lineItems(constraint, closed);
}

function allowedMerchants(constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  const name = "constraint:checkout.allowed_merchants";
  const allowed = constraint["allowed"];
  if (!Array.isArray(allowed)) return fail(name, "malformed", "allowed must be an array");
  const revealed = allowed.filter((item) => isRecord(item) && !("..." in item));
  if (revealed.length === 0) {
    return fail(name, "widened", "allowed contains no revealed merchants, so the constraint is invalid");
  }
  const merchant = merchantOf(closed);
  if (!merchant) {
    return fail(
      name,
      "widened",
      "no merchant object was found on the closed mandate or under checkout_jwt payload.merchant. The payload schema is out of scope, so an absent merchant fails closed.",
    );
  }
  if (!revealed.some((item) => objectMatch(item, merchant))) {
    return fail(name, "widened", "merchant is not in the revealed allowlist");
  }
  return pass(name, "merchant matches a revealed allowlist entry. The merchant JWT signature was not required.");
}

function merchantOf(closed: Record<string, unknown>): Record<string, unknown> | null {
  if (isRecord(closed["merchant"])) return closed["merchant"];
  const token = asString(closed["checkout_jwt"]);
  if (!token) return null;
  const jwt = readJwt(token);
  if ("error" in jwt) return null;
  if (isRecord(jwt.payload["merchant"])) return jwt.payload["merchant"];
  return null;
}

function lineItems(constraint: Record<string, unknown>, closed: Record<string, unknown>): ConstraintResult {
  const name = "constraint:checkout.line_items";
  const items = constraint["items"];
  if (!Array.isArray(items) || items.length === 0) {
    return fail(name, "malformed", "items must be a non-empty array");
  }
  const requirements: Array<{ ids: string[]; qty: number }> = [];
  for (const item of items) {
    if (!isRecord(item) || !Array.isArray(item["acceptable_items"])) {
      return fail(name, "malformed", "each items entry needs acceptable_items");
    }
    const qty = item["quantity"];
    if (typeof qty !== "number" || !Number.isSafeInteger(qty) || qty < 1) {
      return fail(name, "malformed", "quantity must be a positive integer");
    }
    const ids = item["acceptable_items"]
      .filter((entry) => isRecord(entry) && typeof entry["id"] === "string")
      .map((entry) => (entry as Record<string, unknown>)["id"] as string);
    if (ids.length === 0) return fail(name, "widened", "an items entry has no revealed acceptable item ids");
    requirements.push({ ids, qty });
  }
  const checkoutItems = checkoutLineItems(closed);
  if (!checkoutItems) {
    return fail(
      name,
      "widened",
      "checkout_jwt payload has no line_items array. That payload is out of scope, so the constraint fails closed.",
    );
  }
  const matched = matchUnits(requirements, checkoutItems);
  if (matched === "too-large") {
    return fail(name, "malformed", `matching stopped above ${MATCH_UNIT_LIMIT} units`);
  }
  if (matched === "unfinished") {
    return {
      check: {
        name,
        ok: null,
        detail: "the line-item match did not finish within the step limit, so it was not treated as a pass",
      },
      verdict: null,
    };
  }
  if (!matched) return fail(name, "widened", "checkout line items do not cover the constraint exactly");
  return pass(name, "checkout line items match the constraint quantities exactly");
}

function checkoutLineItems(closed: Record<string, unknown>): Array<{ id: string; qty: number }> | null {
  const token = asString(closed["checkout_jwt"]);
  if (!token) return null;
  const jwt = readJwt(token);
  if ("error" in jwt) return null;
  const list = jwt.payload["line_items"] ?? jwt.payload["items"];
  if (!Array.isArray(list)) return null;
  const out: Array<{ id: string; qty: number }> = [];
  for (const item of list) {
    if (!isRecord(item) || typeof item["id"] !== "string") return null;
    const qty = item["quantity"];
    const count = qty === undefined ? 1 : qty;
    if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 1) return null;
    out.push({ id: item["id"], qty: count });
  }
  return out;
}

function matchUnits(
  requirements: Array<{ ids: string[]; qty: number }>,
  items: Array<{ id: string; qty: number }>,
): boolean | "too-large" | "unfinished" {
  const left: string[][] = [];
  const right: string[] = [];
  for (const requirement of requirements) {
    for (let i = 0; i < requirement.qty; i += 1) left.push(requirement.ids);
  }
  for (const item of items) {
    for (let i = 0; i < item.qty; i += 1) right.push(item.id);
  }
  if (left.length > MATCH_UNIT_LIMIT || right.length > MATCH_UNIT_LIMIT) return "too-large";
  if (left.length !== right.length) return false;
  const used = new Array<boolean>(right.length).fill(false);
  let steps = 0;
  function search(index: number): boolean | "unfinished" {
    if (index === left.length) return true;
    for (let j = 0; j < right.length; j += 1) {
      steps += 1;
      if (steps > MATCH_STEP_LIMIT) return "unfinished";
      if (used[j] || !left[index]!.includes(right[j]!)) continue;
      used[j] = true;
      const found = search(index + 1);
      if (found === true || found === "unfinished") return found;
      used[j] = false;
    }
    return false;
  }
  return search(0);
}

function checkReceipt(parsed: ParsedChain, options: VerifyOptions, checks: Check[], failures: Verdict[]): void {
  if (!parsed.receipt) {
    checks.push({
      name: "receipt",
      ok: null,
      detail: "no mandate receipt was supplied. Settlement is not claimed.",
    });
    return;
  }
  const jwt = readJwt(parsed.receipt);
  if ("error" in jwt) {
    failures.push("malformed");
    checks.push({ name: "receipt", ok: false, detail: jwt.error });
    return;
  }
  const reference = asString(jwt.payload["reference"]);
  const expected = sha256Base64url(parsed.hops[parsed.hops.length - 1]!.segment);
  if (!reference || reference !== expected) {
    failures.push("tampered");
    checks.push({
      name: "receipt",
      ok: false,
      detail: "receipt reference is not the SHA-256 of the final hop bytes",
    });
    return;
  }
  const status = asString(jwt.payload["status"]) ?? asString(jwt.payload["result"]);
  if (status !== "Success" && status !== "Error" && status !== "success" && status !== "error") {
    failures.push("malformed");
    checks.push({ name: "receipt", ok: false, detail: "receipt status is not Success or Error" });
    return;
  }
  const material = options.keys?.["ap2-receipt"];
  if (!material) {
    checks.push({
      name: "receipt",
      ok: null,
      detail: `reference matches the final hop and status is ${status}. The receipt signature was not checked. Pass --key ap2-receipt=<key>.`,
    });
    return;
  }
  const key = parseEcPublicKey(material);
  if (!key) {
    failures.push("malformed");
    checks.push({ name: "receipt", ok: false, detail: "ap2-receipt key is not a P-256 public key" });
    return;
  }
  const verified = verifyEs256Jwt(parsed.receipt, key);
  if ("error" in verified) {
    failures.push("tampered");
    checks.push({ name: "receipt", ok: false, detail: verified.error });
    return;
  }
  checks.push({
    name: "receipt",
    ok: true,
    detail: `receipt signature verified and reference matches. Status is ${status}.`,
  });
}

function cnfFromHop(hop: Hop): EcJwk | null {
  const direct = jwkOf(hop.payload["cnf"]);
  if (direct) return direct;
  for (const value of Object.values(hop.payload)) {
    const found = findCnf(value, new Set());
    if (found) return found;
  }
  return null;
}

function findCnf(value: unknown, seen: Set<unknown>): EcJwk | null {
  if (!value || typeof value !== "object" || seen.has(value)) return null;
  seen.add(value);
  if (isRecord(value) && value["cnf"]) {
    const key = jwkOf(value["cnf"]);
    if (key) return key;
  }
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  for (const inner of entries) {
    const found = findCnf(inner, seen);
    if (found) return found;
  }
  return null;
}

function firstCnf(hops: Hop[]): EcJwk | null {
  for (const hop of hops) {
    const key = cnfFromHop(hop);
    if (key) return key;
  }
  return null;
}

function jwkOf(cnf: unknown): EcJwk | null {
  if (!isRecord(cnf) || !isRecord(cnf["jwk"])) return null;
  const jwk = cnf["jwk"];
  if (jwk["kty"] !== "EC" || jwk["crv"] !== "P-256") return null;
  if (typeof jwk["x"] !== "string" || typeof jwk["y"] !== "string") return null;
  return { kty: "EC", crv: "P-256", x: jwk["x"], y: jwk["y"] };
}

function mandateByVct(mandates: Record<string, unknown>[], vct: string): Record<string, unknown> | null {
  return mandates.find((mandate) => mandate["vct"] === vct) ?? null;
}

function mandateId(mandates: Record<string, unknown>[]): string | null {
  for (const mandate of mandates) {
    const tx = asString(mandate["transaction_id"]) ?? asString(mandate["checkout_hash"]);
    if (tx) return tx;
  }
  return null;
}

function unixOf(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function sameValue(left: unknown, right: unknown): boolean {
  try {
    return canonicalJcs(left) === canonicalJcs(right);
  } catch (err) {
    if (!(err instanceof CanonicalError)) return false;
    return JSON.stringify(left) === JSON.stringify(right);
  }
}

function pass(name: string, detail: string): ConstraintResult {
  return { check: { name, ok: true, detail }, verdict: null };
}

function fail(name: string, verdict: Verdict, detail: string): ConstraintResult {
  return { check: { name, ok: false, detail }, verdict };
}

function summary(verdict: Verdict): string {
  if (verdict === "valid") return "AP2 mandate chain passed the checks that could be run offline.";
  if (verdict === "tampered") return "AP2 signature, disclosure, or hash binding failed.";
  if (verdict === "widened") return "Closed mandate is outside an open-mandate constraint.";
  if (verdict === "expired") return "AP2 mandate exp is at or before the verification clock.";
  return "AP2 input is not well formed.";
}

function malformed(detail: string): RecordResult {
  return finish(null, "malformed", [{ name: "parse", ok: false, detail }], detail);
}

function finish(id: string | null, verdict: Verdict, checks: Check[], text: string): RecordResult {
  return {
    index: 0,
    id,
    format: "ap2",
    verdict,
    label: labelFor(verdict),
    checks,
    summary: text,
  };
}
