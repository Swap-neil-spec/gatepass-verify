/**
 * Writes AP2, Verifiable Intent, and decision-record fixtures.
 * Run after `npm run build`.
 * The signing keys are fixture keys. Do not use them for a real record.
 */
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalCodePoint } from "../dist/src/canonical.js";
import { sha256Base64url, sha256Hex } from "../dist/src/crypto.js";
import { l3PresentationHash } from "../dist/src/formats/vi.js";
import { splitChain } from "../dist/src/sdjwt.js";
import { verify } from "../dist/src/verify.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const NOW = Date.parse("2026-06-01T00:00:00Z");
const NOW_S = Math.floor(NOW / 1000);

const issuer = jwk("EC", "P-256", "o6ZwcdRBahHRKj0hYPDNuUjhqzEmmsLrvhp06oKuG-E", "H3AN4wueEj2DoTvgBYkkphwFDRsizUvECdk4CKwaESw", "7lvHpvkoKVe273AoE-ut9l8x8e0CFVfgv2dUQgBiX8Q");
const user = jwk("EC", "P-256", "ML_ZmJeMrIlwWkFdyAraSwHFd2_nhvIo4sAvxjtblz4", "m4KL6BItaiUHTEUS0bTayYQ-YAulvyB6ArcLJjBonpE", "geMwMKrnBdC75KDzLXwRmtRabP3ndPoXMKXVK2Gk93s");
const agent = jwk("EC", "P-256", "X6Xfzbb2R6-IAREPjvARlgxr3oJfy5zIZGPYK2ffrAc", "EF5zBqtRH-kakwj1LSrMfi7Xm_PYV727QTkGAf1ZsPk", "WmMrbOQW983hPOE8OK4xb6EQy32ZRLar97v6ntjCco8");
const passkey = jwk("EC", "P-256", "RiTWpH3eYt08mDxW71gskKmWkJ0ojpCbQpU-w1NQ-vk", "J1LZEIoEjb98HlPoJQxglsiakLmaCknCwt6ThrKJAdM", "0Y6BYcYfZHwzVxmjUHlI_vRDQ3M_9pxH2MzHorNj33E");
const merchant = jwk("EC", "P-256", "2aalM_oTxIjt6zl6R9PSMIrAMpXjkLuTMc0QHo4xzGQ", "2q7iChkOOUd7CmVxzvDg_pT2moLc3GXCxJDFV0P17ow", "ucXBToY2397xEIpe5oR7W_m__fYV22btGDfdUhUv-_0");
const receiptKey = jwk("EC", "P-256", "UXKmMLvFaKLXCIxwBqDjA6ab_M19pp-LMLJW2QFuwAg", "JqeOybdKlYlbXSMAHb3lDNryYZ9f4ZaEK5w9Ybih-3U", "8yINxvaUcf5JThHV3ZQFh6Istq_xHy-LGTwQSO62wNg");

const edSeed = createHash("sha256").update("gatepass-verify decision record fixture key").digest();
const edPrivate = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), edSeed]),
  format: "der",
  type: "pkcs8",
});
const edPublic = Buffer.from(createPublicKey(edPrivate).export({ format: "der", type: "spki" })).subarray(-32);
const edPublicB64 = edPublic.toString("base64url");

function jwk(kty, crv, x, y, d) {
  return { kty, crv, x, y, d };
}

function publicJwk(key) {
  return { kty: key.kty, crv: key.crv, x: key.x, y: key.y };
}

function b64url(value) {
  const bytes = typeof value === "string" ? Buffer.from(value) : value;
  return Buffer.from(bytes).toString("base64url");
}

function signEs256(header, payload, privateJwk) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
  return `${input}.${signature.toString("base64url")}`;
}

function signMessage(message, privateJwk) {
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  return sign("sha256", message, { key, dsaEncoding: "ieee-p1363" });
}

function disclosure(salt, name, value) {
  const body = name === undefined ? [salt, value] : [salt, name, value];
  return b64url(JSON.stringify(body));
}

function digest(segment) {
  return createHash("sha256").update(segment).digest("base64url");
}

function sdJwt(header, payload, privateJwk, disclosures) {
  const jwt = signEs256(header, payload, privateJwk);
  return `${jwt}~${disclosures.join("~")}~`;
}

function joinChain(hops) {
  return hops.join("~~");
}

function repaired(chain) {
  const parts = splitChain(chain);
  if ("error" in parts) throw new Error(parts.error);
  return parts;
}

const shop = { id: "shop-1", name: "Sample Shop", website: "https://shop.example" };
const instrument = { id: "card-1", type: "card", description: "Sample card 4242" };

function paymentChain(opts) {
  const payeeDisc = disclosure("salt-payee", undefined, shop);
  const openMandate = {
    vct: "mandate.payment.open.1",
    constraints: [
      { type: "payment.amount_range", currency: "USD", min: 0, max: opts.max ?? 20000 },
      { type: "payment.allowed_payees", allowed: [{ "...": digest(payeeDisc) }] },
      ...(opts.extraConstraints ?? []),
    ],
    cnf: { jwk: publicJwk(agent) },
    iat: NOW_S - 60,
    exp: opts.openExp ?? NOW_S + 3600,
  };
  const openDisc = disclosure("salt-open", undefined, openMandate);
  const root = sdJwt(
    { alg: "ES256", typ: "dc+sd-jwt", kid: "fixture-issuer" },
    {
      iss: "https://issuer.example",
      iat: NOW_S - 120,
      exp: NOW_S + 86400,
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(openDisc) }],
    },
    issuer,
    [payeeDisc, openDisc],
  );
  const closedMandate = {
    vct: "mandate.payment.1",
    transaction_id: "tx-sample-1",
    payee: shop,
    payment_amount: { currency: "USD", amount: opts.amount ?? 15000 },
    payment_instrument: instrument,
    iat: NOW_S - 30,
    exp: opts.closedExp ?? NOW_S + 3600,
  };
  const closedDisc = disclosure("salt-closed", undefined, closedMandate);
  const leafPayload = {
    sd_hash: sha256Base64url(root),
    iat: NOW_S - 30,
    exp: opts.closedExp ?? NOW_S + 3600,
    _sd_alg: "sha-256",
    delegate_payload: [{ "...": digest(closedDisc) }],
  };
  const leaf = sdJwt(
    { alg: "ES256", typ: "kb+sd-jwt", kid: "fixture-agent" },
    leafPayload,
    agent,
    [closedDisc],
  );
  const chain = joinChain([root, leaf]);
  const hops = repaired(chain);
  if (hops[0] !== root) throw new Error("chain repair changed the first hop");
  return { chain, hops };
}

function checkoutJwt(lineId) {
  return signEs256(
    { alg: "ES256", typ: "JWT" },
    {
      merchant: shop,
      line_items: [{ id: lineId, quantity: 1 }],
    },
    merchant,
  );
}

function checkoutChain(lineId) {
  const itemDisc = disclosure("salt-item", undefined, { id: "sku-1", title: "Sample item" });
  const openMandate = {
    vct: "mandate.checkout.open.1",
    constraints: [
      {
        type: "checkout.allowed_merchants",
        allowed: [shop],
      },
      {
        type: "checkout.line_items",
        items: [
          {
            id: "line-1",
            quantity: 1,
            acceptable_items: [{ "...": digest(itemDisc) }],
          },
        ],
      },
    ],
    cnf: { jwk: publicJwk(agent) },
    iat: NOW_S - 60,
    exp: NOW_S + 3600,
  };
  const openDisc = disclosure("salt-open-checkout", undefined, openMandate);
  const root = sdJwt(
    { alg: "ES256", typ: "dc+sd-jwt", kid: "fixture-issuer" },
    {
      iss: "https://issuer.example",
      iat: NOW_S - 120,
      exp: NOW_S + 86400,
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(openDisc) }],
    },
    issuer,
    [itemDisc, openDisc],
  );
  const jwt = checkoutJwt(lineId);
  const closedMandate = {
    vct: "mandate.checkout.1",
    checkout_jwt: jwt,
    checkout_hash: sha256Base64url(jwt),
    iat: NOW_S - 30,
    exp: NOW_S + 3600,
  };
  const closedDisc = disclosure("salt-closed-checkout", undefined, closedMandate);
  const leaf = sdJwt(
    { alg: "ES256", typ: "kb+sd-jwt" },
    {
      sd_hash: sha256Base64url(root),
      iat: NOW_S - 30,
      exp: NOW_S + 3600,
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(closedDisc) }],
    },
    agent,
    [closedDisc],
  );
  return joinChain([root, leaf]);
}

function receiptFor(segment) {
  return signEs256(
    { alg: "ES256", typ: "JWT", kid: "fixture-receipt" },
    {
      iss: "https://verifier.example",
      status: "Success",
      reference: sha256Base64url(segment),
      iat: NOW_S,
      payment_id: "pay-sample-1",
    },
    receiptKey,
  );
}

function flipSignature(token) {
  const parts = token.split("~");
  const jwt = parts[0].split(".");
  const last = jwt[2];
  const replacement = last.endsWith("A") ? "B" : "A";
  jwt[2] = `${last.slice(0, -1)}${replacement}`;
  parts[0] = jwt.join(".");
  return parts.join("~");
}

function l1Token(exp = NOW_S + 86400 * 30) {
  const email = disclosure("salt-email", "email", "person@example.com");
  return sdJwt(
    { alg: "ES256", typ: "sd+jwt", kid: "fixture-issuer" },
    {
      iss: "https://issuer.example",
      sub: "person-1",
      iat: NOW_S - 86400,
      exp,
      vct: "https://credentials.mastercard.com/card",
      cnf: { jwk: publicJwk(user) },
      pan_last_four: "4242",
      scheme: "mastercard",
      _sd_alg: "sha-256",
      _sd: [digest(email)],
    },
    issuer,
    [email],
  );
}

function immediateVi(l1, amount) {
  const jwt = checkoutJwt("sku-1");
  const hash = sha256Base64url(jwt);
  const checkout = disclosure("salt-checkout", undefined, {
    vct: "mandate.checkout.1",
    checkout_jwt: jwt,
    checkout_hash: hash,
  });
  const payment = disclosure("salt-payment", undefined, {
    vct: "mandate.payment.1",
    payment_instrument: instrument,
    payment_amount: { currency: "USD", amount },
    payee: { name: shop.name, website: shop.website },
    transaction_id: hash,
  });
  const l2 = sdJwt(
    { alg: "ES256", typ: "kb-sd-jwt" },
    {
      nonce: "nonce-immediate-1",
      aud: "https://network.example/authorize",
      iat: NOW_S - 30,
      exp: NOW_S + 600,
      sd_hash: sha256Base64url(l1),
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(checkout) }, { "...": digest(payment) }],
    },
    user,
    [checkout, payment],
  );
  return { l1, l2 };
}

function autonomousVi(l1, amount) {
  const agentJwk = { ...publicJwk(agent), kid: "holder-key-1" };
  const checkoutBody = {
    vct: "mandate.checkout.open.1",
    cnf: { jwk: agentJwk },
    constraints: [
      { type: "mandate.checkout.allowed_merchants", allowed: [shop] },
    ],
  };
  const checkout = disclosure("salt-open-checkout", undefined, checkoutBody);
  const paymentBody = {
    vct: "mandate.payment.open.1",
    cnf: { jwk: agentJwk },
    payment_instrument: instrument,
    constraints: [
      { type: "mandate.payment.amount_range", currency: "USD", min: 0, max: 30000 },
      { type: "mandate.payment.allowed_payees", allowed: [shop] },
      { type: "mandate.payment.reference", conditional_transaction_id: digest(checkout) },
    ],
  };
  const payment = disclosure("salt-open-payment", undefined, paymentBody);
  const l2 = sdJwt(
    { alg: "ES256", typ: "kb-sd-jwt+kb" },
    {
      nonce: "nonce-auto-1",
      aud: "https://network.example/authorize",
      iat: NOW_S - 60,
      exp: NOW_S + 86400,
      sd_hash: sha256Base64url(l1),
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(checkout) }, { "...": digest(payment) }],
    },
    user,
    [checkout, payment],
  );
  const jwt = checkoutJwt("sku-1");
  const hash = sha256Base64url(jwt);
  const l3aDisc = disclosure("salt-l3a", undefined, {
    vct: "mandate.payment.1",
    payment_instrument: instrument,
    payment_amount: { currency: "USD", amount },
    payee: shop,
    transaction_id: hash,
  });
  const l3bDisc = disclosure("salt-l3b", undefined, {
    vct: "mandate.checkout.1",
    checkout_jwt: jwt,
    checkout_hash: hash,
  });
  const l3Header = { alg: "ES256", typ: "kb-sd-jwt", kid: "holder-key-1" };
  const l3Times = { iat: NOW_S - 10, exp: NOW_S + 300 };
  const l3a = sdJwt(
    l3Header,
    {
      nonce: "nonce-l3a",
      aud: "https://network.example/authorize",
      ...l3Times,
      sd_hash: l3PresentationHash(l2, "mandate.payment.open.1"),
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(l3aDisc) }],
    },
    agent,
    [l3aDisc],
  );
  const l3b = sdJwt(
    l3Header,
    {
      nonce: "nonce-l3b",
      aud: "https://shop.example/checkout",
      ...l3Times,
      sd_hash: l3PresentationHash(l2, "mandate.checkout.open.1"),
      _sd_alg: "sha-256",
      delegate_payload: [{ "...": digest(l3bDisc) }],
    },
    agent,
    [l3bDisc],
  );
  return { profile: "verifiable-intent-v0.1", l1, l2, l3a, l3b };
}

function hashesFor(args, path, tool) {
  return {
    argsHash: sha256Hex(canonicalCodePoint(args)),
    resolvedPathHash: sha256Hex(path),
    toolDefinitionHash: sha256Hex(canonicalCodePoint(tool)),
  };
}

function passkeyMandate(scopes, caps, expiresAt) {
  const core = {
    id: "mandate-1",
    scopes,
    caps,
    expiresAt,
    publicKey: publicJwk(passkey),
  };
  const canonical = canonicalCodePoint(core);
  const challenge = sha256Base64url(canonical);
  const clientJson = JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin: "https://gate.example",
  });
  const authData = Buffer.concat([
    createHash("sha256").update("gate.example").digest(),
    Buffer.from([0x05, 0, 0, 0, 1]),
  ]);
  const message = Buffer.concat([authData, createHash("sha256").update(clientJson).digest()]);
  const signature = signMessage(message, passkey);
  return {
    ...core,
    clientDataJSON: b64url(clientJson),
    authenticatorData: authData.toString("base64url"),
    signature: signature.toString("base64url"),
  };
}

function signRecord(record) {
  const signature = sign(null, Buffer.from(canonicalCodePoint(record)), edPrivate).toString("base64url");
  return { ...record, signature };
}

function withChain(record, seq, prev) {
  const body = { ...record, chain: { seq, prev } };
  const hash = sha256Hex(canonicalCodePoint(body));
  return { ...body, chain: { seq, prev, hash } };
}

function decisionRecord(opts) {
  const approvedHashes = hashesFor(opts.approvedArgs, opts.approvedPath, opts.approvedTool);
  const executedHashes = hashesFor(opts.executedArgs, opts.executedPath, opts.executedTool);
  const base = {
    id: opts.id,
    alg: "Ed25519",
    publicKey: edPublicB64,
    issuedAt: "2026-06-01T00:00:00Z",
    expiresAt: "2026-12-01T00:00:00Z",
    approver: { id: "person-1" },
    approved: { tool: opts.tool, ...approvedHashes },
    executed: {
      tool: opts.executedToolName ?? opts.tool,
      ...executedHashes,
      amount: opts.amount,
      currency: "USD",
      count: opts.count ?? 1,
    },
    mandate: passkeyMandate(
      opts.scopes ?? [opts.tool],
      { amount: opts.cap ?? 5000, currency: "USD", count: opts.countCap ?? 4 },
      opts.mandateExpires ?? "2026-12-01T00:00:00Z",
    ),
  };
  if (opts.materials) base.materials = opts.materials;
  const chained = opts.chain ? withChain(base, opts.chain.seq, opts.chain.prev) : base;
  return signRecord(chained);
}

const sampleArgs = { path: "/tmp/sample.txt", bytes: 5 };
const sampleTool = { name: "fs.write", description: "Write one file" };
const samplePath = "/tmp/sample.txt";
const otherTool = { name: "fs.write", description: "Write any file" };

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const ap2Dir = join(root, "fixtures/ap2");
const viDir = join(root, "fixtures/vi");
const gpDir = join(root, "fixtures/gatepass");
for (const dir of [ap2Dir, viDir, gpDir]) mkdirSync(dir, { recursive: true });

writeJson(join(ap2Dir, "issuer.public.jwk"), publicJwk(issuer));
writeJson(join(ap2Dir, "receipt.public.jwk"), publicJwk(receiptKey));
writeJson(join(viDir, "issuer.public.jwk"), publicJwk(issuer));
writeFileSync(join(gpDir, "record.public.txt"), `${edPublicB64}\n`);

const validPayment = paymentChain({});
const validHops = repaired(validPayment.chain);
writeJson(join(ap2Dir, "payment-valid.json"), {
  profile: "ap2-mandate",
  chain: validPayment.chain,
  receipt: receiptFor(validHops[validHops.length - 1]),
});
writeFileSync(join(ap2Dir, "payment-valid.txt"), `${validPayment.chain}\n`);

const tamperedBuilt = paymentChain({});
const tamperedHops = [...tamperedBuilt.hops];
tamperedHops[tamperedHops.length - 1] = flipSignature(tamperedHops[tamperedHops.length - 1]);
writeJson(join(ap2Dir, "payment-tampered.json"), {
  profile: "ap2-mandate",
  chain: joinChain(tamperedHops),
});

writeJson(join(ap2Dir, "payment-widened.json"), {
  profile: "ap2-mandate",
  chain: paymentChain({ amount: 50000 }).chain,
});
writeJson(join(ap2Dir, "payment-expired.json"), {
  profile: "ap2-mandate",
  chain: paymentChain({ closedExp: NOW_S - 86400, openExp: NOW_S - 86400 }).chain,
});
writeJson(join(ap2Dir, "payment-unknown-constraint.json"), {
  profile: "ap2-mandate",
  chain: paymentChain({ extraConstraints: [{ type: "payment.not_in_the_spec", limit: 1 }] }).chain,
});
writeJson(join(ap2Dir, "malformed.json"), { profile: "ap2-mandate" });
writeJson(join(ap2Dir, "checkout-valid.json"), {
  profile: "ap2-mandate",
  chain: checkoutChain("sku-1"),
});
writeJson(join(ap2Dir, "checkout-widened.json"), {
  profile: "ap2-mandate",
  chain: checkoutChain("sku-2"),
});

const l1 = l1Token();
writeJson(join(viDir, "immediate-valid.json"), {
  profile: "verifiable-intent-v0.1",
  ...immediateVi(l1, 27999),
});
const immediateTampered = immediateVi(l1, 27999);
writeJson(join(viDir, "immediate-tampered.json"), {
  profile: "verifiable-intent-v0.1",
  l1,
  l2: flipSignature(immediateTampered.l2),
});
writeJson(join(viDir, "autonomous-valid.json"), autonomousVi(l1, 15000));
writeJson(join(viDir, "autonomous-widened.json"), autonomousVi(l1, 50000));
writeJson(join(viDir, "autonomous-expired.json"), autonomousVi(l1Token(NOW_S - 86400), 15000));
writeJson(join(viDir, "malformed.json"), { profile: "verifiable-intent-v0.1" });

const materials = {
  approvedArgs: sampleArgs,
  executedArgs: sampleArgs,
  approvedPath: samplePath,
  executedPath: samplePath,
  approvedTool: sampleTool,
  executedTool: sampleTool,
};
const first = decisionRecord({
  id: "rec-1",
  tool: "fs.write",
  approvedArgs: sampleArgs,
  executedArgs: sampleArgs,
  approvedPath: samplePath,
  executedPath: samplePath,
  approvedTool: sampleTool,
  executedTool: sampleTool,
  amount: 1000,
  materials,
  chain: { seq: 0, prev: "0".repeat(64) },
});
const second = decisionRecord({
  id: "rec-2",
  tool: "fs.write",
  approvedArgs: sampleArgs,
  executedArgs: sampleArgs,
  approvedPath: samplePath,
  executedPath: samplePath,
  approvedTool: sampleTool,
  executedTool: sampleTool,
  amount: 2000,
  chain: { seq: 1, prev: first.chain.hash },
});
const witness = { logId: "sample-log", length: 2, headHash: second.chain.hash };
writeJson(join(gpDir, "chain-valid.json"), {
  profile: "gatepass-decision-record",
  witness,
  records: [first, second],
});
writeJson(join(gpDir, "path-tampered.json"), {
  profile: "gatepass-decision-record",
  records: [
    decisionRecord({
      id: "rec-path",
      tool: "fs.write",
      approvedArgs: sampleArgs,
      executedArgs: sampleArgs,
      approvedPath: samplePath,
      executedPath: "/tmp/other.txt",
      approvedTool: sampleTool,
      executedTool: sampleTool,
      amount: 1000,
    }),
  ],
});
writeJson(join(gpDir, "tool-tampered.json"), {
  profile: "gatepass-decision-record",
  records: [
    decisionRecord({
      id: "rec-tool",
      tool: "fs.write",
      approvedArgs: sampleArgs,
      executedArgs: sampleArgs,
      approvedPath: samplePath,
      executedPath: samplePath,
      approvedTool: sampleTool,
      executedTool: otherTool,
      amount: 1000,
    }),
  ],
});
writeJson(join(gpDir, "widened.json"), {
  profile: "gatepass-decision-record",
  records: [
    decisionRecord({
      id: "rec-cap",
      tool: "fs.write",
      approvedArgs: sampleArgs,
      executedArgs: sampleArgs,
      approvedPath: samplePath,
      executedPath: samplePath,
      approvedTool: sampleTool,
      executedTool: sampleTool,
      amount: 9000,
      cap: 5000,
    }),
  ],
});
writeJson(join(gpDir, "expired.json"), {
  profile: "gatepass-decision-record",
  records: [
    decisionRecord({
      id: "rec-old",
      tool: "fs.write",
      approvedArgs: sampleArgs,
      executedArgs: sampleArgs,
      approvedPath: samplePath,
      executedPath: samplePath,
      approvedTool: sampleTool,
      executedTool: sampleTool,
      amount: 1000,
      mandateExpires: "2026-05-01T00:00:00Z",
    }),
  ],
});
writeJson(join(gpDir, "witness-truncated.json"), {
  profile: "gatepass-decision-record",
  witness,
  records: [first],
});
writeJson(join(gpDir, "malformed.json"), {
  profile: "gatepass-decision-record",
  id: "rec-bad",
  alg: "Ed25519",
});

const clock = new Date("2026-06-01T00:00:00Z");
const ap2Keys = { ap2: JSON.stringify(publicJwk(issuer)), "ap2-receipt": JSON.stringify(publicJwk(receiptKey)) };
const viKeys = { "verifiable-intent": JSON.stringify(publicJwk(issuer)) };
const cases = [
  ["fixtures/ap2/payment-valid.json", ["valid"], ap2Keys],
  ["fixtures/ap2/payment-valid.txt", ["valid"], { ap2: JSON.stringify(publicJwk(issuer)) }],
  ["fixtures/ap2/payment-tampered.json", ["tampered"], ap2Keys],
  ["fixtures/ap2/payment-widened.json", ["widened"], ap2Keys],
  ["fixtures/ap2/payment-expired.json", ["expired"], ap2Keys],
  ["fixtures/ap2/payment-unknown-constraint.json", ["widened"], ap2Keys],
  ["fixtures/ap2/malformed.json", ["malformed"], ap2Keys],
  ["fixtures/ap2/checkout-valid.json", ["valid"], ap2Keys],
  ["fixtures/ap2/checkout-widened.json", ["widened"], ap2Keys],
  ["fixtures/vi/immediate-valid.json", ["valid"], viKeys],
  ["fixtures/vi/immediate-tampered.json", ["tampered"], viKeys],
  ["fixtures/vi/autonomous-valid.json", ["valid"], viKeys],
  ["fixtures/vi/autonomous-widened.json", ["widened"], viKeys],
  ["fixtures/vi/autonomous-expired.json", ["expired"], viKeys],
  ["fixtures/vi/malformed.json", ["malformed"], viKeys],
  ["fixtures/gatepass/chain-valid.json", ["valid", "valid"], {}],
  ["fixtures/gatepass/path-tampered.json", ["tampered"], {}],
  ["fixtures/gatepass/tool-tampered.json", ["tampered"], {}],
  ["fixtures/gatepass/widened.json", ["widened"], {}],
  ["fixtures/gatepass/expired.json", ["expired"], {}],
  ["fixtures/gatepass/witness-truncated.json", ["tampered"], {}],
  ["fixtures/gatepass/malformed.json", ["malformed"], {}],
];

let failed = 0;
for (const [file, verdicts, keys] of cases) {
  const bytes = await import("node:fs").then((fs) => fs.readFileSync(join(root, file)));
  const result = verify(bytes, { now: clock, keys });
  const actual = result.records.map((record) => record.verdict);
  if (JSON.stringify(actual) !== JSON.stringify(verdicts)) {
    failed += 1;
    process.stderr.write(`${file}\n  expected ${verdicts.join(",")}\n  actual   ${actual.join(",")}\n`);
    for (const record of result.records) {
      for (const check of record.checks) {
        if (check.ok !== true) process.stderr.write(`  ${check.ok === false ? "fail" : "skip"} ${check.name}: ${check.detail}\n`);
      }
    }
  }
}
if (failed > 0) process.exit(1);
process.stdout.write(`wrote mandate fixtures, ${cases.length} self-checks passed\n`);
