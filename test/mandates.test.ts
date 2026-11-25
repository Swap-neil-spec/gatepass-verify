import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalCodePoint } from "../src/canonical.js";
import { disclosureDigest, reconstructSdJwt, splitChain, splitSdJwt } from "../src/sdjwt.js";
import { verify } from "../src/verify.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const now = new Date("2026-06-01T00:00:00Z");
const issuer = readFileSync(join(root, "fixtures/ap2/issuer.public.jwk"), "utf8");

function read(path: string): Buffer {
  return readFileSync(join(root, path));
}

describe("sd-jwt chain bytes", () => {
  it("puts a terminator tilde back on the previous hop", () => {
    const hops = splitChain("aaa.bbb.ccc~ZGlzYw~~~ddd.eee.fff~");
    assert.ok(!("error" in hops));
    if ("error" in hops) return;
    assert.deepEqual(hops, ["aaa.bbb.ccc~ZGlzYw~", "ddd.eee.fff~"]);
  });

  it("hashes a disclosure the way RFC 9901 does, over the wire segment", () => {
    const segment = Buffer.from(JSON.stringify(["salt", "color", "red"])).toString("base64url");
    const expected = createHash("sha256").update(segment).digest("base64url");
    assert.equal(disclosureDigest(segment), expected);
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "sd+jwt" })).toString("base64url");
    const payload = {
      _sd_alg: "sha-256",
      _sd: [expected],
    };
    const payloadPart = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const token = `${header}.${payloadPart}.c2ln~${segment}~`;
    const parts = splitSdJwt(token);
    assert.ok(!("error" in parts));
    if ("error" in parts) return;
    const rebuilt = reconstructSdJwt(parts);
    assert.ok(!("error" in rebuilt));
    if ("error" in rebuilt) return;
    assert.equal(rebuilt.payload["color"], "red");
  });

  it("rejects a disclosure that no hash binds", () => {
    const extra = Buffer.from(JSON.stringify(["other", "color", "blue"])).toString("base64url");
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ vct: "mandate.payment.1" })).toString("base64url");
    const parts = splitSdJwt(`${header}.${payload}.c2ln~${extra}~`);
    assert.ok(!("error" in parts));
    if ("error" in parts) return;
    const rebuilt = reconstructSdJwt(parts);
    assert.ok("error" in rebuilt);
  });
});

describe("adversarial receipts", () => {
  it("does not treat a Keel permit as an AP2 mandate", () => {
    const result = verify(read("fixtures/keel/narrow.json"), { now });
    assert.equal(result.records[0]?.format, "keel-permit");
    assert.equal(result.records[0]?.verdict, "valid");
  });

  it("fails a forced format that does not match the file", () => {
    const result = verify(read("fixtures/keel/narrow.json"), { now, format: "ap2" });
    assert.equal(result.records[0]?.verdict, "malformed");
    assert.equal(result.records[0]?.format, "ap2");
  });

  it("rejects a non-ES256 first hop instead of skipping it", () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ vct: "mandate.payment.1" })).toString("base64url");
    const body = {
      profile: "ap2-mandate",
      chain: `${header}.${payload}.c2ln~`,
    };
    const result = verify(Buffer.from(JSON.stringify(body)), { now, keys: { ap2: issuer } });
    assert.equal(result.records[0]?.verdict, "malformed");
    assert.equal(
      result.records[0]?.checks.some((check) => check.name === "issuer_signature" && check.ok === false),
      true,
    );
  });

  it("rejects the issuer signature when the supplied key is wrong", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const wrong = JSON.stringify(publicKey.export({ format: "jwk" }));
    const result = verify(read("fixtures/ap2/payment-valid.json"), { now, keys: { ap2: wrong } });
    assert.equal(result.records[0]?.verdict, "tampered");
  });

  it("skips the issuer signature when no key is supplied and does not call that a pass", () => {
    const result = verify(read("fixtures/ap2/payment-valid.json"), { now });
    const check = result.records[0]?.checks.find((item) => item.name === "issuer_signature");
    assert.equal(check?.ok, null);
    assert.match(check?.detail ?? "", /not checked/);
    assert.equal(
      result.records[0]?.checks.some((item) => item.name === "hop_signature" && item.ok === true),
      true,
    );
  });

  it("rejects an unbound disclosure added to a valid chain", () => {
    const file = JSON.parse(read("fixtures/ap2/payment-valid.json").toString("utf8")) as { chain: string };
    const extra = Buffer.from(JSON.stringify(["salt", "note", "forged"])).toString("base64url");
    file.chain = `${file.chain.slice(0, file.chain.indexOf("~"))}~${extra}${file.chain.slice(file.chain.indexOf("~"))}`;
    const result = verify(Buffer.from(JSON.stringify({ profile: "ap2-mandate", chain: file.chain })), {
      now,
      keys: { ap2: issuer },
    });
    assert.notEqual(result.records[0]?.verdict, "valid");
  });

  it("rejects a truncated decision-record chain against the witness head", () => {
    const result = verify(read("fixtures/gatepass/witness-truncated.json"), { now });
    assert.equal(result.records[0]?.verdict, "tampered");
    assert.equal(
      result.records[0]?.checks.some((check) => check.name === "witness" && check.ok === false),
      true,
    );
  });

  it("rejects a pinned decision-record key that does not match", () => {
    const seed = createHash("sha256").update("some other fixture key").digest();
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
    const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const publicRaw = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" })).subarray(-32);
    const result = verify(read("fixtures/gatepass/chain-valid.json"), {
      now,
      keys: { gatepass: publicRaw.toString("base64url") },
    });
    assert.equal(result.records[0]?.verdict, "tampered");
    assert.equal(
      result.records[0]?.checks.some((check) => check.name === "pinned_key" && check.ok === false),
      true,
    );
  });

  it("keeps a valid chain valid when the embedded key is pinned", () => {
    const publicKey = readFileSync(join(root, "fixtures/gatepass/record.public.txt"), "utf8");
    const result = verify(read("fixtures/gatepass/chain-valid.json"), {
      now,
      keys: { gatepass: publicKey },
    });
    assert.deepEqual(
      result.records.map((record) => record.verdict),
      ["valid", "valid"],
    );
    const names = result.records[0]?.checks.map((check) => check.name) ?? [];
    for (const name of ["signature", "mandate_signature", "resolvedPathHash", "toolDefinitionHash", "witness"]) {
      assert.equal(names.includes(name), true, name);
      assert.equal(
        result.records[0]?.checks.find((check) => check.name === name)?.ok,
        true,
        name,
      );
    }
  });

  it("does not throw on truncated or empty cryptographic text", () => {
    for (const body of ["", "~~", "~~~~", "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJtYW5kYXRlLnBheW1lbnQuMSJ9.", "{", "null"]) {
      const result = verify(Buffer.from(body));
      assert.equal(result.records[0]?.verdict === "malformed" || result.error !== undefined, true);
    }
    const nested = { profile: "ap2-mandate", chain: "not-a-jwt" };
    const result = verify(Buffer.from(JSON.stringify(nested)), { now });
    assert.equal(result.records[0]?.verdict, "malformed");
  });

  it("rejects a passkey assertion whose challenge does not bind the mandate", () => {
    const file = JSON.parse(read("fixtures/gatepass/chain-valid.json").toString("utf8")) as {
      records: Array<Record<string, unknown>>;
      witness: unknown;
      profile: string;
    };
    const record = file.records[0];
    assert.ok(record);
    const mandate = record["mandate"] as { clientDataJSON: string; signature: string };
    const client = JSON.parse(Buffer.from(mandate.clientDataJSON, "base64url").toString("utf8")) as {
      challenge: string;
    };
    client.challenge = "not-the-mandate";
    mandate.clientDataJSON = Buffer.from(JSON.stringify(client)).toString("base64url");
    const seed = createHash("sha256").update("gatepass-verify decision record fixture key").digest();
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
      format: "der",
      type: "pkcs8",
    });
    const body = { ...record };
    delete body["signature"];
    const signature = sign(null, Buffer.from(canonicalCodePoint(body)), privateKey).toString("base64url");
    record["signature"] = signature;
    const result = verify(Buffer.from(JSON.stringify(file)), { now });
    assert.equal(result.records[0]?.verdict, "tampered");
    assert.equal(
      result.records[0]?.checks.some((check) => check.name === "mandate_signature" && check.ok === false),
      true,
    );
  });
});
