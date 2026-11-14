import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalJcs } from "../src/canonical.js";
import { base64urlEncode, sha256 } from "../src/crypto.js";
import { exitCode } from "../src/result.js";
import type { VerifyOptions, VerifyResult } from "../src/types.js";
import { verify } from "../src/verify.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

interface ExpectedCase {
  file: string;
  now?: string;
  key?: string[];
  verdicts: string[];
}

function loadExpected(): ExpectedCase[] {
  const parsed = JSON.parse(readFileSync(join(root, "fixtures/expected.json"), "utf8")) as {
    cases: ExpectedCase[];
  };
  return parsed.cases;
}

function optionsFor(item: ExpectedCase): VerifyOptions {
  const options: VerifyOptions = {};
  if (item.now) options.now = new Date(item.now);
  if (item.key) {
    const keys: Record<string, string> = {};
    for (const pair of item.key) {
      const eq = pair.indexOf("=");
      keys[pair.slice(0, eq)] = readFileSync(join(root, pair.slice(eq + 1)), "utf8");
    }
    options.keys = keys;
  }
  return options;
}

function runCase(item: ExpectedCase): VerifyResult {
  return verify(readFileSync(join(root, item.file)), optionsFor(item));
}

describe("fixtures", () => {
  for (const item of loadExpected()) {
    it(`${item.file} -> ${item.verdicts.join(", ")}`, () => {
      const result = runCase(item);
      assert.equal(result.schema, "gatepass-verify.result.v1");
      assert.equal(result.version, 1);
      assert.deepEqual(
        result.records.map((record) => record.verdict),
        item.verdicts,
      );
      assert.equal(result.ok, item.verdicts.every((verdict) => verdict === "valid"));
      for (const record of result.records) {
        assert.equal(record.label.length > 0, true);
        assert.equal(record.checks.length > 0, true);
        if (record.verdict === "valid") {
          assert.equal(
            record.checks.some((check) => check.ok === false),
            false,
          );
        }
      }
    });
  }
});

describe("published HAPS hashes", () => {
  const vectors: Array<[string, string]> = [
    [
      "fixtures/haps/published/action-intent.payment.transfer.sample.json",
      "fixtures/haps/published/expected_intent_hash.txt",
    ],
    [
      "fixtures/haps/published/signing-view.payment.transfer.sample.json",
      "fixtures/haps/published/expected_presentation_hash.txt",
    ],
    [
      "fixtures/haps/published/canonicalization-edge-cases.sample.json",
      "fixtures/haps/published/expected_canonicalization_edge_cases_hash.txt",
    ],
  ];
  for (const [input, expectedPath] of vectors) {
    it(input, () => {
      const value = JSON.parse(readFileSync(join(root, input), "utf8")) as unknown;
      const digest = `sha256:${base64urlEncode(sha256(Buffer.from(canonicalJcs(value), "utf8")))}`;
      const expected = readFileSync(join(root, expectedPath), "utf8").trim();
      assert.equal(digest, expected);
    });
  }
});

describe("fail closed", () => {
  it("rejects an empty input before parsing", () => {
    const result = verify(Buffer.alloc(0));
    assert.equal(result.error?.code, "empty_input");
    assert.equal(exitCode(result), 1);
  });

  it("rejects an oversized input before parsing", () => {
    const result = verify(Buffer.alloc(1024 * 1024 + 1));
    assert.equal(result.error?.code, "input_too_large");
    assert.equal(exitCode(result), 1);
  });

  it("does not guess an unknown object", () => {
    const result = verify(Buffer.from("{}\n"));
    assert.equal(result.records[0]?.verdict, "malformed");
    assert.equal(exitCode(result), 6);
  });

  it("honors an explicit format that does not match", () => {
    const bytes = readFileSync(join(root, "fixtures/keel/narrow.json"));
    const result = verify(bytes, { format: "haps", now: new Date("2026-06-01T00:00:00Z") });
    assert.equal(result.records[0]?.verdict, "malformed");
  });

  it("uses the caller clock for expiry", () => {
    const bytes = readFileSync(join(root, "fixtures/haps/valid.json"));
    const fresh = verify(bytes, { now: new Date("2026-01-09T00:01:00Z") });
    const later = verify(bytes, { now: new Date("2026-01-09T00:03:00Z") });
    assert.equal(fresh.records[0]?.verdict, "valid");
    assert.equal(later.records[0]?.verdict, "expired");
  });
});

describe("HAPS credential key", () => {
  it("checks an EdDSA credential when a key is supplied", () => {
    const seed = createHash("sha256").update("gatepass-verify fixture key").digest();
    const pkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]);
    const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const publicRaw = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" })).subarray(-32);
    const claims = JSON.parse(
      readFileSync(join(root, "fixtures/haps/published/consent-credential.webauthn-uv.sample.json"), "utf8"),
    ) as Record<string, unknown>;
    const action = JSON.parse(
      readFileSync(join(root, "fixtures/haps/published/action-intent.payment.transfer.sample.json"), "utf8"),
    ) as unknown;
    const header = base64urlEncode(Buffer.from(JSON.stringify({ alg: "EdDSA" })));
    const payload = base64urlEncode(Buffer.from(JSON.stringify(claims)));
    const signature = sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
    const body = {
      profile: "haps-v0.4",
      claims,
      action,
      credential: `${header}.${payload}.${signature}`,
    };
    const ok = verify(Buffer.from(JSON.stringify(body)), {
      now: new Date("2026-01-09T00:01:00Z"),
      keys: { haps: publicRaw.toString("base64url") },
    });
    assert.equal(ok.records[0]?.verdict, "valid");
    assert.equal(
      ok.records[0]?.checks.find((check) => check.name === "provider_signature")?.ok,
      true,
    );

    const forged = { ...claims, aud: "did:web:other.example" };
    const forgedBody = { ...body, claims: forged };
    const bad = verify(Buffer.from(JSON.stringify(forgedBody)), {
      now: new Date("2026-01-09T00:01:00Z"),
      keys: { haps: publicRaw.toString("base64url") },
    });
    assert.equal(bad.records[0]?.verdict, "tampered");
  });
});

describe("result shape", () => {
  it("matches the published verdict enum", () => {
    const schema = JSON.parse(readFileSync(join(root, "schema/result.v1.json"), "utf8")) as {
      properties: { records: { items: { properties: { verdict: { enum: string[] } } } } };
    };
    assert.deepEqual(schema.properties.records.items.properties.verdict.enum, [
      "valid",
      "tampered",
      "revoked",
      "widened",
      "expired",
      "malformed",
    ]);
  });
});
