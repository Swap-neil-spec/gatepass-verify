import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { evidenceFor } from "../src/evidence.js";
import { exitCode } from "../src/result.js";
import { verify } from "../src/verify.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const bin = join(root, "bin/gatepass-verify.js");
const now = new Date("2026-06-01T00:00:00Z");

function run(args: string[]): { status: number; stdout: string; stderr: string } {
  const child = spawnSync(process.execPath, [bin, ...args], { cwd: root, encoding: "utf8" });
  return { status: child.status ?? 1, stdout: child.stdout, stderr: child.stderr };
}

describe("evidence bundle", () => {
  it("names the approval, the approver, the time, what ran, and the verdict", () => {
    const bytes = readFileSync(join(root, "fixtures/ap2/payment-valid.json"));
    const keys = {
      ap2: readFileSync(join(root, "fixtures/ap2/issuer.public.jwk"), "utf8"),
      "ap2-receipt": readFileSync(join(root, "fixtures/ap2/receipt.public.jwk"), "utf8"),
    };
    const bundle = evidenceFor(bytes, { now, keys });
    assert.equal(bundle.schema, "gatepass-verify.evidence.v1");
    assert.equal(bundle.version, 1);
    assert.equal(bundle.ok, true);
    assert.equal(bundle.verificationClock, "2026-06-01T00:00:00.000Z");
    assert.equal(bundle.input.sha256.length, 64);
    const record = bundle.records[0];
    assert.ok(record);
    assert.equal(record.verdict, "valid");
    assert.equal(record.format, "ap2");
    assert.match(record.why, /AP2/);
    assert.equal(record.approved.fields["amount"], 15000);
    assert.equal(record.approved.fields["payee"], "Sample Shop");
    assert.equal(typeof record.approver.summary, "string");
    assert.ok(record.approver.summary.length > 0);
    assert.equal(typeof record.when.fields["exp"], "number");
    assert.match(String(record.executed.summary), /not a settlement/);
    assert.ok(record.unsupported.length > 0);
    assert.equal(record.checks.some((check) => check.name === "issuer_signature" && check.ok === true), true);
  });

  it("uses the same verdict as verify", () => {
    const bytes = readFileSync(join(root, "fixtures/gatepass/path-tampered.json"));
    const result = verify(bytes, { now });
    const bundle = evidenceFor(bytes, { now });
    assert.deepEqual(
      bundle.records.map((record) => record.verdict),
      result.records.map((record) => record.verdict),
    );
    assert.equal(bundle.ok, false);
    assert.match(bundle.records[0]?.why ?? "", /hash|signature|witness/i);
  });

  it("prints plain text and JSON from the command", () => {
    const text = run([
      "fixtures/keel/narrow.json",
      "--evidence",
      "--now",
      "2026-06-01T00:00:00Z",
    ]);
    assert.equal(text.status, 0);
    assert.match(text.stdout, /^Evidence/);
    assert.match(text.stdout, /Approved:/);
    assert.match(text.stdout, /Approver:/);
    assert.match(text.stdout, /When:/);
    assert.match(text.stdout, /Ran:/);
    assert.match(text.stdout, /Why:/);
    assert.equal(text.stdout.includes("{"), false);

    const json = run([
      "fixtures/ap2/payment-widened.json",
      "--evidence",
      "--json",
      "--now",
      "2026-06-01T00:00:00Z",
      "--key",
      "ap2=fixtures/ap2/issuer.public.jwk",
    ]);
    const parsed = JSON.parse(json.stdout) as { schema: string; ok: boolean; records: Array<{ verdict: string }> };
    assert.equal(parsed.schema, "gatepass-verify.evidence.v1");
    assert.equal(parsed.ok, false);
    assert.equal(parsed.records[0]?.verdict, "widened");
    assert.equal(json.status, 4);
    assert.equal(json.status, exitCode(verify(readFileSync(join(root, "fixtures/ap2/payment-widened.json")), {
      now,
      keys: { ap2: readFileSync(join(root, "fixtures/ap2/issuer.public.jwk"), "utf8") },
    })));
  });
});
