import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { exitCode } from "../src/result.js";
import type { VerifyResult } from "../src/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const bin = join(root, "bin/gatepass-verify.js");

function run(args: string[]): { status: number; stdout: string; stderr: string } {
  const child = spawnSync(process.execPath, [bin, ...args], {
    cwd: root,
    encoding: "utf8",
  });
  return {
    status: child.status ?? 1,
    stdout: child.stdout,
    stderr: child.stderr,
  };
}

describe("cli", () => {
  it("prints a human verdict for a narrow child", () => {
    const result = run(["fixtures/keel/narrow.json", "--now", "2026-06-01T00:00:00Z"]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Valid/);
    assert.match(result.stdout, /narrower than the parent/);
    assert.equal(result.stdout.includes("{"), false);
  });

  it("prints JSON and the exit code for a widened child", () => {
    const result = run(["fixtures/keel/widened.json", "--json", "--now", "2026-06-01T00:00:00Z"]);
    const parsed = JSON.parse(result.stdout) as VerifyResult;
    assert.equal(parsed.schema, "gatepass-verify.result.v1");
    assert.deepEqual(
      parsed.records.map((record) => record.verdict),
      ["valid", "widened"],
    );
    assert.equal(result.status, exitCode(parsed));
    assert.equal(result.status, 4);
  });

  it("checks a published flight log with a supplied key", () => {
    const result = run([
      "fixtures/afr/published/flight.jsonl",
      "--json",
      "--key",
      "afr=fixtures/afr/published/signing.pub",
    ]);
    const parsed = JSON.parse(result.stdout) as VerifyResult;
    assert.equal(parsed.ok, true);
    assert.equal(parsed.records.length, 16);
    assert.equal(result.status, 0);
  });

  it("rejects a missing file", () => {
    const result = run(["fixtures/missing.json"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /cannot read/);
  });

  it("shows help", () => {
    const result = run(["--help"]);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Exit codes/);
    assert.match(result.stdout, /--sample/);
  });

  it("checks the shipped sample from another working directory", () => {
    const result = spawnSync(process.execPath, [bin, "--sample"], {
      cwd: "/tmp",
      encoding: "utf8",
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Valid/);
    assert.match(result.stdout, /fixtures\/keel\/narrow\.json/);
  });

  it("lets --sample print JSON", () => {
    const result = spawnSync(process.execPath, [bin, "--sample", "--json"], {
      cwd: "/tmp",
      encoding: "utf8",
    });
    const parsed = JSON.parse(result.stdout) as VerifyResult;
    assert.equal(result.status, 0);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.records.every((record) => record.verdict === "valid"), true);
  });

  it("refuses --sample together with a file", () => {
    const result = run(["--sample", "fixtures/keel/narrow.json"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /pass --sample or a file/);
  });

});

describe("cli matches the library on every fixture", () => {
  it("agrees on verdicts and exit codes", () => {
    const expected = JSON.parse(readFileSync(join(root, "fixtures/expected.json"), "utf8")) as {
      cases: Array<{ file: string; now?: string; key?: string[] }>;
    };
    for (const item of expected.cases) {
      const args = [item.file, "--json"];
      if (item.now) args.push("--now", item.now);
      for (const key of item.key ?? []) args.push("--key", key);
      const result = run(args);
      const parsed = JSON.parse(result.stdout) as VerifyResult;
      assert.equal(result.status, exitCode(parsed), item.file);
    }
  });
});
