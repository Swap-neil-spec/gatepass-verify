import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const packed = spawnSync("npm", ["pack", "--json"], { cwd: root, encoding: "utf8" });
if (packed.status !== 0) {
  process.stderr.write(packed.stderr);
  process.exit(1);
}
const packedInfo = JSON.parse(packed.stdout);
const tarballName = (Array.isArray(packedInfo) ? packedInfo[0] : packedInfo).filename;
const tarball = join(root, tarballName);
const bytes = statSync(tarball).size;
const dir = mkdtempSync(join(tmpdir(), "gatepass-verify-"));
const installed = spawnSync("npm", ["install", "--ignore-scripts", tarball], {
  cwd: dir,
  encoding: "utf8",
});
if (installed.status !== 0) {
  process.stderr.write(installed.stdout + installed.stderr);
  process.exit(1);
}

const bin = join(dir, "node_modules", "gatepass-verify", "bin", "gatepass-verify.js");
const { exitCode } = await import(pathToFileURL(join(dir, "node_modules", "gatepass-verify", "dist", "src", "index.js")).href);
const expected = JSON.parse(readFileSync(join(root, "fixtures/expected.json"), "utf8"));
let failed = 0;
for (const item of expected.cases) {
  const args = [bin, item.file, "--json"];
  if (item.now) args.push("--now", item.now);
  for (const key of item.key ?? []) args.push("--key", key);
  const child = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });
  let parsed;
  try {
    parsed = JSON.parse(child.stdout);
  } catch {
    parsed = null;
  }
  const verdicts = parsed ? parsed.records.map((record) => record.verdict) : [];
  const same = JSON.stringify(verdicts) === JSON.stringify(item.verdicts);
  const codeOk = parsed && child.status === exitCode(parsed);
  if (!same || !codeOk) {
    failed += 1;
    process.stderr.write(
      `${item.file}\n  expected ${item.verdicts.join(",")}\n  actual   ${verdicts.join(",")}\n  status ${child.status}\n${child.stderr}`,
    );
  }
}
rmSync(dir, { recursive: true, force: true });
rmSync(tarball, { force: true });
if (failed > 0) {
  process.stderr.write(`${failed} fixture runs failed\n`);
  process.exit(1);
}
process.stdout.write(`tarball ${tarballName} ${bytes} bytes, ${expected.cases.length} fixtures ok\n`);
