import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const roots = ["src", "test", "bin", "scripts", "schema", "fixtures", "docs", ".github"].map((name) =>
  join(root, name),
);
const banned = [
  ["em dash", "\u2014"],
  ["forbidden word", new RegExp("\\b" + "de" + "mo" + "\\b", "i")],
  ["eval", /\beval\s*\(/],
  ["Function constructor", /new\s+Function\s*\(/],
  ["network client", /node:(https?|net|dns)\b/],
  ["fetch", /\bfetch\s*\(/],
];

function files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (/\.(ts|js|mjs|md|json|yml|jsonl|txt|pub)$/.test(name)) out.push(path);
  }
  return out;
}

function fileURLToPath(url) {
  return decodeURIComponent(url.pathname);
}

const problems = [];
for (const dir of roots) {
  for (const path of files(dir)) {
    const text = readFileSync(path, "utf8");
    for (const [label, pattern] of banned) {
      if (typeof pattern === "string" ? text.includes(pattern) : pattern.test(text)) {
        problems.push(`${path}: ${label}`);
      }
    }
  }
}
for (const name of readdirSync(root)) {
  if (!name.endsWith(".md")) continue;
  const text = readFileSync(join(root, name), "utf8");
  for (const [label, pattern] of banned) {
    if (typeof pattern === "string" ? text.includes(pattern) : pattern.test(text)) {
      problems.push(`${name}: ${label}`);
    }
  }
}
if (problems.length > 0) {
  process.stderr.write(`${problems.join("\n")}\n`);
  process.exit(1);
}
