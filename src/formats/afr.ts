import { CanonicalError, canonicalCodePoint } from "../canonical.js";
import { bytesOf, ed25519Verify, parsePublicKey, sha256Hex } from "../crypto.js";
import { labelFor } from "../result.js";
import type { Check, RecordResult, VerifyOptions } from "../types.js";
import { asString, isRecord, parseJson } from "../text.js";

const GENESIS = "0".repeat(64);

export function isAfrDocument(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0 && value.every((item) => isEntry(item));
  if (!isRecord(value)) return false;
  if (value["profile"] === "afr") return true;
  return isEntry(value);
}

function isEntry(value: unknown): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    typeof value["seq"] === "number" &&
    typeof value["prev"] === "string" &&
    typeof value["hash"] === "string"
  );
}

interface Loaded {
  entries: Array<Record<string, unknown> | null>;
  key: Uint8Array | null;
  keyNote: string;
}

function load(value: unknown, text: string, options: VerifyOptions): Loaded | RecordResult[] {
  const keyMaterial = options.keys?.["afr"];
  let embedded: string | null = null;
  let entries: Array<Record<string, unknown> | null> = [];

  if (isRecord(value) && value["profile"] === "afr") {
    embedded = asString(value["public_key_pem"]);
    const log = asString(value["log"]);
    if (log === null) {
      return [broken("log text was not supplied")];
    }
    entries = parseLines(log);
  } else if (looksLikeJsonl(text) && !isEntry(value)) {
    entries = parseLines(text);
  } else if (Array.isArray(value)) {
    entries = value.map((item) => (isRecord(item) ? item : null));
  } else if (isEntry(value)) {
    entries = [value];
  } else {
    return [broken("flight-recorder log was not found")];
  }

  const material = keyMaterial ?? embedded ?? undefined;
  const key = material ? parsePublicKey(material) : null;
  if (material && !key) {
    return [broken("public key is not an Ed25519 key")];
  }
  const keyNote = key
    ? "Ed25519 signature checked with the supplied public key"
    : "no public key supplied";
  return { entries, key, keyNote };
}

function looksLikeJsonl(text: string): boolean {
  const lines = text.split(/\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return false;
  try {
    return isEntry(parseJson(lines[0]!));
  } catch {
    return false;
  }
}

function parseLines(text: string): Array<Record<string, unknown> | null> {
  const out: Array<Record<string, unknown> | null> = [];
  const lines = text.split(/\n/);
  for (const line of lines) {
    if (line.trim().length === 0) continue;
    try {
      const parsed = parseJson(line);
      out.push(isRecord(parsed) ? parsed : null);
    } catch {
      out.push(null);
    }
  }
  return out;
}

export function verifyAfr(value: unknown, text: string, options: VerifyOptions): RecordResult[] {
  const loaded = load(value, text, options);
  if (Array.isArray(loaded)) return loaded;
  if (loaded.entries.length === 0) {
    return [broken("log is empty")];
  }

  const results: RecordResult[] = [];
  let previous = GENESIS;
  let brokenPrefix = false;

  for (let index = 0; index < loaded.entries.length; index += 1) {
    const entry = loaded.entries[index];
    if (!entry) {
      results.push(
        entryResult(
          index,
          null,
          brokenPrefix ? "tampered" : "malformed",
          [
            {
              name: "parse",
              ok: false,
              detail: brokenPrefix
                ? "line is not a JSON object, and an earlier entry already broke the chain"
                : "line is not a JSON object",
            },
          ],
          brokenPrefix
            ? "Hash chain or signature check failed."
            : "Log line is not a JSON object.",
        ),
      );
      brokenPrefix = true;
      previous = "";
      continue;
    }

    const checks: Check[] = [];
    const seq = entry["seq"];
    const id = typeof seq === "number" ? String(seq) : null;
    if (seq !== index) {
      checks.push({
        name: "sequence",
        ok: false,
        detail: `sequence is ${String(seq)}, expected ${index}`,
      });
    } else {
      checks.push({ name: "sequence", ok: true, detail: `sequence ${index}` });
    }

    const prev = asString(entry["prev"]);
    const linkOk = prev === previous;
    checks.push({
      name: "chain",
      ok: linkOk,
      detail: linkOk
        ? "links to the previous entry"
        : "does not link to the previous recomputed entry",
    });

    let recomputed: string | null = null;
    try {
      const body: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(entry)) {
        if (key === "hash" || key === "sig") continue;
        body[key] = item;
      }
      recomputed = sha256Hex(bytesOf(canonicalCodePoint(body)));
    } catch (err) {
      const detail = err instanceof CanonicalError ? err.message : "entry canonicalization failed";
      checks.push({ name: "hash", ok: false, detail });
    }
    const stored = asString(entry["hash"]);
    const hashOk = recomputed !== null && stored === recomputed;
    if (recomputed !== null) {
      checks.push({
        name: "hash",
        ok: hashOk,
        detail: hashOk ? "entry matches its hash" : "entry does not match its hash",
      });
    }

    const signature = asString(entry["sig"]);
    let signatureState: "ok" | "bad" | "missing-key" | "unsigned" = "unsigned";
    if (signature) {
      if (!loaded.key || !stored || !/^[0-9a-f]{64}$/.test(stored)) {
        signatureState = loaded.key ? "bad" : "missing-key";
        checks.push({
          name: "signature",
          ok: false,
          detail: loaded.key
            ? "signature could not be checked"
            : "entry is signed and no public key was supplied",
        });
      } else {
        const raw = Buffer.from(signature, "base64");
        const ok = raw.length === 64 && ed25519Verify(loaded.key, Buffer.from(stored, "hex"), raw);
        signatureState = ok ? "ok" : "bad";
        checks.push({
          name: "signature",
          ok,
          detail: ok ? loaded.keyNote : "signature does not verify with the supplied public key",
        });
      }
    } else if (loaded.key) {
      signatureState = "bad";
      checks.push({ name: "signature", ok: false, detail: "entry is not signed" });
    } else {
      checks.push({ name: "signature", ok: null, detail: "entry is unsigned and no key was supplied" });
    }

    const chainBroken = checks.some(
      (check) =>
        (check.name === "sequence" || check.name === "chain" || check.name === "hash") &&
        check.ok === false,
    );
    if (brokenPrefix) {
      checks.push({
        name: "chain_prefix",
        ok: false,
        detail: "an earlier entry already broke the chain",
      });
    }
    const verdict =
      chainBroken || brokenPrefix || signatureState === "bad"
        ? "tampered"
        : signatureState === "missing-key"
          ? "malformed"
          : "valid";
    const summary =
      verdict === "valid"
        ? "Hash chain entry is intact."
        : verdict === "malformed"
          ? "Signed entry cannot be checked without a public key."
          : "Hash chain or signature check failed.";
    results.push(entryResult(index, id, verdict, checks, summary));
    if (chainBroken || !entry) brokenPrefix = true;
    previous = recomputed ?? "";
  }

  return results;
}

function entryResult(
  index: number,
  id: string | null,
  verdict: "valid" | "tampered" | "malformed",
  checks: Check[],
  summary: string,
): RecordResult {
  return {
    index,
    id,
    format: "afr",
    verdict,
    label: labelFor(verdict),
    checks,
    summary,
  };
}

function broken(detail: string): RecordResult {
  return entryResult(0, null, "malformed", [{ name: "parse", ok: false, detail }], detail);
}
