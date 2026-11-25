import { adapters } from "./formats/registry.js";
import type { EvidenceView, Fact } from "./facts.js";
import { sha256Hex } from "./crypto.js";
import type { Check, VerifyOptions, VerifyResult } from "./types.js";
import { verify } from "./verify.js";
import { parseJson } from "./text.js";

export const EVIDENCE_SCHEMA = "gatepass-verify.evidence.v1" as const;
export const EVIDENCE_VERSION = 1 as const;

export interface EvidenceRecord {
  index: number;
  id: string | null;
  format: string;
  verdict: string;
  label: string;
  why: string;
  approved: Fact;
  approver: Fact;
  when: Fact;
  executed: Fact;
  unsupported: string[];
  checks: Check[];
}

export interface EvidenceBundle {
  schema: typeof EVIDENCE_SCHEMA;
  version: typeof EVIDENCE_VERSION;
  ok: boolean;
  verificationClock: string;
  input: { sha256: string; bytes: number };
  records: EvidenceRecord[];
  error?: { code: string; message: string };
}

/**
 * Evidence bundle for a dispute or an audit.
 * The verdict is the same one `verify` returns. Sections that the format does
 * not carry are stated, not filled in.
 */
export function evidenceFor(input: string | Uint8Array, options: VerifyOptions = {}): EvidenceBundle {
  const bytes = typeof input === "string" ? Buffer.from(input) : Buffer.from(input);
  const now = options.now ?? new Date();
  const result = verify(bytes, { ...options, now });
  return evidenceFrom(bytes, result, now);
}

/** Build the bundle from a result already produced for these bytes. */
export function evidenceFrom(input: string | Uint8Array, result: VerifyResult, now: Date): EvidenceBundle {
  const bytes = typeof input === "string" ? Buffer.from(input) : Buffer.from(input);
  return bundleFrom(bytes, result, now);
}

export function formatEvidence(bundle: EvidenceBundle, label: string): string {
  const lines: string[] = [
    `Evidence  ${label}`,
    `sha256 ${bundle.input.sha256}`,
    `clock  ${bundle.verificationClock}`,
  ];
  if (bundle.error) {
    lines.push(bundle.error.message);
    return `${lines.join("\n")}\n`;
  }
  for (const record of bundle.records) {
    const id = record.id ?? "-";
    lines.push("");
    lines.push(`[${record.index + 1}] ${record.label}  ${record.format}  ${id}`);
    lines.push(`Why: ${record.why}`);
    lines.push(section("Approved", record.approved));
    lines.push(section("Approver", record.approver));
    lines.push(section("When", record.when));
    lines.push(section("Ran", record.executed));
    if (record.unsupported.length > 0) {
      lines.push("Unsupported:");
      for (const item of record.unsupported) lines.push(`  - ${item}`);
    }
    for (const check of record.checks) {
      const mark = check.ok === true ? "pass" : check.ok === false ? "fail" : "skip";
      lines.push(`    ${mark}  ${check.name}  ${check.detail}`);
    }
  }
  lines.push("");
  lines.push(bundle.ok ? "Bundle: every record is valid." : "Bundle: at least one record is not valid.");
  return `${lines.join("\n")}\n`;
}

function bundleFrom(bytes: Buffer, result: VerifyResult, now: Date): EvidenceBundle {
  const base: EvidenceBundle = {
    schema: EVIDENCE_SCHEMA,
    version: EVIDENCE_VERSION,
    ok: result.ok,
    verificationClock: now.toISOString(),
    input: { sha256: sha256Hex(bytes), bytes: bytes.length },
    records: [],
  };
  if (result.error) {
    return {
      ...base,
      error: { code: result.error.code, message: result.error.message },
    };
  }
  let parsed: unknown;
  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = parseJson(text);
  } catch {
    parsed = undefined;
  }
  base.records = result.records.map((record) => {
    const view = viewFor(record.format, parsed, text, record.index);
    return {
      index: record.index,
      id: record.id,
      format: record.format,
      verdict: record.verdict,
      label: record.label,
      why: record.summary,
      approved: view.approved,
      approver: view.approver,
      when: view.when,
      executed: view.executed,
      unsupported: view.unsupported,
      checks: record.checks,
    };
  });
  return base;
}

function viewFor(format: string, parsed: unknown, text: string, index: number): EvidenceView {
  const adapter = adapters.find((item) => item.id === format);
  if (format === "unknown" || !adapter) {
    return {
      approved: { summary: "The format was not recognized.", fields: {} },
      approver: { summary: "No approver was read.", fields: {} },
      when: { summary: "No time was read.", fields: {} },
      executed: { summary: "Nothing was read as an execution.", fields: {} },
      unsupported: ["unrecognized format"],
    };
  }
  return adapter.describe(parsed, text, index);
}

function section(title: string, fact: Fact): string {
  const fields = Object.entries(fact.fields)
    .filter((entry) => entry[1] !== null && entry[1] !== undefined)
    .map(([key, value]) => `${key}=${String(value)}`);
  const extra = fields.length > 0 ? ` (${fields.join(", ")})` : "";
  return `${title}: ${fact.summary}${extra}`;
}
