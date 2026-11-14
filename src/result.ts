import type { InputError, RecordResult, Verdict, VerifyResult } from "./types.js";

export const RESULT_SCHEMA = "gatepass-verify.result.v1" as const;
export const RESULT_VERSION = 1 as const;

export const VERDICT_LABELS: Readonly<Record<Verdict, string>> = {
  valid: "Valid",
  tampered: "Tampered",
  revoked: "Revoked",
  widened: "Widened beyond mandate",
  expired: "Expired",
  malformed: "Malformed",
};

/** Highest severity first. Exit codes are documented in the README. */
const SEVERITY: readonly Verdict[] = [
  "tampered",
  "widened",
  "revoked",
  "expired",
  "malformed",
];

const EXIT: Readonly<Record<Verdict, number>> = {
  valid: 0,
  tampered: 2,
  revoked: 3,
  widened: 4,
  expired: 5,
  malformed: 6,
};

export function labelFor(verdict: Verdict): string {
  return VERDICT_LABELS[verdict];
}

/**
 * Pick one verdict when several checks fail.
 * Integrity failures outrank authority failures. Malformed is last among failures
 * because a parsed record with a broken binding is tampered, not merely unreadable.
 */
export function worstVerdict(failures: readonly Verdict[]): Verdict {
  for (const verdict of SEVERITY) {
    if (failures.includes(verdict)) return verdict;
  }
  return "valid";
}

export function exitCode(result: VerifyResult): number {
  if (result.error) return 1;
  if (result.records.length === 0) return 6;
  for (const verdict of SEVERITY) {
    if (result.records.some((record) => record.verdict === verdict)) {
      return EXIT[verdict];
    }
  }
  return 0;
}

export function resultBase(records: RecordResult[], error?: InputError): VerifyResult {
  const ok = !error && records.length > 0 && records.every((record) => record.verdict === "valid");
  if (error) {
    return {
      schema: RESULT_SCHEMA,
      version: RESULT_VERSION,
      ok: false,
      records,
      error,
    };
  }
  return {
    schema: RESULT_SCHEMA,
    version: RESULT_VERSION,
    ok,
    records,
  };
}

export function formatText(result: VerifyResult, label: string): string {
  const lines: string[] = [label];
  if (result.error) {
    lines.push(result.error.message);
    return `${lines.join("\n")}\n`;
  }
  for (const record of result.records) {
    const id = record.id ?? "-";
    lines.push(`[${record.index + 1}] ${record.label}  ${record.format}  ${id}`);
    lines.push(`    ${record.summary}`);
    for (const check of record.checks) {
      const mark = check.ok === true ? "pass" : check.ok === false ? "fail" : "skip";
      lines.push(`    ${mark}  ${check.name}  ${check.detail}`);
    }
  }
  const valid = result.records.filter((record) => record.verdict === "valid").length;
  lines.push(`${result.records.length} records, ${valid} valid`);
  return `${lines.join("\n")}\n`;
}
