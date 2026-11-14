import { verifyAction, isActionDocument } from "./formats/action.js";
import { verifyAfr, isAfrDocument } from "./formats/afr.js";
import { verifyHaps, isHapsDocument } from "./formats/haps.js";
import { verifyKeel, isKeelDocument } from "./formats/keel.js";
import { labelFor, resultBase } from "./result.js";
import { DEFAULT_MAX_BYTES, isRecord, parseJson } from "./text.js";
import type { FormatId, RecordResult, VerifyOptions, VerifyResult } from "./types.js";

const FORMAT_IDS: readonly FormatId[] = ["keel-permit", "haps", "action-v1", "afr"];

/**
 * Verify receipt bytes. This function does not read the filesystem or the network.
 * `input` is the file contents, not a path.
 */
export function verify(input: string | Uint8Array, options: VerifyOptions = {}): VerifyResult {
  const bytes = typeof input === "string" ? Buffer.from(input) : Buffer.from(input);
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    return resultBase(
      [],
      { code: "empty_input", message: "maxBytes must be a positive integer" },
    );
  }
  if (bytes.length === 0) {
    return resultBase([], { code: "empty_input", message: "input is empty" });
  }
  if (bytes.length > maxBytes) {
    return resultBase([], {
      code: "input_too_large",
      message: `input is ${bytes.length} bytes, which is over the ${maxBytes} byte limit`,
    });
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return resultBase([unsupported("input is not UTF-8")]);
  }

  const format = options.format ?? "auto";
  if (format !== "auto" && !FORMAT_IDS.includes(format)) {
    return resultBase([unsupported(`unsupported format ${String(format)}`)]);
  }

  let parsed: unknown;
  let parsedOk = false;
  try {
    parsed = parseJson(text);
    parsedOk = true;
  } catch {
    parsedOk = false;
  }

  try {
    const records = select(format, parsedOk ? parsed : undefined, text, options);
    return resultBase(records.map((record, index) => ({ ...record, index })));
  } catch {
    return resultBase([unsupported("input could not be verified")]);
  }
}

function select(
  format: VerifyOptions["format"],
  parsed: unknown,
  text: string,
  options: VerifyOptions,
): RecordResult[] {
  const chosen = format ?? "auto";
  if (chosen === "auto") {
    if (parsed !== undefined && isActionDocument(parsed)) return verifyAction(parsed, options);
    if (parsed !== undefined && isHapsDocument(parsed)) return verifyHaps(parsed, options);
    if (parsed !== undefined && isAfrDocument(parsed)) return verifyAfr(parsed, text, options);
    if (parsed !== undefined && isKeelDocument(parsed)) return verifyKeel(parsed, options);
    if (isJsonl(text)) return verifyAfr(undefined, text, options);
    return [unsupported("format was not recognized. Refusing to guess.")];
  }
  if (chosen === "action-v1") {
    return verifyAction(parsed ?? {}, options);
  }
  if (chosen === "haps") {
    return verifyHaps(parsed ?? {}, options);
  }
  if (chosen === "afr") {
    return verifyAfr(parsed, text, options);
  }
  return verifyKeel(parsed ?? {}, options);
}

function isJsonl(text: string): boolean {
  const lines = text.split(/\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) return false;
  try {
    const first = parseJson(lines[0]!);
    return (
      isRecord(first) &&
      typeof first["seq"] === "number" &&
      typeof first["prev"] === "string" &&
      typeof first["hash"] === "string"
    );
  } catch {
    return false;
  }
}

function unsupported(detail: string): RecordResult {
  return {
    index: 0,
    id: null,
    format: "unknown",
    verdict: "malformed",
    label: labelFor("malformed"),
    checks: [{ name: "format", ok: false, detail }],
    summary: detail,
  };
}
