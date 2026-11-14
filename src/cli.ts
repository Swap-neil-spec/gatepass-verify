import { readFileSync, statSync } from "node:fs";
import { formatText, exitCode } from "./result.js";
import { DEFAULT_MAX_BYTES } from "./text.js";
import type { FormatSelection, VerifyOptions } from "./types.js";
import { verify } from "./verify.js";

const FORMATS = new Set(["auto", "keel-permit", "haps", "action-v1", "afr"]);

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  readFile: (path: string) => Buffer;
  readKey: (path: string) => string;
}

const defaultIo: CliIo = {
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
  readFile: (path) => readFileSync(path),
  readKey: (path) => readFileSync(path, "utf8"),
};

export async function main(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  const parsed = parseArgs(argv);
  if ("error" in parsed) {
    io.stderr(`${parsed.error}\n`);
    io.stderr(`${usage()}\n`);
    return 1;
  }
  if (parsed.help) {
    io.stdout(`${usage()}\n`);
    return 0;
  }
  if (parsed.version) {
    io.stdout("gatepass-verify 0.1.0\n");
    return 0;
  }

  let size = 0;
  try {
    size = statSync(parsed.file).size;
  } catch {
    io.stderr(`cannot read ${parsed.file}\n`);
    return 1;
  }
  if (size > parsed.maxBytes) {
    io.stderr(`input is ${size} bytes, which is over the ${parsed.maxBytes} byte limit\n`);
    return 1;
  }

  let bytes: Buffer;
  try {
    bytes = io.readFile(parsed.file);
  } catch {
    io.stderr(`cannot read ${parsed.file}\n`);
    return 1;
  }

  const keys: Record<string, string> = {};
  for (const [id, path] of parsed.keys) {
    try {
      keys[id] = io.readKey(path);
    } catch {
      io.stderr(`cannot read key ${path}\n`);
      return 1;
    }
  }

  const options: VerifyOptions = { format: parsed.format, maxBytes: parsed.maxBytes };
  if (parsed.now) options.now = parsed.now;
  if (Object.keys(keys).length > 0) options.keys = keys;
  if (parsed.audience) options.audience = parsed.audience;

  const result = verify(bytes, options);
  if (parsed.json) io.stdout(`${JSON.stringify(result, null, 2)}\n`);
  else io.stdout(formatText(result, parsed.file));
  return exitCode(result);
}

interface ParsedArgs {
  file: string;
  json: boolean;
  format: FormatSelection;
  now?: Date;
  keys: Array<[string, string]>;
  audience?: string;
  maxBytes: number;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: readonly string[]): ParsedArgs | { error: string } {
  const keys: Array<[string, string]> = [];
  let file = "";
  let json = false;
  let format: FormatSelection = "auto";
  let now: Date | undefined;
  let audience: string | undefined;
  let help = false;
  let version = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--json") json = true;
    else if (arg === "--help" || arg === "-h") help = true;
    else if (arg === "--version") version = true;
    else if (arg === "--format") {
      const value = argv[i + 1];
      if (!value || !FORMATS.has(value)) return { error: "format must be auto, keel-permit, haps, action-v1, or afr" };
      format = value as FormatSelection;
      i += 1;
    } else if (arg === "--now") {
      const value = argv[i + 1];
      if (!value || Number.isNaN(Date.parse(value))) return { error: "--now must be an ISO 8601 time" };
      now = new Date(value);
      i += 1;
    } else if (arg === "--aud") {
      const value = argv[i + 1];
      if (!value) return { error: "--aud needs an audience" };
      audience = value;
      i += 1;
    } else if (arg === "--key") {
      const value = argv[i + 1];
      if (!value || !value.includes("=")) return { error: "--key must look like id=path" };
      const eq = value.indexOf("=");
      const id = value.slice(0, eq);
      const path = value.slice(eq + 1);
      if (!/^[a-z0-9-]+$/.test(id) || path.length === 0) return { error: "--key must look like id=path" };
      keys.push([id, path]);
      i += 1;
    } else if (arg.startsWith("-")) {
      return { error: `unknown option ${arg}` };
    } else if (file) {
      return { error: "only one file is accepted" };
    } else file = arg;
  }
  if (help || version) {
    return { file: "", json, format, keys, maxBytes: DEFAULT_MAX_BYTES, help, version };
  }
  if (!file) return { error: "a file is required" };
  const parsed: ParsedArgs = { file, json, format, keys, maxBytes: DEFAULT_MAX_BYTES, help, version };
  if (now) parsed.now = now;
  if (audience) parsed.audience = audience;
  return parsed;
}

function usage(): string {
  return [
    "gatepass-verify <file> [--json] [--format auto|keel-permit|haps|action-v1|afr]",
    "                   [--now <iso>] [--key <id>=<path>] [--aud <audience>]",
    "",
    "Read one receipt file and print a verdict for each record.",
    "The process does not use the network.",
    "",
    "Exit codes:",
    "  0  every record is valid",
    "  1  the file was rejected before verification",
    "  2  a record is tampered",
    "  3  a record is revoked",
    "  4  a record is widened beyond mandate",
    "  5  a record is expired",
    "  6  a record is malformed or the format is unsupported",
    "",
    "When several records fail, the exit code follows this order:",
    "tampered, widened, revoked, expired, malformed.",
  ].join("\n");
}
