/** Verdict codes. Labels for humans live in VERDICT_LABELS. */
export type Verdict =
  | "valid"
  | "tampered"
  | "revoked"
  | "widened"
  | "expired"
  | "malformed";

export type FormatId =
  | "keel-permit"
  | "haps"
  | "action-v1"
  | "afr"
  | "ap2"
  | "verifiable-intent"
  | "gatepass";

export type FormatSelection = "auto" | FormatId;

/**
 * One check the verifier actually ran.
 * `ok: null` means the check was skipped because the evidence for it was not supplied.
 * A skipped check is named in `detail`. It is not a pass.
 */
export interface Check {
  name: string;
  ok: boolean | null;
  detail: string;
}

/** One verdict. A file may contain several records. */
export interface RecordResult {
  index: number;
  id: string | null;
  format: FormatId | "unknown";
  verdict: Verdict;
  label: string;
  checks: Check[];
  summary: string;
}

export interface InputError {
  code: "input_too_large" | "empty_input";
  message: string;
}

/**
 * Result document, schema `gatepass-verify.result.v1`.
 * `ok` is true only when every record is valid and the input was accepted.
 */
export interface VerifyResult {
  schema: "gatepass-verify.result.v1";
  version: 1;
  ok: boolean;
  records: RecordResult[];
  error?: InputError;
}

export interface VerifyOptions {
  format?: FormatSelection;
  /** Verification clock. Defaults to the time of the call. */
  now?: Date;
  /** Maximum accepted input size in bytes. Default is 1 MiB. */
  maxBytes?: number;
  /**
   * Pinned Ed25519 public keys, keyed by an id the caller chooses.
   * Values are PEM text, or base64url of the raw 32-byte key.
   * The id `afr` is used for a flight-recorder log.
   * Any id is tried for Keel revocation events and for HAPS EdDSA credentials.
   */
  keys?: Readonly<Record<string, string>>;
  /** When set, a HAPS `aud` that differs is not accepted. */
  audience?: string;
}
