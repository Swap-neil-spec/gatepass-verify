export { verify } from "./verify.js";
export { evidenceFor, evidenceFrom, formatEvidence, EVIDENCE_SCHEMA, EVIDENCE_VERSION } from "./evidence.js";
export { exitCode, formatText, labelFor, RESULT_SCHEMA, RESULT_VERSION, VERDICT_LABELS } from "./result.js";
export type { EvidenceBundle, EvidenceRecord } from "./evidence.js";
export type { EvidenceView, Fact } from "./facts.js";
export type {
  Check,
  FormatId,
  FormatSelection,
  InputError,
  RecordResult,
  Verdict,
  VerifyOptions,
  VerifyResult,
} from "./types.js";
