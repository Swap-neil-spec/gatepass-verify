import { verifyAction, isActionDocument } from "./action.js";
import { verifyAfr, isAfrDocument } from "./afr.js";
import { describeAp2, isAp2Document, verifyAp2 } from "./ap2.js";
import { describeGatepass, isGatepassDocument, verifyGatepass } from "./gatepass.js";
import { verifyHaps, isHapsDocument } from "./haps.js";
import { verifyKeel, isKeelDocument } from "./keel.js";
import { describeVi, isViDocument, verifyVi } from "./vi.js";
import type { EvidenceView } from "../facts.js";
import type { FormatId, RecordResult, VerifyOptions } from "../types.js";
import { isRecord } from "../text.js";

export interface FormatAdapter {
  id: FormatId;
  detect(parsed: unknown, text: string): boolean;
  verify(parsed: unknown, text: string, options: VerifyOptions): RecordResult[];
  describe(parsed: unknown, text: string, index: number): EvidenceView;
}

export const FORMAT_IDS: readonly FormatId[] = [
  "keel-permit",
  "haps",
  "action-v1",
  "afr",
  "ap2",
  "verifiable-intent",
  "gatepass",
];

export const adapters: readonly FormatAdapter[] = [
  {
    id: "action-v1",
    detect: (parsed) => isActionDocument(parsed),
    verify: (parsed, _text, options) => verifyAction(parsed, options),
    describe: (parsed) => describeAction(parsed),
  },
  {
    id: "haps",
    detect: (parsed) => isHapsDocument(parsed),
    verify: (parsed, _text, options) => verifyHaps(parsed, options),
    describe: (parsed) => describeHaps(parsed),
  },
  {
    id: "afr",
    detect: (parsed) => isAfrDocument(parsed),
    verify: (parsed, text, options) => verifyAfr(parsed, text, options),
    describe: () => describeAfr(),
  },
  {
    id: "keel-permit",
    detect: (parsed) => isKeelDocument(parsed),
    verify: (parsed, _text, options) => verifyKeel(parsed, options),
    describe: (parsed, _text, index) => describeKeel(parsed, index),
  },
  {
    id: "ap2",
    detect: (parsed, text) => isAp2Document(parsed, text),
    verify: (parsed, text, options) => verifyAp2(parsed, text, options),
    describe: (parsed, text) => describeAp2(parsed, text),
  },
  {
    id: "verifiable-intent",
    detect: (parsed) => isViDocument(parsed),
    verify: (parsed, text, options) => verifyVi(parsed, text, options),
    describe: (parsed) => describeVi(parsed),
  },
  {
    id: "gatepass",
    detect: (parsed) => isGatepassDocument(parsed),
    verify: (parsed, text, options) => verifyGatepass(parsed, text, options),
    describe: (parsed, _text, index) => describeGatepass(parsed, index),
  },
];

export function adapterById(id: FormatId): FormatAdapter | undefined {
  return adapters.find((adapter) => adapter.id === id);
}

function stringField(record: Record<string, unknown> | null, key: string): string | null {
  if (!record) return null;
  return typeof record[key] === "string" ? record[key] : null;
}

function describeKeel(parsed: unknown, index: number): EvidenceView {
  const permits = isRecord(parsed) && Array.isArray(parsed["permits"])
    ? parsed["permits"]
    : [parsed];
  const permit = isRecord(permits[index]) ? permits[index] : null;
  const envelope = permit && isRecord(permit["authority_envelope"]) ? permit["authority_envelope"] : null;
  return {
    approved: {
      summary: permit
        ? "Permit decision and the authority envelope that was present."
        : "Permit object was not found.",
      fields: {
        decision: stringField(permit, "decision"),
        action: stringField(permit, "action_name"),
        binding: stringField(permit, "binding_request_hash"),
        tools: envelope && Array.isArray(envelope["tools"]) ? envelope["tools"].join(",") : null,
      },
    },
    approver: {
      summary: "The permit object is not signed. subject_id is caller-asserted.",
      fields: {
        subjectType: stringField(permit, "subject_type"),
        subjectId: stringField(permit, "subject_id"),
      },
    },
    when: {
      summary: "Times carried on the permit.",
      fields: {
        createdAt: stringField(permit, "created_at"),
        expiresAt: stringField(permit, "expires_at"),
      },
    },
    executed: {
      summary: "A permit does not record what ran after the decision.",
      fields: {},
    },
    unsupported: ["COSE_Sign1", "what ran after the decision"],
  };
}

function describeHaps(parsed: unknown): EvidenceView {
  const root = isRecord(parsed) ? parsed : null;
  const claims = root && isRecord(root["claims"]) ? root["claims"] : root;
  const action = root && isRecord(root["action"]) ? root["action"] : null;
  return {
    approved: {
      summary: action ? "Action intent supplied with the claims." : "No action intent was supplied.",
      fields: {
        intentHash: stringField(claims, "intent_hash"),
        type: stringField(action, "type"),
      },
    },
    approver: {
      summary: "Audience and jti from the claims. The provider signature is a separate check.",
      fields: {
        aud: stringField(claims, "aud"),
        jti: stringField(claims, "jti"),
      },
    },
    when: {
      summary: "exp is a unix time on the claims.",
      fields: { exp: typeof claims?.["exp"] === "number" ? claims["exp"] : null },
    },
    executed: {
      summary: "HAPS does not record an execution.",
      fields: {},
    },
    unsupported: ["provider identity", "biometric evidence", "single-use replay"],
  };
}

function describeAction(parsed: unknown): EvidenceView {
  const root = isRecord(parsed) ? parsed : null;
  const record = root && root["v"] === "action-1"
    ? root
    : root && isRecord(root["record"])
      ? root["record"]
      : null;
  return {
    approved: {
      summary: "Tool and argument hash from the ACTION-v1 record.",
      fields: {
        tool: stringField(record, "tool"),
        argsHash: stringField(record, "args_hash"),
        outcome: stringField(record, "outcome"),
      },
    },
    approver: {
      summary: "The embedded key signed the record. The agent string is caller-asserted.",
      fields: {
        agent: stringField(record, "agent"),
        publicKey: stringField(record, "public_key"),
      },
    },
    when: {
      summary: "Timestamp on the record.",
      fields: { timestamp: stringField(record, "timestamp") },
    },
    executed: {
      summary: "outcome says the policy result. It does not show that the action ran.",
      fields: { outcome: stringField(record, "outcome") },
    },
    unsupported: ["whether the action ran"],
  };
}

function describeAfr(): EvidenceView {
  return {
    approved: {
      summary: "A flight-recorder entry is a hash-linked event, not an approval by itself.",
      fields: {},
    },
    approver: {
      summary: "Ed25519 is checked only when --key afr is supplied.",
      fields: {},
    },
    when: {
      summary: "Each entry carries its own time field when the logger wrote one.",
      fields: {},
    },
    executed: {
      summary: "Entry payloads are whatever the logger stored.",
      fields: {},
    },
    unsupported: ["approval expiry", "a witness for a missing tail"],
  };
}
