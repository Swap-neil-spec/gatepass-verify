/** Flat fields for an evidence section. Values are already display text or numbers. */
export interface Fact {
  summary: string;
  fields: Record<string, string | number | boolean | null>;
}

export interface EvidenceView {
  approved: Fact;
  approver: Fact;
  when: Fact;
  executed: Fact;
  unsupported: string[];
}

export function fact(
  summary: string,
  fields: Record<string, string | number | boolean | null> = {},
): Fact {
  return { summary, fields };
}

export function emptyView(unsupported: string[]): EvidenceView {
  return {
    approved: fact("Nothing in this record could be read as an approval."),
    approver: fact("No approver is named in a way this tool checks."),
    when: fact("No time could be read from this record."),
    executed: fact("This record does not say what ran."),
    unsupported,
  };
}
