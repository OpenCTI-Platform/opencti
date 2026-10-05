import { procedureMatchKey } from '../provenance/provenance-procedures';

export interface ConflictingProcedure {
  text: string;
  /** Writer of the procedure: a user, connector or author id, as recorded by the relationship conflict detector. */
  source_id: string | null;
}

export interface ProcedureEntry {
  text: string;
  source_id: string | null;
  last_asserted_at: string;
}

/**
 * Procedures to append to a relationship's `procedures` list when a relationship conflict is resolved by keeping both
 * descriptions: same shape and same matching as the procedures preserved on upsert, so a text already known (whatever
 * its case or surrounding spaces) is never added twice.
 */
export const procedureAdditions = (
  existing: Array<{ text?: string | null }>,
  candidates: Array<ConflictingProcedure | null | undefined>,
  assertedAt: string,
): ProcedureEntry[] => {
  const known = new Set(existing.filter((procedure) => procedure.text).map((procedure) => procedureMatchKey(procedure.text as string)));
  const additions: ProcedureEntry[] = [];
  candidates.forEach((procedure) => {
    const text = procedure?.text?.trim();
    if (!procedure || !text || known.has(procedureMatchKey(text))) return;
    known.add(procedureMatchKey(text));
    additions.push({ text, source_id: procedure.source_id, last_asserted_at: assertedAt });
  });
  return additions;
};

export interface ProcedureNoteRelationship {
  internal_id: string;
  fromName: string;
  toName: string;
  markingIds: string[];
}

/**
 * Note keeping an overwritten procedure next to its relationship. The author is only set when the writer of that
 * procedure is an identity: a user or connector id is not a valid author reference.
 */
export const procedureNoteInput = (relationship: ProcedureNoteRelationship, procedureText: string, authorIdentityId: string | null) => ({
  attribute_abstract: `Alternative procedure: ${relationship.fromName} uses ${relationship.toName}`,
  content: procedureText,
  note_types: ['analysis'],
  objects: [relationship.internal_id],
  objectMarking: relationship.markingIds,
  ...(authorIdentityId ? { createdBy: authorIdentityId } : {}),
});
