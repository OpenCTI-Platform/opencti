export interface ConflictingProcedure {
  text: string;
  /** Writer of the procedure: a user, connector or author id, as recorded by the relationship conflict detector. */
  source_id: string | null;
}

export interface ProcedureNoteRelationship {
  internal_id: string;
  fromName: string;
  toName: string;
  markingIds: string[];
  organizationIds: string[];
}

/**
 * Note keeping an overwritten procedure next to its relationship, with its markings and its organization sharing. The
 * author is only set when the writer of that procedure is an identity: a user or connector id is not a valid author
 * reference.
 */
export const procedureNoteInput = (relationship: ProcedureNoteRelationship, procedureText: string, authorIdentityId: string | null) => ({
  attribute_abstract: `Alternative procedure: ${relationship.fromName} uses ${relationship.toName}`,
  content: procedureText,
  note_types: ['analysis'],
  objects: [relationship.internal_id],
  objectMarking: relationship.markingIds,
  objectOrganization: relationship.organizationIds,
  ...(authorIdentityId ? { createdBy: authorIdentityId } : {}),
});
