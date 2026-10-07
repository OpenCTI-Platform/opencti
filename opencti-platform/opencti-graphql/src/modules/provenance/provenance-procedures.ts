import type { EditInput } from '../../generated/graphql';
import { EditOperation } from '../../generated/graphql';
import { RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';
import type { AssertionSource, StoreProcedure } from './provenance-types';

export const PROCEDURES_POLICY_LONGEST = 'longest';
export const PROCEDURES_POLICY_MOST_RECENT = 'most_recent';
export type ProceduresDescriptionPolicy = typeof PROCEDURES_POLICY_LONGEST | typeof PROCEDURES_POLICY_MOST_RECENT;

// Settings of the relationship entity setting, on by default. Procedures are only recorded while the provenance of
// relationships is tracked.
export const isProceduresPreservationEnabled = (entitySetting: Pick<BasicStoreEntityEntitySetting, 'procedures_preservation'> | undefined | null) => {
  return entitySetting?.procedures_preservation ?? true;
};

export const getProceduresDescriptionPolicy = (
  entitySetting: Pick<BasicStoreEntityEntitySetting, 'procedures_description_policy'> | undefined | null,
): ProceduresDescriptionPolicy => {
  return entitySetting?.procedures_description_policy === PROCEDURES_POLICY_MOST_RECENT ? PROCEDURES_POLICY_MOST_RECENT : PROCEDURES_POLICY_LONGEST;
};

export const isProcedureRelationship = (relationshipType: string, toType: string | undefined | null) => {
  return relationshipType === RELATION_USES && toType === ENTITY_TYPE_ATTACK_PATTERN;
};

// Must stay aligned with the normalization done by the side-channel script (trim + lower case).
export const procedureMatchKey = (text: string) => text.trim().toLowerCase();

export const buildProcedure = (text: string, source: AssertionSource, at: string): StoreProcedure => ({
  text: text.trim(),
  source_id: source.source_id,
  last_asserted_at: at,
});

export interface ProcedureUpsertArgs {
  element: { description?: string | null; procedures?: StoreProcedure[] | null; created_at?: string | Date | null };
  incomingDescription: unknown;
  source: AssertionSource;
  previousSource: AssertionSource | null;
  at: string;
  policy: ProceduresDescriptionPolicy;
  isConfidenceMatch: boolean;
  inputs: EditInput[];
}

/**
 * Distinct procedure descriptions of a uses relationship to an Attack Pattern are preserved instead of
 * overwriting each other (relationship identity unchanged). The description follows the configured policy.
 */
export const computeProcedureUpsert = (args: ProcedureUpsertArgs) => {
  const { element, incomingDescription, source, previousSource, at, policy, isConfidenceMatch, inputs } = args;
  const proceduresAdd: StoreProcedure[] = [];
  const incoming = typeof incomingDescription === 'string' ? incomingDescription.trim() : '';
  if (incoming.length === 0) {
    return { inputs, proceduresAdd };
  }
  const current = (element.description ?? '').trim();
  const existing = element.procedures ?? [];
  const known = new Set(existing.map((procedure) => procedureMatchKey(procedure.text)));
  if (current.length > 0 && !known.has(procedureMatchKey(current)) && previousSource) {
    // Relationships created before preservation existed: their description becomes the first procedure.
    const seededAt = element.created_at ? new Date(element.created_at).toISOString() : at;
    proceduresAdd.push(buildProcedure(current, previousSource, seededAt));
  }
  proceduresAdd.push(buildProcedure(incoming, source, at));
  const candidates = [...existing.map((procedure) => procedure.text), current, incoming].filter((text) => text.length > 0);
  const desired = policy === PROCEDURES_POLICY_MOST_RECENT
    ? incoming
    : candidates.reduce((longest, text) => (text.length > longest.length ? text : longest), '');
  const otherInputs = inputs.filter((input) => input.key !== 'description');
  const canChangeDescription = isConfidenceMatch || current.length === 0;
  if (canChangeDescription && desired !== current) {
    return { inputs: [...otherInputs, { key: 'description', value: [desired], operation: EditOperation.Replace }], proceduresAdd };
  }
  return { inputs: otherInputs, proceduresAdd };
};
