import type { EditInput } from '../../generated/graphql';
import { iAttributes } from '../../schema/attribute-definition';
import type { AuthContext, AuthUser } from '../../types/user';
import { now } from '../../utils/format';
import { getEntitySettingFromCache } from '../entitySetting/entitySetting-utils';
import { logApp } from '../../config/conf';
import { isNotEmptyField } from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import {
  buildConflictValue,
  type ConflictAddition,
  computeUpsertConflicts,
  isConflictTrackedAttribute,
  normalizeConflictValue,
  type PreviousValueOwner,
} from './provenance-conflicts';
import {
  buildProcedure,
  computeProcedureUpsert,
  getProceduresDescriptionPolicy,
  isProcedureRelationship,
  isProceduresPreservationEnabled,
  type ProcedureUpsertArgs,
} from './provenance-procedures';
import { PROVENANCE_ENABLED } from './provenance-config';
import { resolveAssertionSource, resolveSourceOfUser } from './provenance-source';
import {
  type AssertionSource,
  ATTRIBUTE_ASSERTION_SOURCE_IDS,
  ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_PROCEDURES,
  type StoreAssertion,
  type StoreConflict,
  type StoreProcedure,
  type StoreProvenanceFields,
} from './provenance-types';
import { type FreshnessState, isFreshAfterMerge } from './provenance-freshness';
import { getActiveKnowledgeDecayRules } from '../decayRule/decayRule-knowledge';
import {
  computeProvenanceChange,
  isProvenanceRecordable,
  publishProvenanceChange,
  resolveProvenanceBeforeWrite,
  type UpsertProvenanceRecord,
  writeProvenanceUpdate,
} from './provenance-write';
import { hasProvenanceTriggers } from './provenance-notification';

type UpsertElement = Record<string, any> & { entity_type: string; internal_id: string };

/**
 * Who asserted what the element currently holds: the last modifier of the attribute,
 * otherwise its oldest source, otherwise its creator.
 */
export const resolveCurrentValueOwner = async (context: AuthContext, element: UpsertElement, field?: string): Promise<PreviousValueOwner | null> => {
  const attributeMeta = field ? (element[iAttributes.name] ?? []).find((attribute: { name: string }) => attribute.name === field) : undefined;
  if (attributeMeta?.user_id) {
    const source = await resolveSourceOfUser(context, attributeMeta.user_id);
    return { source, confidence: attributeMeta.confidence ?? element.confidence ?? null };
  }
  const assertions: StoreAssertion[] = element[ATTRIBUTE_ASSERTIONS] ?? [];
  if (assertions.length > 0) {
    const oldest = assertions.reduce((first, assertion) => (assertion.first_asserted_at < first.first_asserted_at ? assertion : first));
    const source: AssertionSource = { source_id: oldest.source_id, source_kind: oldest.source_kind, source_name: oldest.source_name, work_id: oldest.work_id };
    return { source, confidence: oldest.confidence ?? element.confidence ?? null };
  }
  const creatorId = Array.isArray(element.creator_id) ? element.creator_id[0] : element.creator_id;
  if (creatorId) {
    const source = await resolveSourceOfUser(context, creatorId);
    return { source, confidence: element.confidence ?? null };
  }
  return null;
};

export interface PreparedUpsertProvenance {
  inputs: EditInput[];
  record: UpsertProvenanceRecord | null;
}

/**
 * Runs after the confidence-based upsert resolution and before the element update:
 * preserves procedures, chooses the description policy and records the values that lost.
 */
export const prepareUpsertProvenance = async (
  context: AuthContext,
  user: AuthUser,
  element: UpsertElement,
  type: string,
  args: { basePatch: Record<string, any>; updatePatch: Record<string, any>; inputs: EditInput[]; isConfidenceMatch: boolean; confidence: number | null | undefined },
): Promise<PreparedUpsertProvenance> => {
  const { basePatch, updatePatch, inputs, isConfidenceMatch, confidence } = args;
  if (!(await isProvenanceRecordable(context, user, type))) {
    return { inputs, record: null };
  }
  try {
    const source = await resolveAssertionSource(context, user, basePatch);
    const at = now();
    let finalInputs = inputs;
    let proceduresAdd: StoreProcedure[] = [];
    const skipFields: string[] = [];
    if (isProcedureRelationship(type, element.toType)) {
      const relationshipSetting = await getEntitySettingFromCache(context, type);
      if (isProceduresPreservationEnabled(relationshipSetting)) {
        const previousOwner = await resolveCurrentValueOwner(context, element, 'description');
        const procedureUpsert = computeProcedureUpsert({
          element: element as ProcedureUpsertArgs['element'],
          incomingDescription: updatePatch.description,
          source,
          previousSource: previousOwner?.source ?? null,
          at,
          policy: getProceduresDescriptionPolicy(relationshipSetting),
          isConfidenceMatch,
          inputs,
        });
        finalInputs = procedureUpsert.inputs;
        proceduresAdd = procedureUpsert.proceduresAdd;
        skipFields.push('description');
      }
    }
    const { conflictsAdd, conflictsRemove } = await computeUpsertConflicts({
      type,
      element,
      updatePatch,
      inputs: finalInputs,
      incomingSource: source,
      incomingConfidence: confidence,
      at,
      skipFields,
      resolvePreviousOwner: (field) => resolveCurrentValueOwner(context, element, field),
    });
    return {
      inputs: finalInputs,
      record: { source, input: basePatch, confidence, at, conflictsAdd, conflictsRemove, proceduresAdd },
    };
  } catch (err) {
    // Provenance never blocks the knowledge write: keep the regular upsert resolution
    logApp.error('[PROVENANCE] Unable to prepare the upsert provenance', { cause: err, id: element.internal_id, type });
    return { inputs, record: { input: basePatch, confidence } };
  }
};

/**
 * Merging entities merges their provenance: the target inherits the sources assertions,
 * conflicts and procedures, and every scalar value of a source that did not survive becomes a conflict.
 */
export const mergeProvenanceOnEntitiesMerge = async (
  context: AuthContext,
  user: AuthUser,
  target: UpsertElement & { _index: string },
  sources: UpsertElement[],
) => {
  if (sources.length === 0 || !(await isProvenanceRecordable(context, user, target.entity_type))) {
    return;
  }
  try {
    const at = now();
    const assertions: StoreAssertion[] = sources.flatMap((source) => source[ATTRIBUTE_ASSERTIONS] ?? []);
    const sourceIdsAdd: string[] = sources.flatMap((source) => source[ATTRIBUTE_ASSERTION_SOURCE_IDS] ?? []);
    const sourceKindsAdd: string[] = sources.flatMap((source) => source[ATTRIBUTE_ASSERTION_SOURCE_KINDS] ?? []);
    const proceduresAdd: StoreProcedure[] = sources.flatMap((source) => source[ATTRIBUTE_PROCEDURES] ?? []);
    const conflictsAdd: ConflictAddition[] = sources.flatMap((source) => (source[ATTRIBUTE_CONFLICTS] ?? [])
      .flatMap((conflict: StoreConflict) => (conflict.values ?? []).map((value) => ({ field: conflict.field, value }))));
    const attributes = Array.from(schemaAttributesDefinition.getAttributes(target.entity_type).values()).filter(isConflictTrackedAttribute);
    for (let sourceIndex = 0; sourceIndex < sources.length; sourceIndex += 1) {
      const source = sources[sourceIndex];
      for (let attributeIndex = 0; attributeIndex < attributes.length; attributeIndex += 1) {
        const attribute = attributes[attributeIndex];
        const sourceValue = source[attribute.name];
        const targetValue = target[attribute.name];
        if (isNotEmptyField(sourceValue) && isNotEmptyField(targetValue)
          && normalizeConflictValue(attribute, sourceValue) !== normalizeConflictValue(attribute, targetValue)) {
          const owner = await resolveCurrentValueOwner(context, source, attribute.name);
          if (owner) {
            conflictsAdd.push({ field: attribute.name, value: buildConflictValue(attribute, sourceValue, owner.source, owner.confidence, at) });
          }
        }
      }
    }
    if (assertions.length === 0 && sourceIdsAdd.length === 0 && proceduresAdd.length === 0 && conflictsAdd.length === 0) {
      return;
    }
    const inheritedLastAssertedAt = assertions.reduce<string | undefined>((last, assertion) => {
      return !last || assertion.last_asserted_at > last ? assertion.last_asserted_at : last;
    }, undefined);
    const resetFreshness = target[ATTRIBUTE_FRESHNESS_STALE] === true
      && isFreshAfterMerge(target as FreshnessState, inheritedLastAssertedAt, await getActiveKnowledgeDecayRules(context));
    const before = await resolveProvenanceBeforeWrite(context, target as UpsertElement & { _index: string } & Partial<StoreProvenanceFields>);
    const { newConflicts, current } = await writeProvenanceUpdate(
      context,
      target,
      { assertions, countMode: 'sum', conflictsAdd, proceduresAdd, sourceIdsAdd, sourceKindsAdd, resetFreshness },
      { withCurrent: await hasProvenanceTriggers(context) },
    );
    const change = computeProvenanceChange(before, [...sourceIdsAdd, ...assertions.map((assertion) => assertion.source_id)], newConflicts);
    await publishProvenanceChange(context, target, change, current);
  } catch (err) {
    logApp.error('[PROVENANCE] Unable to merge the provenance of merged entities', { cause: err, id: target.internal_id });
  }
};

/**
 * The description of a new uses relationship to an Attack Pattern is its first procedure.
 */
export const creationProceduresBuilder = async (context: AuthContext, relationshipType: string, input: Record<string, any>) => {
  if (!PROVENANCE_ENABLED) {
    return undefined;
  }
  const description = typeof input.description === 'string' ? input.description.trim() : '';
  if (description.length === 0 || !isProcedureRelationship(relationshipType, input.to?.entity_type)) {
    return undefined;
  }
  if (!isProceduresPreservationEnabled(await getEntitySettingFromCache(context, relationshipType))) {
    return undefined;
  }
  return (source: AssertionSource, at: string) => [buildProcedure(description, source, at)];
};
