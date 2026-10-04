import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, StoreObject, StoreRelation } from '../../types/store';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { createEntity, deleteElementById, mergeEntities, storeLoadByIdWithRefs, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { getInstanceIds } from '../../schema/identifier';
import { lockResources } from '../../lock/master-lock';
import { getDraftContext } from '../../utils/draftContext';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNMERGE, SYSTEM_USER } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { resolveAliasesField, ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_INTRUSION_SET } from '../../schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { ENTITY_TYPE_DELETE_OPERATION } from '../deleteOperation/deleteOperation-types';
import { restoreDelete } from '../deleteOperation/deleteOperation-domain';
import { now } from '../../utils/format';
import {
  ACTION_ACKNOWLEDGE,
  ACTION_ADD_ALIASES,
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_PRESERVE_PROCEDURE,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_REVOKE,
  ACTION_SET_FIELD,
  ACTION_UNMERGE,
  ACTION_UNREVOKE_INDICATOR,
  type AppliedPatch,
  type AppliedPatchOperation,
  type BasicStoreEntityCurationProposal,
  type BasicStoreEntityMergeRecord,
  type CurationSettings,
  ENTITY_TYPE_MERGE_RECORD,
  RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY,
  RELATIONSHIP_CONFLICT_MODE_PROCEDURES,
} from './curation-types';
import { unmergeFromRecord } from './curation-merge-record';
import { effectiveProposalAction } from './curation-access';
import { type ConflictingProcedure, procedureAdditions, procedureNoteInput, type ProcedureEntry } from './curation-procedures';
import { ATTRIBUTE_ASSERTIONS, ATTRIBUTE_PROCEDURES } from '../provenance/provenance-types';

const MIN_REACTIVATION_DAYS = 30;
const MAX_REACTIVATION_DAYS = 365;

export interface ApplyOptions {
  targetId?: string | null;
  decision?: string | null;
  payload?: Record<string, unknown> | null;
}

export interface ApplyResult {
  appliedPatch: AppliedPatch | null;
  mergeRecordId: string | null;
}

const parsePayload = (proposal: BasicStoreEntityCurationProposal): Record<string, any> => {
  const payload = proposal.action_payload as unknown;
  if (!payload) return {};
  if (typeof payload === 'string') {
    try {
      return JSON.parse(payload);
    } catch {
      return {};
    }
  }
  return payload as Record<string, any>;
};

const loadSubject = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await storeLoadByIdWithRefs<StoreObject>(context, user, id);
  if (!element) {
    throw FunctionalError('A subject of the curation proposal does not exist anymore or is not accessible', { id });
  }
  controlUserConfidenceAgainstElement(user, element);
  return element;
};

const patchOperation = (element: BasicStoreBase, key: string, previous: unknown, value: unknown): AppliedPatchOperation => ({
  element_id: element.internal_id,
  entity_type: element.entity_type,
  key,
  previous: previous ?? null,
  value: value ?? null,
});

const replaceInputs = (changes: Record<string, unknown>) => Object.entries(changes).map(([key, value]) => ({
  key,
  value: value === null || value === undefined ? [] : (Array.isArray(value) ? value : [value]),
}));

export const isProceduresAttributeAvailable = (relationshipType = 'uses') => schemaAttributesDefinition.getAttribute(relationshipType, ATTRIBUTE_PROCEDURES) !== undefined;

// Per-source assertions are owned by the provenance module: their source agreement evidence is used only when registered.
export const isProvenanceAvailable = () => schemaAttributesDefinition.getAttribute(ENTITY_TYPE_INTRUSION_SET, ATTRIBUTE_ASSERTIONS) !== undefined;

const findLatestMergeRecordForProposal = async (context: AuthContext, proposalId: string) => {
  const records = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
    filters: { mode: FilterMode.And, filters: [{ key: ['proposal_id'], values: [proposalId] }], filterGroups: [] },
    noFiltersChecking: true,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    first: 1,
  });
  return records.edges[0]?.node ?? null;
};

// region actions
const applyMerge = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMERGE)) {
    throw ForbiddenAccess('Merging entities requires the merge capability');
  }
  const entityIds = proposal.subject_ids;
  const targetId = opts.targetId ?? proposal.target_id ?? entityIds[0];
  if (!entityIds.includes(targetId)) {
    throw FunctionalError('The merge target must be one of the proposal subjects', { targetId });
  }
  const existing = await internalFindByIds(context, user, entityIds, { baseData: true }) as BasicStoreBase[];
  const existingIds = new Set(existing.map((element) => element.internal_id));
  if (!existingIds.has(targetId)) {
    throw FunctionalError('The merge target does not exist anymore or is not accessible', { targetId });
  }
  const sourceIds = entityIds.filter((id) => id !== targetId && existingIds.has(id));
  if (sourceIds.length === 0) {
    throw FunctionalError('Nothing left to merge: the other subjects do not exist anymore or are not accessible', { proposal_id: proposal.internal_id });
  }
  await mergeEntities(context, user, targetId, sourceIds, { mergeRecordMetadata: { proposal_id: proposal.internal_id } });
  const record = await findLatestMergeRecordForProposal(context, proposal.internal_id);
  return { appliedPatch: null, mergeRecordId: record?.internal_id ?? null };
};

const addAliases = async (context: AuthContext, user: AuthUser, element: StoreObject, aliases: string[]): Promise<ApplyResult> => {
  const aliasField = resolveAliasesField(element.entity_type).name;
  const current = ((element as Record<string, any>)[aliasField] ?? []) as string[];
  const currentKeys = new Set([(element as Record<string, any>).name, ...current].filter(Boolean).map((value: string) => value.toLowerCase()));
  const toAdd = R.uniq(aliases.filter((alias) => alias && !currentKeys.has(alias.toLowerCase())));
  if (toAdd.length === 0) {
    return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
  }
  const next = [...current, ...toAdd];
  await updateAttribute(context, user, element.internal_id, element.entity_type, [{ key: aliasField, value: next }]);
  return { appliedPatch: { operations: [patchOperation(element, aliasField, current, next)], applied_at: now() }, mergeRecordId: null };
};

/**
 * The names of the other subjects become aliases of the target, entities stay separate (overlapping clusters,
 * sub-groups): an "alias" decision on a merge proposal, or an alias proposal applied to another target than its own.
 */
const applyAliasDecision = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions) => {
  const targetId = opts.targetId ?? proposal.target_id ?? proposal.subject_ids[0];
  if (!proposal.subject_ids.includes(targetId)) {
    throw FunctionalError('The alias target must be one of the proposal subjects', { targetId });
  }
  const target = await loadSubject(context, user, targetId);
  const others = proposal.subject_names.filter((_, index) => proposal.subject_ids[index] !== targetId);
  return addAliases(context, user, target, others);
};

const applyAddAliases = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions) => {
  const proposedTargetId = proposal.target_id ?? proposal.subject_ids[0];
  // The aliases of the payload name the other subjects for the proposed target: another target takes their names.
  if (opts.targetId && opts.targetId !== proposedTargetId) {
    return applyAliasDecision(context, user, proposal, opts);
  }
  const payload = { ...parsePayload(proposal), ...(opts.payload ?? {}) };
  const element = await loadSubject(context, user, proposedTargetId);
  return addAliases(context, user, element, (payload.aliases ?? []) as string[]);
};

const applyFixDates = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const element = await loadSubject(context, user, proposal.target_id ?? proposal.subject_ids[0]);
  const record = element as Record<string, any>;
  const start = record[payload.start_field];
  const stop = record[payload.stop_field];
  if (!start || !stop || new Date(start).getTime() <= new Date(stop).getTime()) {
    throw FunctionalError('The dates are not inverted anymore, nothing to fix', { id: element.internal_id });
  }
  await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs({ [payload.start_field]: stop, [payload.stop_field]: start }));
  return {
    appliedPatch: {
      operations: [patchOperation(element, payload.start_field, start, stop), patchOperation(element, payload.stop_field, stop, start)],
      applied_at: now(),
    },
    mergeRecordId: null,
  };
};

const applyResolveAttribution = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  const payload = { ...parsePayload(proposal), ...(opts.payload ?? {}) };
  const keepActorId = payload.keep_actor_id as string | undefined;
  const relationships = (payload.relationships ?? []) as Array<{ actor_id: string; relationship_id: string }>;
  if (!keepActorId || !relationships.some((relation) => relation.actor_id === keepActorId)) {
    throw FunctionalError('Choose which attribution to keep (keep_actor_id) to resolve this contradiction', { proposal_id: proposal.internal_id });
  }
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNDELETE)) {
    throw ForbiddenAccess('Removing an attribution requires the delete capability');
  }
  const toDelete = relationships.filter((relation) => relation.actor_id !== keepActorId).map((relation) => relation.relationship_id);
  const deletedIds: string[] = [];
  for (let index = 0; index < toDelete.length; index += 1) {
    const relationshipId = toDelete[index];
    const [existing] = await internalFindByIds(context, user, [relationshipId], { baseData: true }) as StoreRelation[];
    if (existing) {
      await deleteElementById(context, user, relationshipId, existing.entity_type);
      deletedIds.push(relationshipId);
    }
  }
  return { appliedPatch: { operations: [], deleted_ids: deletedIds, applied_at: now() }, mergeRecordId: null };
};

const applyUnrevokeIndicator = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const indicator = await loadSubject(context, user, payload.indicator_id ?? proposal.target_id);
  const record = indicator as Record<string, any>;
  // The indicator is reactivated for its original lifetime (bounded), otherwise the expiration manager revokes it again.
  const lifetimeMs = record.valid_from && record.valid_until ? new Date(record.valid_until).getTime() - new Date(record.valid_from).getTime() : 0;
  const lifetimeDays = Math.min(MAX_REACTIVATION_DAYS, Math.max(MIN_REACTIVATION_DAYS, Math.round(lifetimeMs / (24 * 3600 * 1000))));
  const validUntil = new Date(Date.now() + lifetimeDays * 24 * 3600 * 1000).toISOString();
  await updateAttribute(context, user, indicator.internal_id, indicator.entity_type, replaceInputs({ revoked: false, valid_until: validUntil }));
  return {
    appliedPatch: {
      operations: [patchOperation(indicator, 'revoked', record.revoked, false), patchOperation(indicator, 'valid_until', record.valid_until, validUntil)],
      applied_at: now(),
    },
    mergeRecordId: null,
  };
};

const applyRevoke = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal): Promise<ApplyResult> => {
  const element = await loadSubject(context, user, proposal.target_id ?? proposal.subject_ids[0]);
  if (!schemaAttributesDefinition.getAttribute(element.entity_type, 'revoked')) {
    throw FunctionalError('This entity type cannot be revoked', { entity_type: element.entity_type });
  }
  const previous = (element as Record<string, any>).revoked ?? false;
  await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs({ revoked: true }));
  return { appliedPatch: { operations: [patchOperation(element, 'revoked', previous, true)], applied_at: now() }, mergeRecordId: null };
};

const applyPreserveProcedure = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const relationship = await loadSubject(context, user, payload.relationship_id ?? proposal.target_id) as StoreRelation;
  const previous = payload.previous as ConflictingProcedure;
  const current = payload.current as ConflictingProcedure;
  if (settings.relationship_conflict_mode === RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY) {
    return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
  }
  if (settings.relationship_conflict_mode === RELATIONSHIP_CONFLICT_MODE_PROCEDURES && isProceduresAttributeAvailable(relationship.entity_type)) {
    const existing = ((relationship as Record<string, any>)[ATTRIBUTE_PROCEDURES] ?? []) as ProcedureEntry[];
    const additions = procedureAdditions(existing, [previous, current], now());
    if (additions.length === 0) {
      return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
    }
    const next = [...existing, ...additions];
    await updateAttribute(context, user, relationship.internal_id, relationship.entity_type, [{ key: ATTRIBUTE_PROCEDURES, value: next }]);
    return { appliedPatch: { operations: [patchOperation(relationship, ATTRIBUTE_PROCEDURES, existing, next)], applied_at: now() }, mergeRecordId: null };
  }
  // Note mode (also the fallback when the procedures attribute is not available on this platform): the overwritten
  // procedure is kept as a note attached to the relationship, without touching the relationship identity.
  const author = previous.source_id ? await storeLoadById(context, user, previous.source_id, ENTITY_TYPE_IDENTITY) : undefined;
  const note = await createEntity(context, user, procedureNoteInput({
    internal_id: relationship.internal_id,
    fromName: (relationship.from as { name?: string } | undefined)?.name ?? relationship.fromId,
    toName: (relationship.to as { name?: string } | undefined)?.name ?? relationship.toId,
    markingIds: ((relationship as Record<string, any>).objectMarking ?? []).map((marking: BasicStoreBase) => marking.internal_id),
  }, previous.text, author?.internal_id ?? null), ENTITY_TYPE_CONTAINER_NOTE);
  return { appliedPatch: { operations: [], created_ids: [note.internal_id ?? note.id], applied_at: now() }, mergeRecordId: null };
};

const applySetField = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  const payload = { ...parsePayload(proposal), ...(opts.payload ?? {}) };
  const element = await loadSubject(context, user, payload.element_id ?? proposal.target_id);
  const key = payload.key as string;
  if (!schemaAttributesDefinition.getAttribute(element.entity_type, key)) {
    throw FunctionalError('Unknown attribute for this entity type', { key, entity_type: element.entity_type });
  }
  const previous = (element as Record<string, any>)[key];
  await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs({ [key]: payload.value }));
  return { appliedPatch: { operations: [patchOperation(element, key, previous, payload.value)], applied_at: now() }, mergeRecordId: null };
};
// endregion

/**
 * Execute the action of a proposal with the rights of the given user. The decision of an adjudicator can change the
 * action of a duplicate proposal (alias instead of merge).
 */
export const executeProposalAction = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
  opts: ApplyOptions = {},
): Promise<ApplyResult> => {
  const action = effectiveProposalAction(proposal, opts.decision);
  if (action === ACTION_ADD_ALIASES && proposal.recommended_action !== ACTION_ADD_ALIASES) {
    return applyAliasDecision(context, user, proposal, opts);
  }
  switch (action) {
    case ACTION_MERGE:
      return applyMerge(context, user, proposal, opts);
    case ACTION_ADD_ALIASES:
      return applyAddAliases(context, user, proposal, opts);
    case ACTION_UNMERGE: {
      if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMERGE)) {
        throw ForbiddenAccess('Reverting a merge requires the merge capability');
      }
      const payload = parsePayload(proposal);
      await unmergeFromRecord(context, user, payload.merge_record_id);
      return { appliedPatch: null, mergeRecordId: payload.merge_record_id };
    }
    case ACTION_FIX_DATES:
      return applyFixDates(context, user, proposal);
    case ACTION_RESOLVE_ATTRIBUTION:
      return applyResolveAttribution(context, user, proposal, opts);
    case ACTION_UNREVOKE_INDICATOR:
      return applyUnrevokeIndicator(context, user, proposal);
    case ACTION_REVOKE:
      return applyRevoke(context, user, proposal);
    case ACTION_PRESERVE_PROCEDURE:
      return applyPreserveProcedure(context, user, proposal, settings);
    case ACTION_SET_FIELD:
      return applySetField(context, user, proposal, opts);
    case ACTION_ACKNOWLEDGE:
      return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
    default:
      throw FunctionalError('Unsupported curation action', { action: proposal.recommended_action });
  }
};

// region revert
const findDeleteOperationForElement = async (context: AuthContext, elementId: string) => {
  const operations = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_DELETE_OPERATION], {
    filters: { mode: FilterMode.And, filters: [{ key: ['main_entity_id'], values: [elementId], operator: FilterOperator.Eq }], filterGroups: [] },
    noFiltersChecking: true,
  });
  return operations[0];
};

const sameValue = (left: unknown, right: unknown) => JSON.stringify(left ?? null) === JSON.stringify(right ?? null);

export interface RevertReport {
  reverted_operations: number;
  skipped_operations: Array<{ element_id: string; key: string; reason: string }>;
}

/**
 * Revert a non-merge apply from its recorded patch: values are restored only if the element still holds the value the
 * apply wrote (later edits are kept and reported), created notes are deleted, deleted relationships are restored from
 * the trash.
 */
export const revertAppliedPatch = async (context: AuthContext, user: AuthUser, patch: AppliedPatch): Promise<RevertReport> => {
  const report: RevertReport = { reverted_operations: 0, skipped_operations: [] };
  const byElement = R.groupBy((operation: AppliedPatchOperation) => operation.element_id, patch.operations ?? []);
  const entries = Object.entries(byElement) as Array<[string, AppliedPatchOperation[]]>;
  for (let index = 0; index < entries.length; index += 1) {
    const [elementId, operations] = entries[index];
    const loaded = await storeLoadByIdWithRefs<StoreObject>(context, user, elementId);
    if (!loaded) {
      operations.forEach((operation) => report.skipped_operations.push({ element_id: elementId, key: operation.key, reason: 'element not found' }));
      continue;
    }
    // The comparison and the restore run under the element lock, which every update takes: no edit can land
    // between them and be overwritten by the restored value.
    const lockIds = getInstanceIds(loaded);
    let lock;
    try {
      lock = await lockResources(lockIds, { draftId: getDraftContext(context, user) });
      const element = await storeLoadByIdWithRefs<StoreObject>(context, user, elementId);
      if (!element) {
        operations.forEach((operation) => report.skipped_operations.push({ element_id: elementId, key: operation.key, reason: 'element not found' }));
        continue;
      }
      controlUserConfidenceAgainstElement(user, element);
      const changes: Record<string, unknown> = {};
      operations.forEach((operation) => {
        if (sameValue((element as Record<string, any>)[operation.key], operation.value)) {
          changes[operation.key] = operation.previous;
        } else {
          report.skipped_operations.push({ element_id: elementId, key: operation.key, reason: 'value changed since the apply' });
        }
      });
      if (Object.keys(changes).length > 0) {
        await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs(changes), { locks: lockIds });
        report.reverted_operations += Object.keys(changes).length;
      }
    } finally {
      if (lock) {
        await lock.unlock();
      }
    }
  }
  const createdIds = patch.created_ids ?? [];
  for (let index = 0; index < createdIds.length; index += 1) {
    const [created] = await internalFindByIds(context, user, [createdIds[index]], { baseData: true }) as BasicStoreBase[];
    if (created) {
      await deleteElementById(context, user, created.internal_id, created.entity_type);
      report.reverted_operations += 1;
    }
  }
  const deletedIds = patch.deleted_ids ?? [];
  for (let index = 0; index < deletedIds.length; index += 1) {
    const deleteOperation = await findDeleteOperationForElement(context, deletedIds[index]);
    if (deleteOperation) {
      await restoreDelete(context, user, deleteOperation.internal_id);
      report.reverted_operations += 1;
    } else {
      report.skipped_operations.push({ element_id: deletedIds[index], key: 'relationship', reason: 'not found in the trash anymore' });
    }
  }
  return report;
};
// endregion
