import * as R from 'ramda';
import { v5 as uuidv5 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreRelation, StoreObject, StoreRelation } from '../../types/store';
import { FunctionalError, ForbiddenAccess } from '../../config/errors';
import { createEntity, deleteElementById, mergeEntities, storeLoadByIdWithRefs, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, fullRelationsList, internalFindByIds, pageEntitiesConnection, pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ENTITY_TYPE_IDENTITY, OPENCTI_NAMESPACE } from '../../schema/general';
import { generateAliasesId, getInstanceIds } from '../../schema/identifier';
import { lockResources } from '../../lock/master-lock';
import { getDraftContext } from '../../utils/draftContext';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNMERGE, KNOWLEDGE_ORGANIZATION_RESTRICT, SYSTEM_USER } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { resolveAliasesField, ENTITY_TYPE_CONTAINER_NOTE } from '../../schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { type EditInput, FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { REVOKED, VALID_UNTIL } from '../../schema/identifier';
import { computeIndicatorEditInput } from '../indicator/indicator-domain';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
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
  IRREVERSIBLE_MERGE_INTERRUPTED,
  EVIDENCE_DECAYED_INDICATOR,
  EVIDENCE_STALENESS,
  MERGE_STATUS_REVERTED,
  PROPOSAL_KIND_STALE,
  RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY,
} from './curation-types';
import { unmergeFromRecord } from './curation-merge-record';
import { isDecayedToRevocation, observablesActiveSinceRevocation } from './curation-detectors';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { RELATION_GRANTED_TO } from '../../schema/stixRefRelationship';
import { effectiveProposalAction } from './curation-access';
import { type ConflictingProcedure, procedureNoteInput } from './curation-procedures';

const MIN_REACTIVATION_DAYS = 30;
const MAX_REACTIVATION_DAYS = 365;

export interface ApplyOptions {
  targetId?: string | null;
  decision?: string | null;
  payload?: Record<string, unknown> | null;
  /** Receives the change an action is about to make, before it touches the graph, to keep it durably. */
  onBeforeChange?: (planned: ApplyResult) => Promise<void>;
}

export interface ApplyResult {
  appliedPatch: AppliedPatch | null;
  mergeRecordId: string | null;
}

const planned = async (opts: ApplyOptions, patch: AppliedPatch) => {
  if (opts.onBeforeChange) await opts.onBeforeChange({ appliedPatch: patch, mergeRecordId: null });
  return patch;
};

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

/**
 * Run *change* on the element read again under its lock, which every update of the element takes: what *change* reads
 * cannot be modified before the update it makes with the given locks.
 */
const withSubjectLock = async <T>(
  context: AuthContext,
  user: AuthUser,
  element: StoreObject,
  change: (current: StoreObject, lockIds: string[]) => Promise<T>,
): Promise<T> => {
  const lockIds = getInstanceIds(element);
  let lock;
  try {
    lock = await lockResources(lockIds, { draftId: getDraftContext(context, user) });
    return await change(await loadSubject(context, user, element.internal_id), lockIds);
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

const patchOperation = (element: BasicStoreBase, key: string, previous: unknown, value: unknown): AppliedPatchOperation => ({
  element_id: element.internal_id,
  entity_type: element.entity_type,
  key,
  previous: previous ?? null,
  value: value ?? null,
});

const sameValue = (left: unknown, right: unknown) => JSON.stringify(left ?? null) === JSON.stringify(right ?? null);

const replaceInputs = (changes: Record<string, unknown>) => Object.entries(changes).map(([key, value]) => ({
  key,
  value: value === null || value === undefined ? [] : (Array.isArray(value) ? value : [value]),
}));

/**
 * The fields an edit of an Indicator changes once its lifecycle is computed, as an edit through the Indicator API does:
 * revoking or reactivating it also sets its score, detection, validity and decay. Every change is recorded in the
 * applied patch, so a revert restores the Indicator as it was.
 */
const indicatorLifecycleChanges = (user: AuthUser, indicator: StoreObject, input: EditInput[]): Record<string, unknown> => {
  const record = indicator as Record<string, any>;
  const changes: Record<string, unknown> = {};
  computeIndicatorEditInput(user, indicator as unknown as BasicStoreEntityIndicator, input).forEach((edit) => {
    const multiple = schemaAttributesDefinition.getAttribute(indicator.entity_type, edit.key)?.multiple ?? false;
    const value = multiple ? edit.value : (edit.value?.[0] ?? null);
    if (!sameValue(record[edit.key], value)) changes[edit.key] = value;
  });
  return changes;
};

const changeOperations = (element: StoreObject, changes: Record<string, unknown>) => {
  const record = element as Record<string, any>;
  return Object.entries(changes).map(([key, value]) => patchOperation(element, key, record[key], value));
};

export const findLatestMergeRecordForProposal = async (context: AuthContext, proposalId: string) => {
  const records = await pageEntitiesConnection<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
    filters: { mode: FilterMode.And, filters: [{ key: ['proposal_id'], values: [proposalId] }], filterGroups: [] },
    noFiltersChecking: true,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    first: 1,
  });
  return records.edges[0]?.node ?? null;
};

/** Whether an earlier attempt to apply the proposal left a merge interrupted, other than the given merge record. */
export const hasInterruptedMergeForProposal = async (context: AuthContext, proposalId: string, exceptRecordId: string) => {
  const records = await fullEntitiesList<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
    filters: { mode: FilterMode.And, filters: [{ key: ['proposal_id'], values: [proposalId] }], filterGroups: [] },
    noFiltersChecking: true,
  });
  return records.some((record) => record.internal_id !== exceptRecordId && record.irreversible_reason === IRREVERSIBLE_MERGE_INTERRUPTED);
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

// The aliases are read and replaced under the entity lock: an alias added at the same time is never dropped.
const addAliases = async (context: AuthContext, user: AuthUser, subject: StoreObject, aliases: string[], opts: ApplyOptions): Promise<ApplyResult> => {
  return withSubjectLock(context, user, subject, async (element, lockIds) => {
    const aliasField = resolveAliasesField(element.entity_type).name;
    const current = ((element as Record<string, any>)[aliasField] ?? []) as string[];
    const currentKeys = new Set([(element as Record<string, any>).name, ...current].filter(Boolean).map((value: string) => value.toLowerCase()));
    const toAdd = R.uniq(aliases.filter((alias) => alias && !currentKeys.has(alias.toLowerCase())));
    if (toAdd.length === 0) {
      return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
    }
    const next = [...current, ...toAdd];
    const patch = await planned(opts, { operations: [patchOperation(element, aliasField, current, next)], applied_at: now() });
    await updateAttribute(context, user, element.internal_id, element.entity_type, [{ key: aliasField, value: next }], { locks: lockIds });
    return { appliedPatch: patch, mergeRecordId: null };
  });
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
  // An alias names a single entity: the names of subjects that still exist cannot become aliases of another one.
  const owners = await internalFindByIds(context, SYSTEM_USER, generateAliasesId(others, target), { type: target.entity_type, baseData: true }) as BasicStoreBase[];
  const ownerIds = R.uniq(owners.map((owner) => owner.internal_id).filter((id) => id !== target.internal_id));
  if (ownerIds.length > 0) {
    throw FunctionalError('These names still belong to other entities and cannot become aliases: merge the entities, or reject the proposal to keep them apart', {
      proposal_id: proposal.internal_id,
      existing_ids: ownerIds,
    });
  }
  return addAliases(context, user, target, others, opts);
};

const applyAddAliases = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions) => {
  const proposedTargetId = proposal.target_id ?? proposal.subject_ids[0];
  // The aliases of the payload name the other subjects for the proposed target: another target takes their names.
  if (opts.targetId && opts.targetId !== proposedTargetId) {
    return applyAliasDecision(context, user, proposal, opts);
  }
  // The aliases are the detector's: an accept never adds others than the proposed ones.
  const payload = parsePayload(proposal);
  const element = await loadSubject(context, user, proposedTargetId);
  return addAliases(context, user, element, (payload.aliases ?? []) as string[], opts);
};

const applyFixDates = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const subject = await loadSubject(context, user, proposal.target_id ?? proposal.subject_ids[0]);
  // Read, checked and written under the entity lock: a concurrent edit of either date is never overwritten.
  return withSubjectLock(context, user, subject, async (element, lockIds) => {
    const record = element as Record<string, any>;
    const start = record[payload.start_field];
    const stop = record[payload.stop_field];
    if (!start || !stop || new Date(start).getTime() <= new Date(stop).getTime()) {
      throw FunctionalError('The dates are not inverted anymore, nothing to fix', { id: element.internal_id });
    }
    const patch = await planned(opts, {
      operations: [patchOperation(element, payload.start_field, start, stop), patchOperation(element, payload.stop_field, stop, start)],
      applied_at: now(),
    });
    const inputs = replaceInputs({ [payload.start_field]: stop, [payload.stop_field]: start });
    await updateAttribute(context, user, element.internal_id, element.entity_type, inputs, { locks: lockIds });
    return { appliedPatch: patch, mergeRecordId: null };
  });
};

// The newest delete operation of an element, created no later than a date when one is given: a relationship deleted,
// restored and deleted again has several.
const findDeleteOperationForElement = async (context: AuthContext, elementId: string, createdBefore?: string) => {
  const filters = [{ key: ['main_entity_id'], values: [elementId], operator: FilterOperator.Eq }];
  if (createdBefore) filters.push({ key: ['created_at'], values: [createdBefore], operator: FilterOperator.Lte });
  const operations = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_DELETE_OPERATION], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    maxSize: 1,
    noFiltersChecking: true,
  } as any);
  return operations[0];
};

// The delete operations that put deleted relationships in the trash, recorded right after the deletion so that a
// revert restores this deletion and never a later one. Absent when the trash is disabled.
const deleteOperationsOf = async (context: AuthContext, deletedIds: string[]) => {
  const operationIds: Record<string, string> = {};
  for (let index = 0; index < deletedIds.length; index += 1) {
    const operation = await findDeleteOperationForElement(context, deletedIds[index]);
    if (operation) operationIds[deletedIds[index]] = operation.internal_id;
  }
  return operationIds;
};

const applyResolveAttribution = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  // The caller only chooses the attribution to keep: the attributions in conflict are the detector's.
  const payload = parsePayload(proposal);
  const keepActorId = (opts.payload?.keep_actor_id ?? payload.keep_actor_id) as string | undefined;
  const relationships = (payload.relationships ?? []) as Array<{ actor_id: string; relationship_id: string }>;
  if (!keepActorId || !relationships.some((relation) => relation.actor_id === keepActorId)) {
    throw FunctionalError('Choose which attribution to keep (keep_actor_id) to resolve this contradiction', { proposal_id: proposal.internal_id });
  }
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNDELETE)) {
    throw ForbiddenAccess('Removing an attribution requires the delete capability');
  }
  const relationshipIds = relationships.map((relation) => relation.relationship_id);
  const keptIds = R.uniq(relationships.filter((relation) => relation.actor_id === keepActorId).map((relation) => relation.relationship_id));
  // The attributions to keep stay locked until the other ones are deleted: a deletion takes the lock of the element it
  // deletes, so a concurrent deletion of a kept attribution waits and the object never loses its last attribution.
  // Only the kept ones are held, since each deletion below takes the lock of the attribution it removes.
  const kept = await internalFindByIds(context, SYSTEM_USER, keptIds, { baseData: true }) as StoreRelation[];
  let lock;
  try {
    lock = await lockResources(R.uniq([...keptIds, ...kept.flatMap((relation) => getInstanceIds(relation))]), { draftId: getDraftContext(context, user) });
    // The contradiction is only resolved by a user who can read every attribution in conflict: an attribution hidden
    // from the user is neither removed nor reported as resolved. An attribution deleted since needs no removal.
    const existing = await internalFindByIds(context, SYSTEM_USER, relationshipIds, { baseData: true }) as StoreRelation[];
    const readable = await internalFindByIds(context, user, relationshipIds, { baseData: true }) as StoreRelation[];
    const readableById = new Map(readable.flatMap((relation) => [[relation.internal_id, relation], [relation.standard_id, relation]]));
    if (existing.some((relation) => !readableById.has(relation.internal_id))) {
      throw ForbiddenAccess('You cannot read every attribution in conflict: this contradiction is resolved by a user who can read them all');
    }
    // The attribution to keep must still exist, and so must another one. An attempt that stopped after deleting is
    // recorded from its plan without running the action again (see reconcilePlannedApplication).
    const existingIds = new Set(existing.flatMap((relation) => [relation.internal_id, relation.standard_id]));
    const remaining = relationships.filter((relation) => existingIds.has(relation.relationship_id));
    if (!remaining.some((relation) => relation.actor_id === keepActorId)) {
      throw FunctionalError('The attribution to keep was deleted since the proposal was raised: reject the proposal', { proposal_id: proposal.internal_id });
    }
    if (!remaining.some((relation) => relation.actor_id !== keepActorId)) {
      throw FunctionalError('The other attributions were deleted since the proposal was raised, so the contradiction is resolved: reject the proposal', {
        proposal_id: proposal.internal_id,
      });
    }
    const toDelete = relationships
      .filter((relation) => relation.actor_id !== keepActorId)
      .map((relation) => relation.relationship_id)
      .filter((relationshipId) => readableById.has(relationshipId));
    if (toDelete.length > 0) {
      await planned(opts, { operations: [], deleted_ids: toDelete, applied_at: now() });
    }
    const deletedIds: string[] = [];
    for (let index = 0; index < toDelete.length; index += 1) {
      const relationshipId = toDelete[index];
      await deleteElementById(context, user, relationshipId, (readableById.get(relationshipId) as StoreRelation).entity_type);
      deletedIds.push(relationshipId);
    }
    const deleteOperationIds = await deleteOperationsOf(context, deletedIds);
    return { appliedPatch: { operations: [], deleted_ids: deletedIds, delete_operation_ids: deleteOperationIds, applied_at: now() }, mergeRecordId: null };
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

const applyUnrevokeIndicator = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const subject = await loadSubject(context, user, payload.indicator_id ?? proposal.target_id);
  return withSubjectLock(context, user, subject, async (indicator, lockIds) => {
    const record = indicator as Record<string, any>;
    if (record.revoked !== true) {
      throw FunctionalError('This indicator is not revoked any more, so the contradiction is resolved: reject the proposal', { id: indicator.internal_id });
    }
    // The contradiction is checked again by the detector's own rule: an observable seen active since the proposal was
    // raised may have been lowered or removed since.
    const basedOn = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, RELATION_BASED_ON, { fromId: indicator.internal_id, baseData: true });
    const observableIds = R.uniq(basedOn.map((relation) => relation.toId));
    const observables = observableIds.length > 0 ? await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, observableIds) : [];
    if (observablesActiveSinceRevocation(record, observables as Array<BasicStoreEntity & Record<string, any>>).length === 0) {
      throw FunctionalError('No observable this indicator is based on is active since its revocation any more, so the contradiction is resolved: reject the proposal', { id: indicator.internal_id });
    }
    // Reactivated as an edit of the Indicator does: with a decay rule, the decay restarts from the base score for the decay
    // lifetime; without one, the default score and validity apply. Under a decay exclusion, the validity is its original
    // lifetime (bounded), otherwise the expiration manager revokes it again.
    const lifetimeMs = record.valid_from && record.valid_until ? new Date(record.valid_until).getTime() - new Date(record.valid_from).getTime() : 0;
    const lifetimeDays = Math.min(MAX_REACTIVATION_DAYS, Math.max(MIN_REACTIVATION_DAYS, Math.round(lifetimeMs / (24 * 3600 * 1000))));
    const validUntil = new Date(Date.now() + lifetimeDays * 24 * 3600 * 1000).toISOString();
    const changes = indicatorLifecycleChanges(user, indicator, [{ key: REVOKED, value: [false] }, { key: VALID_UNTIL, value: [validUntil] }]);
    const patch = await planned(opts, { operations: changeOperations(indicator, changes), applied_at: now() });
    await updateAttribute(context, user, indicator.internal_id, indicator.entity_type, replaceInputs(changes), { locks: lockIds });
    return { appliedPatch: patch, mergeRecordId: null };
  });
};

const evidenceDetails = (proposal: BasicStoreEntityCurationProposal, evidenceType: string): Record<string, any> | null => {
  const item = (proposal.curation_evidence ?? []).find((entry) => entry.evidence_type === evidenceType);
  if (!item) return null;
  try {
    return item.details ? JSON.parse(item.details) : {};
  } catch {
    return {};
  }
};

const notStaleAnyMore = (id: string, months: number) => FunctionalError(
  'This entity was updated or gained a relationship since the proposal was raised, so it is not stale any more: reject the proposal',
  { id, months },
);

// Every relationship counts, including the ones the user applying the proposal cannot read.
const hasRelationshipSince = async (context: AuthContext, elementId: string, cutoff: string) => {
  const recent = await pageRelationsConnection(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    fromOrToId: [elementId],
    filters: { mode: FilterMode.And, filters: [{ key: ['updated_at'], values: [cutoff], operator: FilterOperator.Gte }], filterGroups: [] },
    first: 1,
  });
  return recent.edges.length > 0;
};

/**
 * A staleness finding is checked again on the current entity before anything is revoked, by an analyst or a policy:
 * a decayed indicator whose score is back above its revoke score, or an entity updated or given a new or updated
 * relationship within the staleness period, is not stale any more. Returns the staleness period the relationships are
 * checked on, none for a decayed indicator.
 */
const assertStillStale = async (context: AuthContext, proposal: BasicStoreEntityCurationProposal, element: BasicStoreBase) => {
  const record = element as Record<string, any>;
  if (evidenceDetails(proposal, EVIDENCE_DECAYED_INDICATOR)) {
    if (!isDecayedToRevocation(record)) {
      throw FunctionalError('The score of this indicator is above its revoke score again: reject the proposal', { id: element.internal_id });
    }
    return null;
  }
  const months = Number(evidenceDetails(proposal, EVIDENCE_STALENESS)?.months);
  if (!Number.isFinite(months) || months <= 0) {
    throw FunctionalError('This staleness proposal does not say which period it was measured on: reject it, the next scan raises it again if it still applies', { proposal_id: proposal.internal_id });
  }
  const cutoff = new Date(Date.now() - months * 30 * 24 * 3600 * 1000).toISOString();
  if (record.updated_at && new Date(record.updated_at).toISOString() >= cutoff) {
    throw notStaleAnyMore(element.internal_id, months);
  }
  if (await hasRelationshipSince(context, element.internal_id, cutoff)) {
    throw notStaleAnyMore(element.internal_id, months);
  }
  return { cutoff, months };
};

/**
 * The staleness check and the revocation run under the entity lock, so an update of the entity cannot land between
 * them. A relationship write does not take the lock of its endpoints: the relationships are checked once more after the
 * revocation, and an entity that gained one meanwhile is put back as it was.
 */
const applyRevoke = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  const subject = await loadSubject(context, user, proposal.target_id ?? proposal.subject_ids[0]);
  if (!schemaAttributesDefinition.getAttribute(subject.entity_type, 'revoked')) {
    throw FunctionalError('This entity type cannot be revoked', { entity_type: subject.entity_type });
  }
  return withSubjectLock(context, user, subject, async (element, lockIds) => {
    const period = proposal.proposal_kind === PROPOSAL_KIND_STALE ? await assertStillStale(context, proposal, element) : null;
    const record = element as Record<string, any>;
    // An Indicator is revoked as an edit of the Indicator does: revoke score, no detection, validity ending now.
    const changes = element.entity_type === ENTITY_TYPE_INDICATOR
      ? indicatorLifecycleChanges(user, element, [{ key: REVOKED, value: [true] }])
      : { revoked: true };
    const operations = element.entity_type === ENTITY_TYPE_INDICATOR
      ? changeOperations(element, changes)
      : [patchOperation(element, 'revoked', record.revoked ?? false, true)];
    const patch = await planned(opts, { operations, applied_at: now() });
    if (operations.length > 0) {
      await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs(changes), { locks: lockIds });
    }
    if (period && operations.length > 0 && await hasRelationshipSince(context, element.internal_id, period.cutoff)) {
      const restored = Object.fromEntries(operations.map((operation) => [operation.key, operation.previous]));
      await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs(restored), { locks: lockIds });
      throw notStaleAnyMore(element.internal_id, period.months);
    }
    return { appliedPatch: patch, mergeRecordId: null };
  });
};

// The note of an application carries an identifier derived from its proposal: an attempt that stopped before recording
// it upserts the same note when retried, and a matching note written by anyone else is never taken for it.
export const procedureNoteStixId = (proposalId: string) => `note--${uuidv5(`curation-procedure-note:${proposalId}`, OPENCTI_NAMESPACE)}`;

const applyPreserveProcedure = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
): Promise<ApplyResult> => {
  const payload = parsePayload(proposal);
  const relationship = await loadSubject(context, user, payload.relationship_id ?? proposal.target_id) as StoreRelation;
  const previous = payload.previous as ConflictingProcedure;
  if (settings.relationship_conflict_mode === RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY) {
    return { appliedPatch: { operations: [], applied_at: now() }, mergeRecordId: null };
  }
  // Note mode: the overwritten procedure is kept as a note attached to the relationship, without touching the
  // relationship identity.
  const organizationIds = ((relationship as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[];
  // An entity keeps the organization sharing it is created with only for a user allowed to restrict by organization:
  // for anyone else, the note of a relationship shared with selected organizations would be visible beyond them.
  if (organizationIds.length > 0 && !isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
    throw ForbiddenAccess('Keeping the procedure of a relationship shared with selected organizations requires the Restrict organization access capability');
  }
  const author = previous.source_id ? await storeLoadById(context, user, previous.source_id, ENTITY_TYPE_IDENTITY) : undefined;
  const noteInput = procedureNoteInput({
    internal_id: relationship.internal_id,
    fromName: (relationship.from as { name?: string } | undefined)?.name ?? relationship.fromId,
    toName: (relationship.to as { name?: string } | undefined)?.name ?? relationship.toId,
    markingIds: ((relationship as Record<string, any>).objectMarking ?? []).map((marking: BasicStoreBase) => marking.internal_id),
    organizationIds,
  }, previous.text, author?.internal_id ?? null);
  const note = await createEntity(context, user, { ...noteInput, stix_id: procedureNoteStixId(proposal.internal_id) }, ENTITY_TYPE_CONTAINER_NOTE);
  return { appliedPatch: { operations: [], created_ids: [note.internal_id ?? note.id], applied_at: now() }, mergeRecordId: null };
};

const normalizeFieldValue = (attributeType: string, value: unknown): unknown => {
  if (value === undefined || value === null || value === '') return null;
  if (Array.isArray(value)) return value.map((item) => normalizeFieldValue(attributeType, item));
  if (attributeType === 'date' && (typeof value === 'string' || value instanceof Date)) {
    const time = new Date(value).getTime();
    return Number.isNaN(time) ? value : time;
  }
  return value;
};

const isSameFieldValue = (attributeType: string, left: unknown, right: unknown) => {
  return R.equals(normalizeFieldValue(attributeType, left), normalizeFieldValue(attributeType, right));
};

const applySetField = async (context: AuthContext, user: AuthUser, proposal: BasicStoreEntityCurationProposal, opts: ApplyOptions): Promise<ApplyResult> => {
  // The field and its value are the detector's: an accept never writes another value.
  const payload = parsePayload(proposal);
  const subject = await loadSubject(context, user, payload.element_id ?? proposal.target_id);
  const key = payload.key as string;
  const attribute = schemaAttributesDefinition.getAttribute(subject.entity_type, key);
  if (!attribute) {
    throw FunctionalError('Unknown attribute for this entity type', { key, entity_type: subject.entity_type });
  }
  // The authoritative value only replaces the write the detector saw: a later write, of any source, is kept.
  if (payload?.overwritten_value === undefined) {
    throw FunctionalError('This proposal does not say which value it replaces: reject it, the field authority rules raise it again on the next overwrite', { proposal_id: proposal.internal_id });
  }
  // Checked and written under the entity lock: a write landing between the check and the restore is never overwritten.
  return withSubjectLock(context, user, subject, async (element, lockIds) => {
    const previous = (element as Record<string, any>)[key];
    if (!isSameFieldValue(attribute.type, previous, payload.overwritten_value)) {
      throw FunctionalError('This field was written again since the proposal was raised, so restoring the authoritative value would overwrite a newer one: reject the proposal', { id: element.internal_id, key });
    }
    const patch = await planned(opts, { operations: [patchOperation(element, key, previous, payload.value)], applied_at: now() });
    await updateAttribute(context, user, element.internal_id, element.entity_type, replaceInputs({ [key]: payload.value }), { locks: lockIds });
    return { appliedPatch: patch, mergeRecordId: null };
  });
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
      if (opts.onBeforeChange) await opts.onBeforeChange({ appliedPatch: null, mergeRecordId: payload.merge_record_id });
      await unmergeFromRecord(context, user, payload.merge_record_id);
      return { appliedPatch: null, mergeRecordId: payload.merge_record_id };
    }
    case ACTION_FIX_DATES:
      return applyFixDates(context, user, proposal, opts);
    case ACTION_RESOLVE_ATTRIBUTION:
      return applyResolveAttribution(context, user, proposal, opts);
    case ACTION_UNREVOKE_INDICATOR:
      return applyUnrevokeIndicator(context, user, proposal, opts);
    case ACTION_REVOKE:
      return applyRevoke(context, user, proposal, opts);
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

export interface ReconciledApplication {
  /** The part of the planned change found in the graph, null when none of it is. */
  result: ApplyResult | null;
  /** True when all of it is: the action must not run again. */
  complete: boolean;
}

// An attribute never written reads as its empty form: a value planned as false or empty is found as nothing too.
const isUnset = (value: unknown) => value === undefined || value === null || value === false || value === '' || (Array.isArray(value) && value.length === 0);

// The planned write is the evidence: only the planned value counts as applied, a third value is another writer's.
const isAppliedOperation = async (context: AuthContext, operation: AppliedPatchOperation) => {
  const element = await storeLoadById(context, SYSTEM_USER, operation.element_id, operation.entity_type) as unknown as Record<string, unknown> | undefined;
  if (!element) return false;
  const current = element[operation.key];
  return sameValue(current, operation.value) || (isUnset(current) && isUnset(operation.value));
};

/**
 * What of a change planned by an attempt that stopped before recording it reached the graph, read back from the
 * graph: an attribute that holds the planned value, an element that is gone, a merge record that is reverted. A
 * change that never reached the graph is run again by the next attempt.
 */
export const reconcilePlannedApplication = async (context: AuthContext, plan: ApplyResult): Promise<ReconciledApplication> => {
  if (!plan.appliedPatch) {
    if (!plan.mergeRecordId) return { result: null, complete: false };
    const record = await storeLoadById<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, plan.mergeRecordId, ENTITY_TYPE_MERGE_RECORD);
    const complete = record?.merge_status === MERGE_STATUS_REVERTED;
    return { result: complete ? plan : null, complete };
  }
  const patch = plan.appliedPatch;
  const operations: AppliedPatchOperation[] = [];
  for (let index = 0; index < patch.operations.length; index += 1) {
    if (await isAppliedOperation(context, patch.operations[index])) operations.push(patch.operations[index]);
  }
  const plannedDeletions = patch.deleted_ids ?? [];
  const remaining = plannedDeletions.length > 0 ? await internalFindByIds(context, SYSTEM_USER, plannedDeletions, { baseData: true }) as BasicStoreBase[] : [];
  const remainingIds = new Set(remaining.flatMap((element) => [element.internal_id, element.standard_id]));
  const deletedIds = plannedDeletions.filter((id) => !remainingIds.has(id));
  const found = operations.length + deletedIds.length;
  if (found === 0) return { result: null, complete: false };
  const complete = operations.length === patch.operations.length
    && deletedIds.length === plannedDeletions.length;
  const result: AppliedPatch = { ...patch, operations, deleted_ids: deletedIds };
  if (deletedIds.length > 0) result.delete_operation_ids = await deleteOperationsOf(context, deletedIds);
  return { result: { appliedPatch: result, mergeRecordId: plan.mergeRecordId }, complete };
};

// region revert
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
        const current = (element as Record<string, any>)[operation.key];
        if (sameValue(current, operation.value)) {
          changes[operation.key] = operation.previous;
        } else if (sameValue(current, operation.previous)) {
          // Already restored, by a revert retried after it failed to close the proposal.
          report.reverted_operations += 1;
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
    // Only the deletion of this apply is restored: once restored, a later deletion of the relationship is the user's.
    const recordedId = patch.delete_operation_ids?.[deletedIds[index]];
    const deleteOperation = recordedId
      ? await storeLoadById<BasicStoreEntity>(context, SYSTEM_USER, recordedId, ENTITY_TYPE_DELETE_OPERATION)
      : await findDeleteOperationForElement(context, deletedIds[index], patch.applied_at);
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
