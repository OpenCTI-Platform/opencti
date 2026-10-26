// Merge of an incoming copy into an existing object, with today's rules and without a lock.
// It runs the same code as upsertElement / updateAttributeMetaResolved (confidence control, buildUpdatePatchForUpsert,
// generateInputsForUpsert, updateAttributeRaw, the ref handling, i_attributes, the alias and standard id checks, the
// update event) on the object read by id. Only the write changes: the new version is written with if_seq_no, and
// when someone wrote in between, everything is recomputed on the newer version.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { lockfreeContext } from './context';
import { buildChanges } from '../../database/data-changes';
import {
  createContainerSharingTask,
  mergeInstanceWithInputs,
  mergeInstanceWithUpdateInputs,
  partialInstanceWithInputs,
  resolveRefsForInputs,
  triggerEntityUpdateAutoEnrichment,
  updateAttribute,
  updateAttributeRaw,
} from '../../database/middleware';
import {
  elRawBulk,
  elRawSearch,
  elRefreshIndices,
  elUpdateConnectionsOfElement,
  isImpactedTypeAndSide,
  prepareElementForIndexing,
  prepareIndexingElement,
  ROLE_FROM,
  ROLE_TO,
} from '../../database/engine';
import { buildInnerRelation } from '../../database/data-builder';
import { storeUpdateEvent } from '../../database/stream/stream-handler';
import { getEntityFromCache } from '../../database/cache';
import {
  extractObjectsPirsFromInputs,
  extractObjectsRestrictionsFromInputs,
  inferIndexFromConceptType,
  isEmptyField,
  isNotEmptyField,
  READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE,
} from '../../database/utils';
import { buildUpdatePatchForUpsert, generateInputsForUpsert } from '../../utils/upsert-utils';
import { controlUpsertInputWithUserConfidence } from '../../utils/confidence-level';
import { AccessOperation, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, SYSTEM_USER, validateUserAccessOperation } from '../../utils/access';
import { handleMarkingOperations } from '../../utils/markingDefinition-utils';
import { checkObservableSyntax } from '../../utils/syntax';
import { generateVulnerabilitiesUpdates } from '../../utils/vulnerabilities';
import { isIndividualAssociatedToUser } from '../../database/data-consistency';
import { rewriteEmbeddedDataUriImagesInDescriptions, rewriteEmbeddedDataUriImagesInUpdateInputs } from '../../database/middlewareEmbeddedImages';
import { findRemovedEmbeddedStoragePathsFromMarkdownFields, MARKDOWN_FIELD_KEY_SET } from '../../database/markdown-embedded-images';
import { deleteFile } from '../../database/file-storage';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { generateAliasesId, generateStandardId, getInstanceIds, isFieldContributingToStandardId } from '../../schema/identifier';
import { buildRefRelationKey, IDS_STIX } from '../../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, isStixObjectAliased } from '../../schema/stixDomainObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_VULNERABILITY } from '../../modules/vulnerability/vulnerability-types';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED } from '../../modules/securityCoverage/securityCoverage-types';
import { ACTION_TYPE_SHARE } from '../../domain/backgroundTask-common';
import { authorizedMembers, authorizedMembersActivationDate, iAttributes, modified, updatedAt, iAliasedIds } from '../../schema/attribute-definition';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import { computeDateFromEventId, now } from '../../utils/format';
import { deterministicId, type Owner, setKeys } from './identity';
import { liveOwners, loadWithRefs, mgetRaw, type RawDoc, toElements } from './load';
import { enqueue, type EndpointTask, type Task } from './queue';
import { versionOf } from './unchanged';
import { add, type Counters } from './store';

export interface WriteOptions {
  waitForSearch?: boolean; // each write searchable when the call returns (refresh wait_for), as today
  missingEnds?: 'pending' | 'error'; // a relationship whose end is missing waits (default) or fails as today
}

const metaId = (relationType: string, fromId: string, toId: string) => deterministicId(`${relationType}|${fromId}|${toId}`);

// Meta relationships of an object, with ids derived from their ends, ready to index
export const withMetaIds = (relations: any[]) => relations.map((meta: any) => {
  const id = metaId(meta.entity_type, meta.from.internal_id, meta.to.internal_id);
  return { ...meta, internal_id: id, id, standard_id: `relationship-meta--${id}` };
});

// The settler work a set of meta relationships creates or removes on their targets
export const metaTargetTasks = (metas: any[], op: 'add' | 'remove'): Task[] => metas
  .filter((meta) => isImpactedTypeAndSide(meta.entity_type, meta.from.entity_type, meta.to.entity_type, ROLE_TO))
  .map((meta) => ({
    kind: 'endpoint',
    op,
    endpoint: meta.to.internal_id,
    index: meta.to._index,
    type: meta.to.entity_type,
    relation_type: meta.entity_type,
    other: meta.from.internal_id,
    side: 'to',
    relation: meta.internal_id,
  }));

// Meta relationships written by today's path (random ids), from `fromId` to any of `toIds`
const searchMetaRelations = async (fromId: string, relationType: string, toIds: string[]) => {
  const connection = (ids: { term: Record<string, string> } | { terms: Record<string, string[]> }, role: string) => ({
    nested: { path: 'connections', query: { bool: { filter: [ids, { wildcard: { 'connections.role.keyword': role } }] } } },
  });
  const found: any = await elRawSearch(lockfreeContext, SYSTEM_USER, null, {
    index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    size: 1000,
    body: {
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': relationType } },
            connection({ term: { 'connections.internal_id.keyword': fromId } }, '*_from'),
            connection({ terms: { 'connections.internal_id.keyword': toIds } }, '*_to'),
          ],
        },
      },
    },
  });
  return found.hits.hits as { _index: string; _id: string }[];
};

// Delete meta relationships: by derived id when the lock-free path wrote them, by search otherwise
export const deleteMetaRelations = async (fromId: string, relationType: string, toIds: string[]) => {
  if (toIds.length === 0) return;
  const index = inferIndexFromConceptType(relationType);
  const response: any = await elRawBulk(lockfreeContext, {
    refresh: false,
    body: toIds.map((toId) => ({ delete: { _index: index, _id: metaId(relationType, fromId, toId) } })),
  });
  const missing = toIds.filter((_, i) => response.items[i].delete.status === 404);
  if (missing.length === 0) return;
  // Written by today's path (random ids): find them, after a refresh of the meta relationships only
  await elRefreshIndices([index]);
  const hits = await searchMetaRelations(fromId, relationType, missing);
  if (hits.length === 0) return;
  await elRawBulk(lockfreeContext, { refresh: false, body: hits.map((hit) => ({ delete: { _index: hit._index, _id: hit._id } })) });
};

// One bulk is indexed by one write thread per shard: a large one goes as several bulks at once, so Elasticsearch
// indexes them in parallel. Statuses come back in the order of the documents.
const BULK_SLICE = 500;
const BULK_SLICES_AT_ONCE = 4;
export const bulkCreateDocs = async (docs: any[], opts: WriteOptions) => {
  if (docs.length === 0) return [];
  const sliceSize = Math.max(BULK_SLICE, Math.ceil(docs.length / BULK_SLICES_AT_ONCE));
  const statuses = await Promise.all(R.splitEvery(sliceSize, docs).map(async (slice) => {
    const body = slice.flatMap((doc) => [{ create: { _index: doc._index, _id: doc.internal_id } }, R.dissoc('_index', doc)]);
    const response: any = await elRawBulk(lockfreeContext, { refresh: opts.waitForSearch ? 'wait_for' : false, body });
    return response.items.map((item: any) => {
      // 409: the id exists already, which the caller reads from the status
      if (item.create.status !== 201 && item.create.status !== 409) throw new Error(`Create failed: ${JSON.stringify(item.create.error)}`);
      return item.create.status as number;
    });
  }));
  return statuses.flat();
};

// ---------------------------------------------------------------------------------------------------------------
// updateAttributeMetaResolved, lock-free: same computation, version-checked write
// ---------------------------------------------------------------------------------------------------------------
// `pure`: the answer depends only on the object, the inputs, the user and the platform (no other object was read)
type Applied = { status: 'conflict' } | { status: 'updated' | 'unchanged'; element: any; event?: any; workflowStatusChanged?: boolean; pure?: boolean };

type ApplyOptions = WriteOptions & { upsert?: boolean; bypassIndividualUpdate?: boolean };

// The update of the object's refs: the instance and the event inputs it changes, the meta relationships it writes
// (to delete: those of `relationType` to `toIds`, `targets` being the elements they point to)
interface RefUpdate {
  initial: any;
  instance: Record<string, any>;
  updatedInputs: any[];
  relationsToCreate: any[];
  relationsToDelete: { relationType: string; toIds: string[]; targets: any[] }[];
}

interface MultipleRefChange {
  key: string;
  relationType: string;
  refs: any[];
  currentObjects: any[];
  currentIds: string[];
}

const DUPLICATE_ERROR = 'This update will produce a duplicate';

// Today's guard: an individual linked to a user is not updated here. True when it read the users (impure answer)
const checkIndividualUpdate = async (context: AuthContext, initial: any, opts: ApplyOptions) => {
  if (initial.entity_type !== ENTITY_TYPE_IDENTITY_INDIVIDUAL || isEmptyField(initial.contact_information) || opts.bypassIndividualUpdate) return false;
  if (await isIndividualAssociatedToUser(context, initial)) {
    throw FunctionalError('Cannot update an individual corresponding to a user', { id: initial.internal_id });
  }
  return true;
};

// Inputs today's update adds by itself: the activation date of a first set of authorized members, and what a
// vulnerability derives from its CVSS inputs
const addImpliedInputs = (initial: any, updates: any[]) => {
  const hasActivationDate = schemaAttributesDefinition.getAttribute(initial.entity_type, authorizedMembersActivationDate.name);
  const hasNoMembers = !initial.restricted_members || initial.restricted_members.length === 0;
  const setsMembers = updates.some((input) => input.key === authorizedMembers.name && input.value?.length > 0);
  if (hasActivationDate && hasNoMembers && setsMembers) {
    updates.push({ key: authorizedMembersActivationDate.name, value: [now()] });
  }
  if (initial.entity_type === ENTITY_TYPE_VULNERABILITY) {
    const vulnerabilitiesUpdates = generateVulnerabilitiesUpdates(initial, updates);
    if (vulnerabilitiesUpdates.length > 0) updates.push(...vulnerabilitiesUpdates);
  }
};

const requiredAccessOperation = (updates: any[]) => {
  if (updates.some((input) => input.key === 'authorized_authorities')) return AccessOperation.MANAGE_AUTHORITIES_ACCESS;
  if (updates.some((input) => input.key === authorizedMembers.name)) return AccessOperation.MANAGE_ACCESS;
  return AccessOperation.EDIT;
};

// 01. Aliases must not belong to another object (identity index instead of a search). True when it read the index
const checkAliasesNotTaken = async (initial: any, attributeInputs: any[]) => {
  if (!isStixObjectAliased(initial.entity_type)) return false;
  const aliasedInputs = attributeInputs.filter((input) => input.key === 'aliases' || input.key === 'x_opencti_aliases');
  if (aliasedInputs.length === 0) return false;
  const aliases = R.uniq(aliasedInputs.map((input) => input.value).flat().filter((alias: any) => isNotEmptyField(alias)).map((alias: string) => alias.trim()));
  const { live } = await liveOwners(generateAliasesId(aliases, initial));
  const others = live.filter((owner) => owner.owner_id !== initial.internal_id && owner.owner_type === initial.entity_type);
  if (others.length > 0) {
    throw FunctionalError(DUPLICATE_ERROR, { id: initial.internal_id, type: initial.entity_type, existingIds: others.map((owner) => owner.owner_id) });
  }
  return true;
};

// 02. A change of standard id must not land on another object (observables are merged, as today).
// Returns the new standard id when the update moves the object to one it does not hold yet, null otherwise
const checkStandardIdChange = async (initial: any, updated: any, keys: string[]): Promise<string | null> => {
  if (!isFieldContributingToStandardId(initial, keys)) return null;
  const targetStandardId = generateStandardId(initial.entity_type, updated);
  const otherIds = [...(initial[IDS_STIX] ?? []), ...(initial.i_aliases_ids ?? [])];
  if (targetStandardId === initial.standard_id || otherIds.includes(targetStandardId)) return null;
  const { live } = await liveOwners([targetStandardId]);
  const others = live.filter((owner) => owner.owner_id !== initial.internal_id);
  if (others.length === 0) return targetStandardId;
  if (!isStixCyberObservable(initial.entity_type)) {
    throw FunctionalError(DUPLICATE_ERROR, { id: initial.id, type: initial.entity_type, existingIds: others.map((owner) => owner.owner_id) });
  }
  const winner: Owner = {
    key: '', state: 'live', owner_id: initial.internal_id, owner_index: initial._index, owner_type: initial.entity_type, owner_standard_id: initial.standard_id,
  };
  await enqueue(others.map((loser) => ({ kind: 'reconcile', loser, winner } as Task)));
  return targetStandardId;
};

// A single ref (created by, ...): the new target replaces the current one, an empty value removes it
const applySingleRef = (update: RefUpdate, key: string, relationType: string, value: any) => {
  const { instance } = update;
  const currentValue = instance[key];
  const newTarget = R.head(value as any[]) as any;
  if (currentValue?.id === newTarget?.internal_id) return;
  if (currentValue?.internal_id) {
    update.relationsToDelete.push({ relationType, toIds: [currentValue.internal_id], targets: [currentValue] });
  }
  if (isNotEmptyField(newTarget)) {
    update.relationsToCreate.push(...buildInnerRelation(update.initial, newTarget, relationType));
    update.updatedInputs.push({ key, value: [newTarget], previous: currentValue ? [currentValue] : currentValue });
    instance[key] = newTarget;
    instance[relationType] = newTarget.internal_id;
  } else if (currentValue) {
    update.updatedInputs.push({ key, value: [null], previous: [currentValue] });
    instance[key] = null;
    instance[relationType] = null;
  }
};

const replaceRefs = (update: RefUpdate, { key, relationType, refs, currentIds, currentObjects }: MultipleRefChange) => {
  const { instance } = update;
  const newTargetsIds = refs.map((ref: any) => ref.internal_id ?? ref.id);
  if (R.symmetricDifference(newTargetsIds, currentIds).length === 0) return;
  if (currentIds.length > 0) update.relationsToDelete.push({ relationType, toIds: currentIds, targets: currentObjects });
  if (refs.length > 0) update.relationsToCreate.push(...buildInnerRelation(update.initial, refs, relationType));
  update.updatedInputs.push({ key, value: refs, previous: instance[key] });
  instance[key] = refs;
  instance[relationType] = newTargetsIds;
};

const addRefs = (update: RefUpdate, { key, relationType, refs, currentIds, currentObjects }: MultipleRefChange) => {
  const { instance } = update;
  const refsToCreate = refs.filter((ref: any) => !currentIds.includes(ref.internal_id));
  if (refsToCreate.length === 0) return;
  update.relationsToCreate.push(...buildInnerRelation(update.initial, refsToCreate, relationType));
  update.updatedInputs.push({ key, value: refsToCreate, operation: UPDATE_OPERATION_ADD, previous: instance[key] });
  instance[key] = R.uniqBy((ref: any) => ref.internal_id, [...currentObjects, ...refsToCreate]);
  instance[relationType] = instance[key].map((ref: any) => ref.internal_id);
};

const removeRefs = (update: RefUpdate, { key, relationType, refs, currentIds, currentObjects }: MultipleRefChange) => {
  const { instance } = update;
  const targetIds = refs.map((ref: any) => ref.internal_id);
  const removing = currentIds.filter((id) => targetIds.includes(id));
  if (removing.length === 0) return;
  const removedTargets = refs.filter((ref: any) => removing.includes(ref.internal_id));
  update.relationsToDelete.push({ relationType, toIds: removing, targets: removedTargets });
  update.updatedInputs.push({ key, value: refs, operation: UPDATE_OPERATION_REMOVE, previous: instance[key] });
  instance[key] = currentObjects.filter((current: any) => !targetIds.includes(current.internal_id));
  instance[relationType] = instance[key].map((ref: any) => ref.internal_id);
};

// A multiple ref (markings, labels, ...): replaced, added to or removed from, as the input's operation says
const applyMultipleRef = async (context: AuthContext, user: AuthUser, settings: any, update: RefUpdate, refInput: any, key: string, relationType: string) => {
  const isUserCanManipulateGrantedRefs = isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && isEnterpriseEditionFromSettings(settings);
  if (relationType === RELATION_GRANTED_TO && !isUserCanManipulateGrantedRefs) throw ForbiddenAccess();
  let { value: refs, operation = UPDATE_OPERATION_REPLACE } = refInput;
  if (relationType === RELATION_OBJECT_MARKING) {
    ({ operation, refs } = await handleMarkingOperations(context, update.initial.objectMarking, refs, operation));
  }
  const change: MultipleRefChange = { key, relationType, refs, currentObjects: update.instance[key] ?? [], currentIds: [].concat(update.initial[relationType] ?? []) };
  if (operation === UPDATE_OPERATION_REPLACE) replaceRefs(update, change);
  else if (operation === UPDATE_OPERATION_ADD) addRefs(update, change);
  else if (operation === UPDATE_OPERATION_REMOVE) removeRefs(update, change);
};

// Refs: current targets are the ids stored on the object itself (no search)
const applyRefInputs = async (context: AuthContext, user: AuthUser, settings: any, update: RefUpdate, refInputs: any[]) => {
  const entityType = update.instance.entity_type;
  for (const refInput of refInputs) {
    const key = schemaRelationsRefDefinition.convertStixNameToInputName(entityType, refInput.key) || refInput.key;
    const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, key);
    if (!relationRef) throw FunctionalError('Cant find updated instance relation ref from key');
    if (relationRef.multiple) {
      await applyMultipleRef(context, user, settings, update, refInput, key, relationRef.databaseName);
    } else {
      applySingleRef(update, key, relationRef.databaseName, refInput.value);
    }
  }
};

const changedRelationTypes = (update: RefUpdate) => [
  ...update.relationsToCreate.map((relation) => relation.relationship_type as string),
  ...update.relationsToDelete.map((removal) => removal.relationType),
];

// i_attributes, as today: when, by whom and with which confidence each changed attribute or ref was last set
const trackImpactedAttributes = (context: AuthContext, user: AuthUser, update: RefUpdate, impactedInputs: any[]) => {
  const { initial, instance } = update;
  const changedRefKeys = changedRelationTypes(update)
    .map((relationType) => schemaRelationsRefDefinition.convertDatabaseNameToInputName(instance.entity_type, relationType))
    .filter(Boolean) as string[];
  const impactedKeys: string[] = [...impactedInputs.map((input: any) => input.key), ...changedRefKeys];
  const preventAttributeFollow = [updatedAt.name, modified.name, iAliasedIds.name];
  const uniqImpactKeys = R.uniq(impactedKeys.filter((key) => !preventAttributeFollow.includes(key)));
  if (uniqImpactKeys.length === 0) return;
  const updatePatch = mergeInstanceWithInputs(initial, impactedInputs);
  const { confidenceLevelToApply } = controlUpsertInputWithUserConfidence(user, updatePatch as any, initial);
  const attributesMap = new Map((initial.i_attributes ?? []).map((attribute: any) => [attribute.name, attribute]));
  uniqImpactKeys.forEach((uniqImpactKey) => {
    attributesMap.set(uniqImpactKey, {
      name: uniqImpactKey,
      updated_at: context?.eventId ? computeDateFromEventId(context.eventId) : now(),
      confidence: confidenceLevelToApply,
      user_id: user.internal_id,
    });
  });
  impactedInputs.push({ key: iAttributes.name, value: Array.from(attributesMap.values()) });
};

// The full document at the version the merge read, when the merge read it without its relationship lists.
// Undefined when it moved since: the merge is computed again
const readFullDocument = async (raw: RawDoc) => {
  if (!raw.partial) return raw;
  const full = (await mgetRaw([{ index: raw._index, id: raw._id }])).get(raw._id);
  if (!full || full._seq_no !== raw._seq_no || full._primary_term !== raw._primary_term) return undefined;
  return full;
};

// The new version: attributes as elUpdateElement stores them (replace, null removes), refs as rel_* lists
const buildNewSource = async (full: RawDoc, update: RefUpdate, impactedInputs: any[]) => {
  const { initial, instance } = update;
  const source = structuredClone(full._source);
  if (impactedInputs.length > 0) {
    const esData: any = await prepareElementForIndexing(partialInstanceWithInputs(instance, impactedInputs));
    Object.entries(R.omit(['representative', '_id', '_index'], esData)).forEach(([field, value]) => {
      if (value === undefined || value === null) delete source[field];
      else source[field] = value;
    });
  }
  R.uniq(changedRelationTypes(update)).forEach((relationType) => {
    // Only the side that lists the relationship stores it; the other end's type from a created relationship or a removed target
    const created = update.relationsToCreate.find((relation) => relation.relationship_type === relationType);
    const sample = created ?? update.relationsToDelete.find((removal) => removal.relationType === relationType)?.targets[0];
    const toType = sample?.to?.entity_type ?? sample?.entity_type;
    if (toType && !isImpactedTypeAndSide(relationType, initial.entity_type, toType, ROLE_FROM)) return;
    const value = instance[relationType];
    const ids = value === null || value === undefined ? [] : [].concat(value);
    const field = buildRefRelationKey(relationType);
    if (ids.length === 0) delete source[field];
    else source[field] = ids;
  });
  return source;
};

// Written only on the version the merge read: false when someone wrote in between
const writeOnReadVersion = async (raw: RawDoc, source: Record<string, any>, opts: WriteOptions) => {
  const response: any = await elRawBulk(lockfreeContext, {
    refresh: opts.waitForSearch ? 'wait_for' : false,
    body: [{ index: { _index: raw._index, _id: raw._id, if_seq_no: raw._seq_no, if_primary_term: raw._primary_term } }, source],
  });
  const item = response.items[0].index;
  if (item.status === 409) return false;
  if (item.status >= 300) throw new Error(`Update failed: ${JSON.stringify(item.error)}`);
  return true;
};

const removedRefTasks = (initial: any, relationsToDelete: RefUpdate['relationsToDelete']): Task[] => relationsToDelete.flatMap((removal) => removal.targets
  .filter(Boolean)
  .filter((target: any) => isImpactedTypeAndSide(removal.relationType, initial.entity_type, target.entity_type, ROLE_TO))
  .map((target: any): EndpointTask => ({
    kind: 'endpoint',
    op: 'remove',
    endpoint: target.internal_id,
    index: target._index,
    type: target.entity_type,
    relation_type: removal.relationType,
    other: initial.internal_id,
    side: 'to',
  })));

const writeRefRelations = async (update: RefUpdate, counters: Counters, opts: WriteOptions) => {
  const { initial } = update;
  for (const removal of update.relationsToDelete) {
    await deleteMetaRelations(initial.internal_id, removal.relationType, removal.toIds);
    add(counters, 'meta_deleted', removal.toIds.length);
  }
  const removedTasks = removedRefTasks(initial, update.relationsToDelete);
  const metas = withMetaIds(update.relationsToCreate);
  const statuses = await bulkCreateDocs(await Promise.all(metas.map((meta) => prepareIndexingElement(R.omit(['i_raw'], meta)))), opts);
  add(counters, 'meta_created', statuses.filter((status: number) => status === 201).length);
  await enqueue([...removedTasks, ...metaTargetTasks(metas, 'add')]);
};

const applyUpdate = async (
  context: AuthContext, user: AuthUser, initial: any, raw: RawDoc, inputs: any[], counters: Counters, opts: ApplyOptions,
): Promise<Applied> => {
  const updates = Array.isArray(inputs) ? [...inputs] : [inputs];
  const settings = await getEntityFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let pure = true;
  if (await checkIndividualUpdate(context, initial, opts)) pure = false;
  if (updates.length === 0) return { status: 'unchanged', element: initial, pure };
  addImpliedInputs(initial, updates);
  if (!validateUserAccessOperation(user, initial, requiredAccessOperation(updates), null)) throw ForbiddenAccess();
  const markingIds = (initial.objectMarking ?? []).map((marking: any) => marking.internal_id);
  await rewriteEmbeddedDataUriImagesInUpdateInputs(context, user, updates, {
    entityType: initial.entity_type, entityId: initial.internal_id, entity: initial, fileMarkings: markingIds,
  });
  const refKeys = [...schemaRelationsRefDefinition.getStixNames(initial.entity_type), ...schemaRelationsRefDefinition.getInputNames(initial.entity_type)];
  const refInputs = updates.filter((input) => refKeys.includes(input.key));
  const attributeInputs = updates.filter((input) => !refKeys.includes(input.key));
  const updated = mergeInstanceWithUpdateInputs(initial, updates);
  // Identity checks: they read other objects' keys, so their answer is not pure
  if (await checkAliasesNotTaken(initial, attributeInputs)) pure = false;
  const newStandardIdKey = await checkStandardIdChange(initial, updated, attributeInputs.map((input) => input.key));
  if (newStandardIdKey !== null) pure = false;
  // Attributes, then refs, on the instance as updateAttributeRaw leaves it
  const { updatedInstance, impactedInputs, updatedInputs } = await updateAttributeRaw(context, user, initial, attributeInputs, { upsert: opts.upsert ?? false });
  if (isStixCyberObservable(updatedInstance.entity_type) && checkObservableSyntax(updatedInstance.entity_type, updatedInstance) !== true) {
    throw FunctionalError('Observable of is not correctly formatted', { id: initial.internal_id, type: initial.entity_type });
  }
  const update: RefUpdate = { initial, instance: updatedInstance, updatedInputs, relationsToCreate: [], relationsToDelete: [] };
  await applyRefInputs(context, user, settings, update, refInputs);
  trackImpactedAttributes(context, user, update, impactedInputs);
  const isRefUpdate = update.relationsToCreate.length > 0 || update.relationsToDelete.length > 0;
  if (updatedInputs.length === 0 && impactedInputs.length === 0 && !isRefUpdate) {
    return { status: 'unchanged', element: initial, pure };
  }
  // The version-checked write: on a conflict the caller reads the newer version and computes again
  const full = await readFullDocument(raw);
  if (!full) return { status: 'conflict' };
  const source = await buildNewSource(full, update, impactedInputs);
  if (!(await writeOnReadVersion(raw, source, opts))) return { status: 'conflict' };
  if (source.name && raw._source.name !== source.name && updatedInstance.base_type === 'ENTITY') {
    await elUpdateConnectionsOfElement(initial.internal_id, { name: source.name });
  }
  await writeRefRelations(update, counters, opts);
  const objectsRefRelationships = update.relationsToCreate.filter((relation) => relation.relationship_type === RELATION_OBJECT);
  if (objectsRefRelationships.length > 0) await createContainerSharingTask(context, ACTION_TYPE_SHARE, initial, objectsRefRelationships);
  // Keys of the object after the change (new aliases, STIX ids, standard id) point to it
  const newKeys = getInstanceIds(updatedInstance).concat(newStandardIdKey ? [newStandardIdKey] : []);
  const keyOwner = { owner_id: initial.internal_id, owner_index: raw._index, owner_type: initial.entity_type, owner_standard_id: updatedInstance.standard_id };
  await setKeys(newKeys.map((key: string) => ({ key, owner: keyOwner })));
  if (updatedInputs.some((input: any) => MARKDOWN_FIELD_KEY_SET.has(input.key))) {
    const removedPaths = findRemovedEmbeddedStoragePathsFromMarkdownFields(initial, updated, { entityType: initial.entity_type, entityId: initial.internal_id });
    for (const storagePath of removedPaths) {
      await deleteFile(context, user, storagePath, { forceDelete: true })
        .catch((err: any) => logApp.warn('[LOCKFREE] Unable to cleanup removed embedded image', { storagePath, cause: err }));
    }
  }
  if (updatedInputs.length === 0) return { status: 'updated', element: updatedInstance };
  const changes = await buildChanges(context, user, updatedInstance.entity_type, updatedInputs);
  const relatedRestrictions = extractObjectsRestrictionsFromInputs(updatedInputs, initial.entity_type);
  const { pir_ids } = extractObjectsPirsFromInputs(updatedInputs, initial.entity_type);
  const event = await storeUpdateEvent(context, user, initial, updatedInstance as any, changes, { related_restrictions: relatedRestrictions, pir_ids } as any);
  add(counters, 'events_update');
  // A security coverage follows the refs of the object it covers
  if (isRefUpdate && updatedInstance[RELATION_COVERED] && updatedInstance.entity_type !== ENTITY_TYPE_SECURITY_COVERAGE) {
    const { element: securityCoverage } = await updateAttribute(context, user, updatedInstance[RELATION_COVERED], ENTITY_TYPE_SECURITY_COVERAGE, [{ key: 'modified', value: [now()] }], { noEnrich: true });
    await triggerEntityUpdateAutoEnrichment(context, user, securityCoverage as any);
  }
  const workflowStatusChanged = updatedInputs.some((input: any) => input.key === 'x_opencti_workflow_id');
  return { status: 'updated', element: updatedInstance, event, workflowStatusChanged };
};

// ---------------------------------------------------------------------------------------------------------------
// upsertElement, lock-free
// ---------------------------------------------------------------------------------------------------------------
const MAX_MERGE_ATTEMPTS = 50;
const DECAY_FIELDS = ['decay_next_reaction_date', 'decay_base_score', 'decay_base_score_date', 'decay_applied_rule', 'decay_history'];

// As today: an object excluded from decay keeps its decay state
const dropExcludedDecay = (patch: Record<string, any>, element: any) => {
  if (!element.decay_exclusion_applied_rule) return;
  if (patch.decay_applied_rule) DECAY_FIELDS.forEach((field) => delete patch[field]);
  delete patch.decay_exclusion_applied_rule;
};

const unchangedResult = (element: any, raw: RawDoc, pure: boolean) => ({ status: 'unchanged' as const, element, event: null, version: versionOf(raw), pure });

export const upsertLockFree = async (
  context: AuthContext,
  user: AuthUser,
  target: { index: string; id: string },
  type: string,
  basePatch: Record<string, any>,
  counters: Counters,
  opts: WriteOptions & Record<string, any> = {},
  preloaded?: { raw: RawDoc; withRefs: any }, // the target as the chunk read it, for the first attempt
) => {
  const patch = { ...basePatch };
  let imagesRewritten = false;
  for (let attempt = 0; attempt < MAX_MERGE_ATTEMPTS; attempt += 1) {
    const read = attempt === 0 ? preloaded : undefined;
    const raw = read?.raw ?? (await mgetRaw([target], { withoutLists: true })).get(target.id);
    if (!raw) return { status: 'missing' as const };
    const resolvedElement = read?.withRefs ?? await loadWithRefs(context, user, (await toElements([raw]))[0]);
    const attemptPatch: Record<string, any> = { ...patch };
    dropExcludedDecay(attemptPatch, resolvedElement);
    // Embedded images become files once, on the first attempt; later attempts reuse the rewritten patch
    if (!imagesRewritten) {
      await rewriteEmbeddedDataUriImagesInDescriptions(context, user, attemptPatch, {
        entityType: type, entityId: resolvedElement.internal_id, entity: resolvedElement, fileMarkings: (resolvedElement.objectMarking ?? []).map((m: any) => m.internal_id),
      });
      Object.assign(patch, attemptPatch);
      imagesRewritten = true;
    }
    const confidenceForUpsert = controlUpsertInputWithUserConfidence(user, attemptPatch as any, resolvedElement);
    const updatePatch = buildUpdatePatchForUpsert(user, resolvedElement, type, attemptPatch, confidenceForUpsert);
    if (updatePatch.upsertOperations?.length > 0) {
      updatePatch.upsertOperations = await resolveRefsForInputs(context, user, type, updatePatch.upsertOperations);
    }
    const settings = await getEntityFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const inputs = await generateInputsForUpsert(context, user, resolvedElement, type, updatePatch, confidenceForUpsert, isEnterpriseEditionFromSettings(settings));
    if (inputs.length === 0) return unchangedResult(resolvedElement, raw, true);
    const applied = await applyUpdate(context, user, resolvedElement, raw, inputs, counters, { ...opts, upsert: context.synchronizedUpsert !== true });
    if (applied.status === 'conflict') {
      add(counters, 'occ_retries');
      continue;
    }
    if (applied.status === 'unchanged') return unchangedResult(applied.element, raw, applied.pure === true);
    return { ...applied, status: 'merged' as const };
  }
  throw new Error(`Merge of ${target.id} kept conflicting`);
};
