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
import { now } from '../../utils/format';
import { computeDateFromEventId } from '../../utils/format';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../../database/utils';
import { deterministicId, setKeys } from './identity';
import { liveOwners, loadWithRefs, mgetRaw, type RawDoc, toElements } from './load';
import { enqueue, type Task } from './queue';
import { versionOf } from './unchanged';
import { add, type Counters } from './store';

export interface WriteOptions {
  waitForSearch?: boolean; // each write searchable when the call returns (refresh wait_for), as today
  missingEnds?: 'pending' | 'error'; // a relationship whose end is missing waits (default) or fails as today
}

export const metaId = (relationType: string, fromId: string, toId: string) => deterministicId(`${relationType}|${fromId}|${toId}`);

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
  const found: any = await elRawSearch(lockfreeContext, SYSTEM_USER, null, {
    index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    size: 1000,
    body: {
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': relationType } },
            { nested: { path: 'connections', query: { bool: { filter: [{ term: { 'connections.internal_id.keyword': fromId } }, { wildcard: { 'connections.role.keyword': '*_from' } }] } } } },
            { nested: { path: 'connections', query: { bool: { filter: [{ terms: { 'connections.internal_id.keyword': missing } }, { wildcard: { 'connections.role.keyword': '*_to' } }] } } } },
          ],
        },
      },
    },
  });
  const hits = found.hits.hits;
  if (hits.length > 0) await elRawBulk(lockfreeContext, { refresh: false, body: hits.map((h: any) => ({ delete: { _index: h._index, _id: h._id } })) });
};

// One bulk is indexed by one write thread per shard: a large one goes as several bulks at once, so Elasticsearch
// indexes them in parallel. Statuses come back in the order of the documents.
const BULK_SLICE = 500;
const BULK_SLICES_AT_ONCE = 4;
export const bulkCreateDocs = async (docs: any[], opts: WriteOptions) => {
  if (docs.length === 0) return [];
  const slices = R.splitEvery(Math.max(BULK_SLICE, Math.ceil(docs.length / BULK_SLICES_AT_ONCE)), docs);
  const statuses = await Promise.all(slices.map(async (slice) => {
    const body = slice.flatMap((doc) => [{ create: { _index: doc._index, _id: doc.internal_id } }, R.dissoc('_index', doc)]);
    const response: any = await elRawBulk(lockfreeContext, { refresh: opts.waitForSearch ? 'wait_for' : false, body });
    return response.items.map((item: any) => {
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

const applyUpdate = async (
  context: AuthContext, user: AuthUser, initial: any, raw: RawDoc, inputs: any[], counters: Counters, opts: WriteOptions & Record<string, any>,
): Promise<Applied> => {
  const updates = Array.isArray(inputs) ? [...inputs] : [inputs];
  const settings = await getEntityFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let pure = true;
  if (initial.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL && !isEmptyField(initial.contact_information) && !opts.bypassIndividualUpdate) {
    pure = false;
    if (await isIndividualAssociatedToUser(context, initial)) {
      throw FunctionalError('Cannot update an individual corresponding to a user', { id: initial.internal_id });
    }
  }
  if (updates.length === 0) return { status: 'unchanged', element: initial, pure };
  let accessOperation = AccessOperation.EDIT;
  if (updates.some((e) => e.key === authorizedMembers.name)) {
    accessOperation = AccessOperation.MANAGE_ACCESS;
    if (schemaAttributesDefinition.getAttribute(initial.entity_type, authorizedMembersActivationDate.name)
      && (!initial.restricted_members || initial.restricted_members.length === 0)
      && updates.some((e) => e.key === authorizedMembers.name && e.value?.length > 0)) {
      updates.push({ key: authorizedMembersActivationDate.name, value: [now()] });
    }
  }
  if (initial.entity_type === ENTITY_TYPE_VULNERABILITY) {
    const vulnerabilitiesUpdates = generateVulnerabilitiesUpdates(initial, updates);
    if (vulnerabilitiesUpdates.length > 0) updates.push(...vulnerabilitiesUpdates);
  }
  if (updates.some((e) => e.key === 'authorized_authorities')) accessOperation = AccessOperation.MANAGE_AUTHORITIES_ACCESS;
  if (!validateUserAccessOperation(user, initial, accessOperation, null)) throw ForbiddenAccess();
  const markingIds = (initial.objectMarking ?? []).map((m: any) => m.internal_id);
  await rewriteEmbeddedDataUriImagesInUpdateInputs(context, user, updates, {
    entityType: initial.entity_type, entityId: initial.internal_id, entity: initial, fileMarkings: markingIds,
  });
  const metaKeys = [...schemaRelationsRefDefinition.getStixNames(initial.entity_type), ...schemaRelationsRefDefinition.getInputNames(initial.entity_type)];
  const meta = updates.filter((e) => metaKeys.includes(e.key));
  const attributes = updates.filter((e) => !metaKeys.includes(e.key));
  const updated = mergeInstanceWithUpdateInputs(initial, updates);
  const keys = attributes.map((t) => t.key);
  // 01. Aliases must not belong to another object (identity index instead of a search)
  if (isStixObjectAliased(initial.entity_type)) {
    const aliasedInputs = attributes.filter((input) => input.key === 'aliases' || input.key === 'x_opencti_aliases');
    if (aliasedInputs.length > 0) {
      pure = false;
      const aliases = R.uniq(aliasedInputs.map((a) => a.value).flat().filter((a: any) => isNotEmptyField(a)).map((a: string) => a.trim()));
      const aliasesIds = generateAliasesId(aliases, initial);
      const { live } = await liveOwners(aliasesIds);
      const others = live.filter((o) => o.owner_id !== initial.internal_id && o.owner_type === initial.entity_type);
      if (others.length > 0) {
        throw FunctionalError('This update will produce a duplicate', { id: initial.internal_id, type: initial.entity_type, existingIds: others.map((o) => o.owner_id) });
      }
    }
  }
  // 02. A change of standard id must not land on another object (observables are merged, as today)
  let newStandardIdKey: string | null = null;
  if (isFieldContributingToStandardId(initial, keys)) {
    const targetStandardId = generateStandardId(initial.entity_type, updated);
    const otherIds = [...(initial[IDS_STIX] ?? []), ...(initial.i_aliases_ids ?? [])];
    if (targetStandardId !== initial.standard_id && !otherIds.includes(targetStandardId)) {
      pure = false;
      const { live } = await liveOwners([targetStandardId]);
      const others = live.filter((o) => o.owner_id !== initial.internal_id);
      if (others.length > 0) {
        if (isStixCyberObservable(initial.entity_type)) {
          await enqueue(others.map((o) => ({ kind: 'reconcile', loser: o, winner: { key: '', state: 'live', owner_id: initial.internal_id, owner_index: initial._index, owner_type: initial.entity_type, owner_standard_id: initial.standard_id } } as Task)));
        } else {
          throw FunctionalError('This update will produce a duplicate', { id: initial.id, type: initial.entity_type, existingIds: others.map((o) => o.owner_id) });
        }
      }
      newStandardIdKey = targetStandardId;
    }
  }
  const data = await updateAttributeRaw(context, user, initial, attributes, { upsert: opts.upsert ?? false });
  const { updatedInstance, impactedInputs, updatedInputs } = data;
  if (isStixCyberObservable(updatedInstance.entity_type)) {
    if (checkObservableSyntax(updatedInstance.entity_type, updatedInstance) !== true) {
      throw FunctionalError('Observable of is not correctly formatted', { id: initial.internal_id, type: initial.entity_type });
    }
  }
  // Refs: current targets are the ids stored on the object itself (no search)
  const relationsToCreate: any[] = [];
  const relationsToDelete: { relationType: string; toIds: string[]; targets: any[] }[] = [];
  for (const metaInput of meta) {
    const key = schemaRelationsRefDefinition.convertStixNameToInputName(updatedInstance.entity_type, metaInput.key) || metaInput.key;
    const relDef = schemaRelationsRefDefinition.getRelationRef(updatedInstance.entity_type, key);
    if (!relDef) throw FunctionalError('Cant find updated instance relation ref from key');
    const relType = relDef.databaseName;
    if (!relDef.multiple) {
      const currentValue = updatedInstance[key];
      const targetCreated = R.head(metaInput.value as any[]) as any;
      if (currentValue?.id !== targetCreated?.internal_id) {
        if (currentValue?.internal_id) relationsToDelete.push({ relationType: relType, toIds: [currentValue.internal_id], targets: [currentValue] });
        if (isNotEmptyField(targetCreated)) {
          relationsToCreate.push(...buildInnerRelation(initial, targetCreated, relType));
          updatedInputs.push({ key, value: [targetCreated], previous: currentValue ? [currentValue] : currentValue });
          updatedInstance[key] = targetCreated;
          updatedInstance[relType] = targetCreated.internal_id;
        } else if (currentValue) {
          updatedInputs.push({ key, value: [null], previous: [currentValue] });
          updatedInstance[key] = null;
          updatedInstance[relType] = null;
        }
      }
    } else {
      const isUserCanManipulateGrantedRefs = isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && isEnterpriseEditionFromSettings(settings);
      if (relType === RELATION_GRANTED_TO && !isUserCanManipulateGrantedRefs) throw ForbiddenAccess();
      let { value: refs, operation = UPDATE_OPERATION_REPLACE } = metaInput;
      if (relType === RELATION_OBJECT_MARKING) {
        const markingsCleaned = await handleMarkingOperations(context, initial.objectMarking, refs, operation);
        ({ operation, refs } = { operation: markingsCleaned.operation, refs: markingsCleaned.refs });
      }
      const currentObjects: any[] = updatedInstance[key] ?? [];
      const currentIds: string[] = [].concat(initial[relType] ?? []);
      if (operation === UPDATE_OPERATION_REPLACE) {
        const newTargetsIds = refs.map((n: any) => n.internal_id ?? n.id);
        if (R.symmetricDifference(newTargetsIds, currentIds).length > 0) {
          if (currentIds.length > 0) relationsToDelete.push({ relationType: relType, toIds: currentIds, targets: currentObjects });
          if (refs.length > 0) relationsToCreate.push(...buildInnerRelation(initial, refs, relType));
          updatedInputs.push({ key, value: refs, previous: updatedInstance[key] });
          updatedInstance[key] = refs;
          updatedInstance[relType] = newTargetsIds;
        }
      }
      if (operation === UPDATE_OPERATION_ADD) {
        const refsToCreate = refs.filter((r: any) => !currentIds.includes(r.internal_id));
        if (refsToCreate.length > 0) {
          relationsToCreate.push(...buildInnerRelation(initial, refsToCreate, relType));
          updatedInputs.push({ key, value: refsToCreate, operation, previous: updatedInstance[key] });
          updatedInstance[key] = R.uniqBy((r: any) => r.internal_id, [...currentObjects, ...refsToCreate]);
          updatedInstance[relType] = updatedInstance[key].map((u: any) => u.internal_id);
        }
      }
      if (operation === UPDATE_OPERATION_REMOVE) {
        const targetIds = refs.map((t: any) => t.internal_id);
        const removing = currentIds.filter((id) => targetIds.includes(id));
        if (removing.length > 0) {
          relationsToDelete.push({ relationType: relType, toIds: removing, targets: refs.filter((r: any) => removing.includes(r.internal_id)) });
          updatedInputs.push({ key, value: refs, operation, previous: updatedInstance[key] });
          updatedInstance[key] = currentObjects.filter((c: any) => !targetIds.includes(c.internal_id));
          updatedInstance[relType] = updatedInstance[key].map((u: any) => u.internal_id);
        }
      }
    }
  }
  // i_attributes, as today
  const impactedKeys: string[] = impactedInputs.map((input: any) => input.key);
  const metaKeysChanged = [...relationsToCreate.map((r) => r.relationship_type), ...relationsToDelete.map((r) => r.relationType)]
    .map((relType) => schemaRelationsRefDefinition.convertDatabaseNameToInputName(updatedInstance.entity_type, relType))
    .filter(Boolean) as string[];
  impactedKeys.push(...metaKeysChanged);
  const preventAttributeFollow = [updatedAt.name, modified.name, iAliasedIds.name];
  const uniqImpactKeys = R.uniq(impactedKeys.filter((key) => !preventAttributeFollow.includes(key)));
  if (uniqImpactKeys.length > 0) {
    const updatePatch = mergeInstanceWithInputs(initial, impactedInputs);
    const { confidenceLevelToApply } = controlUpsertInputWithUserConfidence(user, updatePatch as any, initial);
    const attributesMap = new Map((initial.i_attributes ?? []).map((obj: any) => [obj.name, obj]));
    uniqImpactKeys.forEach((uniqImpactKey) => {
      attributesMap.set(uniqImpactKey, {
        name: uniqImpactKey,
        updated_at: context?.eventId ? computeDateFromEventId(context.eventId) : now(),
        confidence: confidenceLevelToApply,
        user_id: user.internal_id,
      });
    });
    impactedInputs.push({ key: iAttributes.name, value: Array.from(attributesMap.values()) });
  }
  if (updatedInputs.length === 0 && impactedInputs.length === 0 && relationsToCreate.length === 0 && relationsToDelete.length === 0) {
    return { status: 'unchanged', element: initial, pure };
  }
  // The new version: attributes as elUpdateElement stores them (replace, null removes), refs as rel_* lists. Built on
  // the full document, read now if the merge read it without its relationship lists, at the same version
  let full = raw;
  if (raw.partial) {
    full = (await mgetRaw([{ index: raw._index, id: raw._id }])).get(raw._id) as RawDoc;
    if (!full || full._seq_no !== raw._seq_no || full._primary_term !== raw._primary_term) return { status: 'conflict' };
  }
  const source = structuredClone(full._source);
  if (impactedInputs.length > 0) {
    const updateAsInstance = partialInstanceWithInputs(updatedInstance, impactedInputs);
    const esData: any = await prepareElementForIndexing(updateAsInstance);
    Object.entries(R.omit(['representative', '_id', '_index'], esData)).forEach(([k, v]) => {
      if (v === undefined || v === null) delete source[k];
      else source[k] = v;
    });
  }
  const touchedRelTypes = R.uniq([...relationsToCreate.map((r) => r.relationship_type), ...relationsToDelete.map((r) => r.relationType)]);
  touchedRelTypes.forEach((relType) => {
    const value = updatedInstance[relType];
    const ids = value === null || value === undefined ? [] : [].concat(value);
    const sample = relationsToCreate.find((r) => r.relationship_type === relType) ?? relationsToDelete.find((r) => r.relationType === relType)?.targets[0];
    const toType = sample?.to?.entity_type ?? sample?.entity_type;
    if (toType && !isImpactedTypeAndSide(relType, initial.entity_type, toType, ROLE_FROM)) return;
    const field = buildRefRelationKey(relType);
    if (ids.length === 0) delete source[field];
    else source[field] = ids;
  });
  const response: any = await elRawBulk(lockfreeContext, {
    refresh: opts.waitForSearch ? 'wait_for' : false,
    body: [{ index: { _index: raw._index, _id: raw._id, if_seq_no: raw._seq_no, if_primary_term: raw._primary_term } }, source],
  });
  const item = response.items[0].index;
  if (item.status === 409) return { status: 'conflict' };
  if (item.status >= 300) throw new Error(`Update failed: ${JSON.stringify(item.error)}`);
  // After the write: name in relationships, refs, sharing, keys, cleanup, event
  if (source.name && raw._source.name !== source.name && updatedInstance.base_type === 'ENTITY') {
    await elUpdateConnectionsOfElement(initial.internal_id, { name: source.name });
  }
  for (const removal of relationsToDelete) {
    await deleteMetaRelations(initial.internal_id, removal.relationType, removal.toIds);
    add(counters, 'meta_deleted', removal.toIds.length);
  }
  const removedTasks: Task[] = relationsToDelete.flatMap((removal) => removal.targets.filter(Boolean)
    .filter((t: any) => isImpactedTypeAndSide(removal.relationType, initial.entity_type, t.entity_type, ROLE_TO))
    .map((t: any) => ({ kind: 'endpoint', op: 'remove', endpoint: t.internal_id, index: t._index, type: t.entity_type, relation_type: removal.relationType, other: initial.internal_id, side: 'to' } as Task)));
  const metas = withMetaIds(relationsToCreate);
  const statuses = await bulkCreateDocs(await Promise.all(metas.map((m) => prepareIndexingElement(R.omit(['i_raw'], m)))), opts);
  add(counters, 'meta_created', statuses.filter((s: number) => s === 201).length);
  await enqueue([...removedTasks, ...metaTargetTasks(metas, 'add')]);
  const objectsRefRelationships = relationsToCreate.filter((r) => r.relationship_type === RELATION_OBJECT);
  if (objectsRefRelationships.length > 0) await createContainerSharingTask(context, ACTION_TYPE_SHARE, initial, objectsRefRelationships);
  // Keys of the object after the change (new aliases, STIX ids, standard id) point to it
  const newKeys = getInstanceIds(updatedInstance).concat(newStandardIdKey ? [newStandardIdKey] : []);
  const keyOwner = { owner_id: initial.internal_id, owner_index: raw._index, owner_type: initial.entity_type, owner_standard_id: updatedInstance.standard_id };
  await setKeys(newKeys.map((key: string) => ({ key, owner: keyOwner })));
  if (updatedInputs.some((i: any) => MARKDOWN_FIELD_KEY_SET.has(i.key))) {
    const removedPaths = findRemovedEmbeddedStoragePathsFromMarkdownFields(initial, updated, { entityType: initial.entity_type, entityId: initial.internal_id });
    for (const storagePath of removedPaths) {
      await deleteFile(context, user, storagePath, { forceDelete: true }).catch((err: any) => logApp.warn('[LOCKFREE] Unable to cleanup removed embedded image', { storagePath, cause: err }));
    }
  }
  if (updatedInputs.length === 0) return { status: 'updated', element: updatedInstance };
  const changes = await buildChanges(context, user, updatedInstance.entity_type, updatedInputs);
  const relatedRestrictions = extractObjectsRestrictionsFromInputs(updatedInputs, initial.entity_type);
  const { pir_ids } = extractObjectsPirsFromInputs(updatedInputs, initial.entity_type);
  const event = await storeUpdateEvent(context, user, initial, updatedInstance as any, changes, { related_restrictions: relatedRestrictions, pir_ids } as any);
  add(counters, 'events_update');
  const isRefUpdate = relationsToCreate.length > 0 || relationsToDelete.length > 0;
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
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const read = attempt === 0 ? preloaded : undefined;
    const raw = read?.raw ?? (await mgetRaw([target], { withoutLists: true })).get(target.id);
    if (!raw) return { status: 'missing' as const };
    const resolvedElement = read?.withRefs ?? await loadWithRefs(context, user, (await toElements([raw]))[0]);
    const attemptPatch: Record<string, any> = { ...patch };
    if (resolvedElement.decay_exclusion_applied_rule) {
      if (attemptPatch.decay_applied_rule) {
        ['decay_next_reaction_date', 'decay_base_score', 'decay_base_score_date', 'decay_applied_rule', 'decay_history'].forEach((k) => delete attemptPatch[k]);
      }
      delete attemptPatch.decay_exclusion_applied_rule;
    }
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
    if (inputs.length === 0) return { status: 'unchanged' as const, element: resolvedElement, event: null, version: versionOf(raw), pure: true };
    const applied = await applyUpdate(context, user, resolvedElement, raw, inputs, counters, { ...opts, upsert: context.synchronizedUpsert !== true });
    if (applied.status === 'conflict') {
      add(counters, 'occ_retries');
      continue;
    }
    if (applied.status === 'unchanged') return { status: 'unchanged' as const, element: applied.element, event: null, version: versionOf(raw), pure: applied.pure === true };
    return { ...applied, status: 'merged' as const };
  }
  throw new Error(`Merge of ${target.id} kept conflicting`);
};
