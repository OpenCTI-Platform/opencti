import * as R from 'ramda';
import { isDraftIndex, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS, toBase64 } from './utils';
import { DatabaseError, UnsupportedError } from '../config/errors';
import {
  BULK_TIMEOUT,
  computeDeleteElementsImpacts,
  elBulk,
  elDeleteInstances,
  elFindByIds,
  elRawDeleteByQuery,
  elRawUpdateByQuery,
  elRemoveDraftIdFromElements,
  elRemoveRelationConnection,
  elReplace,
  ES_RETRY_ON_CONFLICT,
  getRelationsToRemove,
  isImpactedRole,
} from './engine';
import {
  DRAFT_OPERATION_CREATE,
  DRAFT_OPERATION_DELETE,
  DRAFT_OPERATION_DELETE_LINKED,
  DRAFT_OPERATION_UPDATE,
  DRAFT_OPERATION_UPDATE_LINKED
} from '../modules/draftWorkspace/draftOperations';
import { SYSTEM_USER } from '../utils/access';
import { isBasicRelationship } from '../schema/stixRelationship';
import { getDraftContext } from '../utils/draftContext';
import { buildReverseUpdateFieldPatch, FILES_UPDATE_KEY } from './draft-utils';
import { storeLoadByIdWithRefs, updateAttributeFromLoadedWithRefs } from './middleware';
import { buildRefRelationKey } from '../schema/general';
import { getFileContent } from './raw-file-storage';
import { loadFile } from './file-storage';
import { EditOperation } from '../generated/graphql';

const completeDeleteElementsFromDraft = async (context, user, elements) => {
  const draftContext = getDraftContext(context, user);
  if (!draftContext) { return; }
  await elDeleteInstances(elements);
  const elementsIds = elements.map((e) => e.internal_id);
  await elRemoveDraftIdFromElements(context, user, draftContext, elementsIds);
};

const isCreateOrDraftDelete = (draftOp) => {
  return draftOp === DRAFT_OPERATION_CREATE || draftOp === DRAFT_OPERATION_DELETE || draftOp === DRAFT_OPERATION_DELETE_LINKED;
};

const elRemoveCreateElementFromDraft = async (context, user, element) => {
  if (element.draft_change?.draft_operation !== DRAFT_OPERATION_CREATE) {
    return;
  }
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, [element]);
  // We get all relations that were created in draft that target this element (should be all of the relations in this case, since element itself was created in draft)
  const draftCreatedRelations = relations.filter((f) => f.draft_change && f.draft_change.draft_operation === DRAFT_OPERATION_CREATE);
  // Add element to relations to get the impacts from if current element is itself a relation
  const relationToRemove = draftCreatedRelations.concat(isBasicRelationship(element.entity_type) ? [element] : []);
  const draftRelationsElementsImpact = await computeDeleteElementsImpacts(relationToRemove, [element.internal_id], relationsToRemoveMap);

  // Clean up all denormalized rel impact of relations deletion, then delete all relations
  // TODO: clean up UPDATE_LINKED impacted elements that no longer need to be in draft => how to know that an update_linked element can be safely removed?
  await elRemoveRelationConnection(context, user, draftRelationsElementsImpact);
  await elDeleteInstances([element, ...draftCreatedRelations]);
};

const elRemoveUpdateElementFromDraft = async (context, user, element) => {
  if (element.draft_change?.draft_operation !== DRAFT_OPERATION_UPDATE) {
    return;
  }

  // apply reverse field patch
  const elementWithRefs = await storeLoadByIdWithRefs(context, user, element.internal_id);
  const reverseUpdateFieldPatch = buildReverseUpdateFieldPatch(element.draft_change.draft_updates_patch);
  await updateAttributeFromLoadedWithRefs(context, user, elementWithRefs, reverseUpdateFieldPatch);
  // TODO: clean up UPDATE_LINKED impacted elements that no longer need to be in draft => how to know that an update_linked element can be safely removed?

  // verify if element can be entirely removed from draft or if it needs to be kept as update_linked
  // We get all relations that were created or deleted/delete_linked in draft that target this element.
  // If there are still some, it means that we need to keep the element as an UPDATE_LINKED
  const { relations } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  const draftCreatedOrDeletedRelations = relations.filter((f) => f.draft_change && isCreateOrDraftDelete(f.draft_change.draft_operation));
  if (draftCreatedOrDeletedRelations.length > 0) {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_UPDATE_LINKED } };
    await elReplace(element._index, element._id, { doc: newDraftChange });
  } else {
    await completeDeleteElementsFromDraft(context, user, [element]);
  }
};

const removeDraftDeleteLinkedRelations = async (context, user, deleteLinkedRelations) => {
  // Reapply denormalized refs on elements impacted with deleteLinked rel removal
  const elementsToUpdate = deleteLinkedRelations.map((deleteLinkedRelToRemove) => {
    const { rel, dep } = deleteLinkedRelToRemove;
    const isFromImpact = rel.fromId === dep.internal_id;
    const isToImpact = rel.toId === dep.internal_id;
    const { entity_type, fromType, fromRole, toType, toRole } = rel;
    if (isFromImpact && !isImpactedRole(entity_type, fromType, toType, fromRole)) {
      return undefined;
    }
    if (isToImpact && !isImpactedRole(entity_type, fromType, toType, toRole)) {
      return undefined;
    }
    const targetId = isFromImpact ? rel.toId : rel.fromId;
    // Create params and scripted update
    const field = buildRefRelationKey(rel.relationship_type);
    let script = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
    script += `ctx._source['${field}'].addAll(params['${field}']);`;
    const source = script;
    const params = { [field]: [targetId] };
    return { ...dep, _id: dep._id, data: { script: { source, params } } };
  }).filter((e) => e);
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    { update: { _index: doc._index, _id: doc._id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
    R.dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([bulkPromise]);
  }

  // After reapplying denormalized refs, we delete relations draft instaces and we remove draftId from live instances
  const deleteLinkedRelationsInstances = deleteLinkedRelations.map((delRel) => delRel.rel);
  await completeDeleteElementsFromDraft(context, user, deleteLinkedRelationsInstances);
};

const elRemoveDeleteElementFromDraft = async (context, user, element) => {
  if (element.draft_change?.draft_operation !== DRAFT_OPERATION_DELETE) {
    return;
  }

  // if current element is a relation, and if from or to are in DRAFT_OPERATION_DELETE, it means the current element needs to be switched to a delete linked
  if (isBasicRelationship(element.entity_type) && (isDraftIndex(element.from?._index) || isDraftIndex(element.to?._index))) {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE_LINKED } };
    await elReplace(element._index, element._id, { doc: newDraftChange });
    return;
  }

  // We get all related relations that are delete_linked
  const { relations } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  const draftDeleteLinkedRelations = relations.filter((f) => isDraftIndex(f._index) && f.draft_change && f.draft_change.draft_operation === DRAFT_OPERATION_DELETE_LINKED);
  const draftDeleteLinkedRelationsIds = draftDeleteLinkedRelations.map((r) => r.internal_id);
  // We get all of those relations dependencies (that are not the current element or the related relations)
  const draftDeleteLinkedRelationsTargetsIds = draftDeleteLinkedRelations.map((r) => {
    const { fromId, toId } = r;
    if (!draftDeleteLinkedRelationsIds.includes(fromId) && fromId !== element.internal_id) {
      return fromId;
    }
    if (!draftDeleteLinkedRelationsIds.includes(toId) && toId !== element.internal_id) {
      return toId;
    }
    return undefined;
  }).filter((i) => i);
  // We resolve all those dependencies
  const draftDeleteDependenciesRaw = await elFindByIds(context, user, draftDeleteLinkedRelationsTargetsIds, { includeDeletedInDraft: true });
  const draftDeleteDependencies = draftDeleteDependenciesRaw.filter((d) => isDraftIndex((d._index)));
  let hasDraftDeletedLinkedRelationsToKeep = false;
  const draftDeletedLinkedRelationsToRemove = [];
  // We distinguish relations that need to be kept (from or to has a DELETE operation) from those that can be reverted in draft
  for (let i = 0; i < draftDeleteLinkedRelations.length; i += 1) {
    const { fromId, toId } = draftDeleteLinkedRelations[i];
    const fromDependency = draftDeleteDependencies.find((e) => e.internal_id === fromId);
    const toDependency = draftDeleteDependencies.find((e) => e.internal_id === toId);
    if (fromDependency) {
      if (fromDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE || fromDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
        hasDraftDeletedLinkedRelationsToKeep = true;
      } else {
        draftDeletedLinkedRelationsToRemove.push({ rel: draftDeleteLinkedRelations[i], dep: fromDependency });
      }
    } else if (toDependency) {
      if (toDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE || toDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
        hasDraftDeletedLinkedRelationsToKeep = true;
      } else {
        draftDeletedLinkedRelationsToRemove.push({ rel: draftDeleteLinkedRelations[i], dep: toDependency });
      }
    }
  }

  // We remove all those draft delete linked relations from draft index, reverting back to live index. We need to reapply denormalized refs on dependencies also
  if (draftDeletedLinkedRelationsToRemove.length > 0) {
    // TODO: clean up UPDATE_LINKED impacted elements that no longer need to be in draft => how to know that an update_linked element can be safely removed?
    await removeDraftDeleteLinkedRelations(context, user, draftDeletedLinkedRelationsToRemove);
  }

  if (!hasDraftDeletedLinkedRelationsToKeep) {
    // TODO: reapply denorm ref if element is a rel
    // TODO: clean up UPDATE_LINKED impacted element that no longer need to be in draft => how to know that an update_linked element can be safely removed?
    await completeDeleteElementsFromDraft(context, user, [element]);
  } else {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_UPDATE_LINKED } };
    await elReplace(element._index, element._id, { doc: newDraftChange });
  }
};

export const elRemoveElementFromDraft = async (context, user, element) => {
  if (!isDraftIndex(element._index) || !element.draft_change) {
    return element;
  }

  switch (element.draft_change.draft_operation) {
    case DRAFT_OPERATION_CREATE:
      return elRemoveCreateElementFromDraft(context, user, element);
    case DRAFT_OPERATION_UPDATE:
      return elRemoveUpdateElementFromDraft(context, user, element);
    case DRAFT_OPERATION_DELETE:
      return elRemoveDeleteElementFromDraft(context, user, element);
    case DRAFT_OPERATION_UPDATE_LINKED:
    case DRAFT_OPERATION_DELETE_LINKED:
      throw UnsupportedError('Cannot remove linked elements from draft', { id: element.id });
    default:
      throw UnsupportedError('Draft operation not recognized', { id: element.id, operation: element.draft_change.draft_operation });
  }
};

export const elDeleteDraftElements = async (context, user, draftId) => {
  return elRawDeleteByQuery({
    index: READ_INDEX_DRAFT_OBJECTS,
    refresh: true,
    body: {
      query: {
        term: { 'draft_ids.keyword': draftId },
      }
    },
  }).catch((err) => {
    throw DatabaseError('Error deleting draft elements', { cause: err });
  });
};

export const elDeleteDraftContextFromUsers = async (context, user, draftId) => {
  return elRawUpdateByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: "ctx._source.remove('draft_context')" },
      query: {
        term: {
          'draft_context.keyword': draftId
        }
      },
    },
  }).catch((err) => {
    throw DatabaseError('Error deleting users draft context', { cause: err });
  });
};

export const elDeleteDraftContextFromWorks = async (context, user, draftId) => {
  return elRawUpdateByQuery({
    index: READ_INDEX_HISTORY,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: "ctx._source.remove('draft_context')" },
      query: {
        term: {
          'draft_context.keyword': draftId
        }
      },
    },
  }).catch((err) => {
    throw DatabaseError('Error deleting works draft context', { cause: err });
  });
};

export const resolveDraftUpdateFiles = async (context, user, draftUpdates) => {
  const resolvedDraftUpdatePatch = [...draftUpdates.filter((k) => k.key !== FILES_UPDATE_KEY)];
  const addedFiles = draftUpdates.find((k) => k.key === FILES_UPDATE_KEY && k.operation === EditOperation.Add);
  if (addedFiles) {
    const fileIds = addedFiles.value;
    const loadedFileValues = [];
    for (let i = 0; i < fileIds.length; i += 1) {
      const currentFileId = fileIds[i];
      const currentFile = await loadFile(context, user, currentFileId);
      const currentFileContent = toBase64(await getFileContent(currentFileId));
      const currentFileObject = {
        name: currentFile.name,
        data: currentFileContent,
        version: currentFile.metaData.version,
        mime_type: currentFile.metaData.mime_type,
        object_marking_refs: currentFile.metaData.file_markings ?? [],
        no_trigger_import: true,
      };
      loadedFileValues.push(currentFileObject);
    }
    const addInput = { key: FILES_UPDATE_KEY, value: loadedFileValues, operation: EditOperation.Add };
    resolvedDraftUpdatePatch.push(addInput);
  }
  return resolvedDraftUpdatePatch;
};
