import * as R from 'ramda';
import { INDEX_DRAFT_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from './utils';
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
  isImpactedRole
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
import { buildReverseUpdateFieldPatch } from './draft-utils';
import { updateAttributeFromLoadedWithRefs } from './middleware';
import { buildRefRelationKey } from '../schema/general';

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
  const draftContext = getDraftContext(context, user);

  // apply reverse field patch
  const reverseUpdateFieldPatch = buildReverseUpdateFieldPatch(element.draft_change.draft_patch);
  const revertedElement = await updateAttributeFromLoadedWithRefs(context, user, element, reverseUpdateFieldPatch);
  // TODO: clean up UPDATE_LINKED impacted elements that no longer need to be in draft => how to know that an update_linked element can be safely removed?

  // verify if element can be entirely removed from draft or if it needs to be kept as update_linked
  // We get all relations that were created or deleted/delete_linked in draft that target this element.
  // If there are still some, it means that we need to keep the element as an UPDATE_LINKED
  const { relations } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  const draftCreatedOrDeletedRelations = relations.filter((f) => f.draft_change && isCreateOrDraftDelete(f.draft_change.draft_operation));
  if (draftCreatedOrDeletedRelations.length <= 0) {
    await elDeleteInstances([element]);
    await elRemoveDraftIdFromElements(context, user, draftContext, [element.internal_id]);
  } else {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_UPDATE_LINKED } };
    await elReplace(revertedElement._index, revertedElement._id, newDraftChange);
  }
};

const removeDraftDeleteLinkedRelations = async (context, user, deleteLinkedRelations) => {
  const elementsToUpdate = deleteLinkedRelations.map((deleteLinkedRelToRemove) => {
    const { rel, dep } = deleteLinkedRelToRemove;
    const isFromImpact = rel.fromId === dep.internal_id;
    const isToImpact = rel.toId === dep.internal_id;
    if (isFromImpact && !isImpactedRole(rel.fromRole)) {
      return {};
    }
    if (isToImpact && !isImpactedRole(rel.toRole)) {
      return {};
    }
    const targetId = isFromImpact ? rel.toId : rel.fromId;
    // Create params and scripted update
    const field = buildRefRelationKey(rel.relationship_type);
    let script = `if (ctx._source['${field}'] == null) ctx._source['${field}'] = [];`;
    script += `ctx._source['${field}'].addAll(params['${field}'])`;
    const source = script;
    const params = { [field]: targetId };
    return { ...dep, id: dep._id, data: { script: { source, params } } };
  });
  const bodyUpdate = elementsToUpdate.flatMap((doc) => [
    { update: { _index: doc._index, _id: doc._id ?? doc.id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
    R.dissoc('_index', doc.data),
  ]);
  if (bodyUpdate.length > 0) {
    const bulkPromise = elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bodyUpdate });
    await Promise.all([bulkPromise]);
  }

  // After reapplying denormalized refs, we delete relations draft instaces and we remove draftId from live instances
  const deleteLinkedRelationsInstances = deleteLinkedRelations.map((delRel) => delRel.rel);
  const deleteLinkedRelationsInstancesIds = deleteLinkedRelationsInstances.map((r) => r.internal_id);
  await elDeleteInstances(deleteLinkedRelationsInstances);
  const draftContext = getDraftContext(context, user);
  await elRemoveDraftIdFromElements(context, user, draftContext, deleteLinkedRelationsInstancesIds);
};

const elRemoveDeleteElementFromDraft = async (context, user, element) => {
  if (element.draft_change?.draft_operation !== DRAFT_OPERATION_DELETE) {
    return;
  }

  // if current element is a relation, and if from or to are in DRAFT_OPERATION_DELETE, it means the current element needs to be switched to a delete linked
  if (isBasicRelationship(element.entity_type) && (element.from?._index._index.includes(INDEX_DRAFT_OBJECTS) || element.to?._index._index.includes(INDEX_DRAFT_OBJECTS))) {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_DELETE_LINKED } };
    await elReplace(element._index, element._id, newDraftChange);
    return;
  }

  const draftContext = getDraftContext(context, user);
  // We get all related relations that are delete_linked
  const { relations } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  const draftDeleteLinkedRelations = relations.filter((f) => f.draft_change && f.draft_change.draft_operation === DRAFT_OPERATION_DELETE_LINKED);
  const draftDeleteLinkedRelationsIds = draftDeleteLinkedRelations.map((r) => r.internal_id);
  // We get all of those relations dependencies (that are not the current element or the related relations)
  const draftDeleteLinkedRelationsTargetsIds = draftDeleteLinkedRelations.map((r) => {
    const { fromId, toId } = r;
    if (!draftDeleteLinkedRelationsIds.includes(fromId)) {
      return fromId;
    }
    if (!draftDeleteLinkedRelationsIds.includes(toId)) {
      return toId;
    }
    return undefined;
  }).filter((i) => i);
  // We resolve all those dependencies
  const draftDeleteDependencies = await elFindByIds(context, user, draftDeleteLinkedRelationsTargetsIds, { includeDeletedInDraft: true });
  const draftDeletedLinkedRelationsToKeep = [];
  const draftDeletedLinkedRelationsToRemove = [];
  // We distinguish relations that need to be kept (from or to has a DELETE operation) from those that can be reverted in draft
  for (let i = 0; i < draftDeleteLinkedRelations.length; i += 1) {
    const { fromId, toId } = draftDeleteLinkedRelations[i];
    const fromDependency = draftDeleteDependencies.find((e) => e.internal_id === fromId);
    const toDependency = draftDeleteDependencies.find((e) => e.internal_id === toId);
    if (fromDependency) {
      if (fromDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE || fromDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
        draftDeletedLinkedRelationsToKeep.push(draftDeleteLinkedRelations[i]);
      } else {
        draftDeletedLinkedRelationsToRemove.push({ rel: draftDeleteLinkedRelations[i], dep: fromDependency });
      }
    } else if (toDependency) {
      if (toDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE || toDependency.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
        draftDeletedLinkedRelationsToKeep.push(draftDeleteLinkedRelations[i]);
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

  if (draftDeletedLinkedRelationsToKeep.length === 0) {
    // TODO: reapply denorm ref if element is a rel
    // TODO: clean up UPDATE_LINKED impacted element that no longer need to be in draft => how to know that an update_linked element can be safely removed?
    await elDeleteInstances([element]);
    await elRemoveDraftIdFromElements(context, user, draftContext, [element.internal_id]);
  } else {
    const newDraftChange = { draft_change: { draft_operation: DRAFT_OPERATION_UPDATE_LINKED } };
    await elReplace(element._index, element._id, newDraftChange);
  }
};

export const elRemoveElementFromDraft = async (context, user, element) => {
  if (!element._index.includes(INDEX_DRAFT_OBJECTS)) {
    return element;
  }

  if (element.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE_LINKED || element.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
    throw UnsupportedError('Cannot remove linked elements from draft', { id: element.id });
  }

  if (element.draft_change?.draft_operation === DRAFT_OPERATION_CREATE) {
    await elRemoveCreateElementFromDraft(context, user, element);
  } else if (element.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE) {
    await elRemoveUpdateElementFromDraft(context, user, element);
  } else if (element.draft_change?.draft_operation === DRAFT_OPERATION_DELETE) {
    await elRemoveDeleteElementFromDraft(context, user, element);
  }

  return element;
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
