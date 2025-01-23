import { INDEX_DRAFT_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from './utils';
import { DatabaseError, UnsupportedError } from '../config/errors';
import {
  computeDeleteElementsImpacts,
  elDeleteInstances,
  elRawDeleteByQuery,
  elRawUpdateByQuery,
  elRemoveDraftIdFromElements,
  elRemoveRelationConnection,
  getRelationsToRemove
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
import {buildReverseUpdateFieldPatch} from "./draft-utils";
import {updateAttribute, updateAttributeFromLoadedWithRefs} from "./middleware";

const elRemoveCreateElementFromDraft = async (context, user, element) => {
  if(element.draft_change?.draft_operation !== DRAFT_OPERATION_CREATE){
    return;
  }
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, [element]);
  // We get all relations that were created in draft target this element (should be all of the relations in this case, since element itself was created in draft)
  const draftCreatedRelations = relations.filter((f) => f.draft_change && f.draft_change.draft_operation === DRAFT_OPERATION_CREATE);
  // Add element to relations to get impacts from if current element is itself a relation
  const relationToRemove = draftCreatedRelations.concat(isBasicRelationship(element.entity_type) ? [element] : []);
  const draftRelationsElementsImpact = await computeDeleteElementsImpacts(relationToRemove, [element.internal_id], relationsToRemoveMap);

  // TODO: clean up UPDATE_LINKED impacted elements that no longer need to be in draft => how to know that an update_linked element can be safely removed?
  await elRemoveRelationConnection(context, user, draftRelationsElementsImpact);
  await elDeleteInstances(context, user, [element, ...draftCreatedRelations]);
};

const elRemoveUpdateElementFromDraft = async (context, user, element) => {
  if(element.draft_change?.draft_operation !== DRAFT_OPERATION_UPDATE){
    return;
  }
  const draftContext = getDraftContext(context, user);

  // apply reverse field patch
  const reverseUpdateFieldPatch = buildReverseUpdateFieldPatch(element.draft_change.draft_patch);
  await updateAttributeFromLoadedWithRefs(context, user, element,reverseUpdateFieldPatch);

  // verify if element can be entirely removed from draft or if it needs to be kept as update_linked

  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  // We get all relations that were created in draft target this element
  const draftCreatedOrDeletedRelations = relations.filter((f) => f.draft_change && (f.draft_change.draft_operation === DRAFT_OPERATION_CREATE || f.draft_change.draft_operation === DRAFT_OPERATION_DELETE);

  // we need to know if element needs to be completely removed from draft, or if it needs to be switched to an UPDATE_LINKED
  // if there are no draft created or deleted relations: draft element can safely be deleted to revert back to live instance and draft_id can be removed from live entity
  // if there are draft created relations, there are two cases:
  //  - all draft created/deleted relations are refs updated on this instance
  //    -> all draft created/deleted refs can safely be deleted, applying removal/add on impacted entities, draft element can safely be deleted and draft_id can be removed from live entity
  //  - there are created relations/refs that were originated from other sources
  //    -> all updates need to be reverted and draft element needs to be switched to an UPDATE_LINKED
  if (draftCreatedOrDeletedRelations.length <= 0) {
    await elDeleteInstances(context, user, [element]);
    await elRemoveDraftIdFromElements(context, user, draftContext, [element.internal_id]);
  } else {
    // for now, we will not handle the case where the entity can still be reverted to the live instance, we always apply the reverse field patch to the draft instance and move it to an update_linked
    const draftRelationsElementsImpact = await computeDeleteElementsImpacts(draftCreatedRelations, [element.internal_id], relationsToRemoveMap);
  }
};

const elRemoveDeleteElementFromDraft = async (context, user, element) => {
  if(element.draft_change?.draft_operation !== DRAFT_OPERATION_DELETE){
    return;
  }
  const { relations, relationsToRemoveMap } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
  // We get all relations that were created in draft target this element
  const draftCreatedRelations = relations.filter((f) => f.draft_change && f.draft_change.draft_operation === DRAFT_OPERATION_DELETE_LINKED);
  const draftRelationsElementsImpact = await computeDeleteElementsImpacts(draftCreatedRelations, [element.internal_id], relationsToRemoveMap);

  await elRemoveRelationConnection(context, user, draftRelationsElementsImpact);
  await elDeleteInstances(context, user, [element, ...draftCreatedRelations]);
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
