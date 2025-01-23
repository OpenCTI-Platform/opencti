import { INDEX_DRAFT_OBJECTS, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY, READ_INDEX_INTERNAL_OBJECTS } from './utils';
import { DatabaseError, UnsupportedError } from '../config/errors';
import {elDeleteElements, elRawDeleteByQuery, elRawUpdateByQuery, getRelationsToRemove} from './engine';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE_LINKED, DRAFT_OPERATION_UPDATE_LINKED } from '../modules/draftWorkspace/draftOperations';
import { SYSTEM_USER } from '../utils/access';

export const elRemoveElementFromDraft = async (context, user, element) => {
  if (!element._index.includes(INDEX_DRAFT_OBJECTS)) {
    return element;
  }

  if (element.draft_change?.draft_operation === DRAFT_OPERATION_UPDATE_LINKED || element.draft_change?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
    throw UnsupportedError('Cannot remove linked elements from draft', { id: element.id });
  }

  if (element.draft_change?.draft_operation === DRAFT_OPERATION_CREATE) {
    await elDeleteElements()
    const { relations } = await getRelationsToRemove(context, SYSTEM_USER, [element], { includeDeletedInDraft: true });
    const draftRelations = relations.filter((f) => f._index.includes(INDEX_DRAFT_OBJECTS));
  }
  // TODO denormalized relations potentially need to be cleaned up + UPDATE_LINKED can be removed if no longer necessary
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
