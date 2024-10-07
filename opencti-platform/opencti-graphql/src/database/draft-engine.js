import { READ_INDEX_DRAFT_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from './utils';
import { DatabaseError } from '../config/errors';
import { elRawDeleteByQuery, elRawUpdateByQuery } from './engine';

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
