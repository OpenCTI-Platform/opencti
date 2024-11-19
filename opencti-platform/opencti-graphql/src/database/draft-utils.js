import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { getDraftContext } from '../utils/draftContext';
import { READ_INDEX_DRAFT_OBJECTS } from './utils';

export const DRAFT_OPERATION_CREATE = 'create';
export const DRAFT_OPERATION_UPDATE = 'update';
export const DRAFT_OPERATION_DELETE = 'delete';
export const DRAFT_OPERATION_DELETE_LINKED = 'delete_linked';

export const buildDraftFilter = (context, user, opts = {}) => {
  const { includeDeletedInDraft = false } = opts;
  const draftContext = getDraftContext(context, user);
  const draftMust = [];
  if (draftContext) {
    const mustLive = {
      bool: {
        must_not: [
          { term: { _index: READ_INDEX_DRAFT_OBJECTS } },
          { term: { 'draft_ids.keyword': draftContext } }
        ]
      }
    };
    const mustDraft = {
      bool: {
        must: [
          { term: { _index: READ_INDEX_DRAFT_OBJECTS } },
          { term: { 'draft_ids.keyword': draftContext } }
        ]
      }
    };
    const draftBool = {
      bool: {
        should: [mustLive, mustDraft],
        minimum_should_match: 1,
      },
    };
    draftMust.push(draftBool);

    if (!includeDeletedInDraft) {
      const excludeDeletedDraft = {
        bool: {
          must_not: [
            { terms: { 'draft_change.draft_operation.keyword': [DRAFT_OPERATION_DELETE, DRAFT_OPERATION_DELETE_LINKED] } },
          ]
        }
      };
      draftMust.push(excludeDeletedDraft);
    }
  }
  return draftMust;
};

export const isDraftSupportedEntity = (element) => {
  return !isInternalObject(element.entity_type) && !isInternalRelationship(element.entity_type);
};

// TODO: once update metadata is better refined, add it to draft_change
export const getDraftChanges = (initialInstance) => {
  return initialInstance.draft_change ?? { draft_operation: DRAFT_OPERATION_UPDATE };
};
