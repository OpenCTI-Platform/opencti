import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { getDraftContext } from '../utils/draftContext';
import { READ_INDEX_DRAFT_OBJECTS } from './utils';

export const buildDraftFilter = (context, user) => {
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
  }
  return draftMust;
};

export const isDraftSupportedEntity = (element) => {
  return !isInternalObject(element.entity_type) && !isInternalRelationship(element.entity_type);
};
