import * as R from 'ramda';
import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { getDraftContext } from '../utils/draftContext';
import { INDEX_DRAFT_OBJECTS, READ_INDEX_DRAFT_OBJECTS } from './utils';
import { FunctionalError } from '../config/errors';
import { iAttributes, modified, updatedAt } from '../schema/attribute-definition';
import { isMultipleAttribute } from '../schema/schema-attributes';
import { mergeDeepRightAll } from '../utils/format';

export const DRAFT_OPERATION_CREATE = 'create';
export const DRAFT_OPERATION_UPDATE = 'update';
export const DRAFT_OPERATION_DELETE = 'delete';
export const DRAFT_OPERATION_DELETE_LINKED = 'delete_linked';

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

const updatedInputsToData = (instance, inputs) => {
  const inputPairs = R.map((input) => {
    const { key, value } = input;
    let val = value;
    if (!isMultipleAttribute(instance.entity_type, key) && val) {
      val = R.head(value);
    }
    return { [key]: val };
  }, inputs);
  return mergeDeepRightAll(...inputPairs);
};

const IGNORED_INPUTS = [iAttributes.name, modified.name, updatedAt.name];
const computeDraftUpdatePatch = (element, inputs) => {
  let currentDraftPatch = element.draft_change?.draft_update_patch ?? [];
  const updatedInputs = updatedInputsToData(element, inputs);
  Object.keys(updatedInputs).filter((k) => !IGNORED_INPUTS.includes(k)).forEach((key) => {
    const value = updatedInputs[key];
    const inputPatch = { op: 'replace', path: key, value };
    if (currentDraftPatch.some((currentDraftOperation) => currentDraftOperation.path === inputPatch.path)) {
      currentDraftPatch = [...currentDraftPatch.filter((currentDraftOperation) => currentDraftOperation.path !== inputPatch.path), inputPatch];
    } else {
      currentDraftPatch = [...currentDraftPatch, inputPatch];
    }
  });
  return currentDraftPatch;
};

export const getDraftChanges = (initialInstance, inputs) => {
  let draftPatch = [];
  if (!initialInstance._index.includes(INDEX_DRAFT_OBJECTS) || initialInstance.draft_change.draft_operation === DRAFT_OPERATION_UPDATE) {
    draftPatch = computeDraftUpdatePatch(initialInstance, inputs);
  } else if (initialInstance.draft_change.draft_operation !== DRAFT_OPERATION_CREATE) {
    throw FunctionalError('Update operation not possible on draft entity in this state', { initialInstance });
  }
  const draftChange = initialInstance.draft_change ?? { draft_operation: DRAFT_OPERATION_UPDATE };
  return { ...draftChange, draft_update_patch: draftPatch };
};
