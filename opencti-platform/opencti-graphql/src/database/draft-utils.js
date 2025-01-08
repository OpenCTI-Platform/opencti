import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { getDraftContext } from '../utils/draftContext';
import { READ_INDEX_DRAFT_OBJECTS, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from './utils';

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

export const getDraftChanges = (initialInstance, updatedInputs) => {
  const currentDraftChanges = initialInstance.draft_change ?? { draft_operation: DRAFT_OPERATION_UPDATE };
  if (updatedInputs.length === 0) {
    return currentDraftChanges;
  }

  const currentInputs = currentDraftChanges.draftupdateinputs ? JSON.parse(currentDraftChanges.draftupdateinputs) : {};
  const nonResolvedInput = updatedInputs.map((i) => { return { key: i.key, value: i.value.map((v) => v.internal_id ?? v), operation: i.operation ?? UPDATE_OPERATION_REPLACE }; });

  for (let i = 0; i < nonResolvedInput.length; i += 1) {
    const updatedInput = nonResolvedInput[i];
    const currentUpdates = currentInputs[updatedInput.key];
    // If there is currently an update, we have to handle deduplication
    if (currentUpdates) {
      // If new input is an add
      if (updatedInput.operation === UPDATE_OPERATION_ADD) {
        // if current input was a replace, add updateInput values to the replaced values
        if (currentUpdates.replacedValue.length > 0) {
          const newReplacedValues = [...currentUpdates.replacedValue, ...updatedInput.value];
          currentInputs[updatedInput.key] = { replacedValue: newReplacedValues, addedValue: [], removedValue: [] };
        } else { // Otherwise, remove added inputs from removedValues and add them to addedValues
          const newAddedValues = [...currentUpdates.addedValue, ...updatedInput.value];
          const newRemovedValues = currentUpdates.removedValue.filter((v) => !updatedInput.value.includes(v));
          currentInputs[updatedInput.key] = { replacedValue: [], addedValue: newAddedValues, removedValue: newRemovedValues };
        }
      } else if (updatedInput.operation === UPDATE_OPERATION_REMOVE) { // Else if new input is a remove
        // if current input was a replace, remove updateInput values from the replaced values
        if (currentUpdates.replacedValue.length > 0) {
          const newReplacedValues = currentUpdates.replacedValue.filter((v) => !updatedInput.value.includes(v));
          currentInputs[updatedInput.key] = { replacedValue: newReplacedValues, addedValue: [], removedValue: [] };
        } else { // Otherwise, remove added inputs from addedValues and add them to removedValues
          const newAddedValues = currentUpdates.addedValue.filter((v) => !updatedInput.value.includes(v));
          const newRemovedValues = [...currentUpdates.removedValue, ...updatedInput.value];
          currentInputs[updatedInput.key] = { replacedValue: [], addedValue: newAddedValues, removedValue: newRemovedValues };
        }
      } else { // Else if new input is a replace or not defined, remove all addedValues and removedValues, and overwrite replacedValues with current input
        currentInputs[updatedInput.key] = { replacedValue: updatedInput.value, addedValue: [], removedValue: [] };
      }
    } else { // If no update is currently defined for this key, we just initialize it with current operation
      const replacedValue = updatedInput.operation === UPDATE_OPERATION_REPLACE ? updatedInput.value : [];
      const addedValue = updatedInput.operation === UPDATE_OPERATION_ADD ? updatedInput.value : [];
      const removedValue = updatedInput.operation === UPDATE_OPERATION_REMOVE ? updatedInput.value : [];
      currentInputs[updatedInput.key] = { replacedValue, addedValue, removedValue };
    }
  }

  const stringifiedInputs = JSON.stringify(currentInputs);

  return { ...currentDraftChanges, draftupdateinputs: stringifiedInputs };
};
