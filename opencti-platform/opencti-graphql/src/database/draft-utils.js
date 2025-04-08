import { files } from '../schema/attribute-definition';
import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';
import { getDraftContext } from '../utils/draftContext';
import { isDraftIndex, READ_INDEX_DRAFT_OBJECTS, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from './utils';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_DELETE, DRAFT_OPERATION_DELETE_LINKED, DRAFT_OPERATION_UPDATE } from '../modules/draftWorkspace/draftOperations';
import { EditOperation } from '../generated/graphql';

export const getDraftFilePrefix = (draftId) => {
  return `draft/${draftId}/`;
};

export const getDraftContextFilesPrefix = (context) => {
  const draftContext = getDraftContext(context, context.user);
  if (draftContext) {
    return getDraftFilePrefix(draftContext);
  }
  return '';
};

export const isDraftFile = (fileKey, draftId, suffix = '') => {
  return fileKey.startsWith(getDraftFilePrefix(draftId) + suffix);
};

export const getDraftContextIfElementInDraft = (context, instance) => {
  return !getDraftContext(context) && isDraftIndex(instance._index) && instance.draft_ids?.length === 1 ? { ...context, draft_context: instance.draft_ids[0] } : context;
};

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

export const FILES_UPDATE_KEY = files.name;
// Transform a raw update patched stored in a draft_updates_patch to a list of reverse field patch inputs
export const buildReverseUpdateFieldPatch = (rawUpdatePatch) => {
  const resulReverseFieldPatch = [];
  if (rawUpdatePatch) {
    const parsedUpdatePatch = JSON.parse(rawUpdatePatch);
    // no need for now to reverse files because draft_change is cleared.
    const updatePatchKeys = Object.keys(parsedUpdatePatch).filter((k) => k !== FILES_UPDATE_KEY);
    for (let i = 0; i < updatePatchKeys.length; i += 1) {
      const currentKey = updatePatchKeys[i];
      const currentValues = parsedUpdatePatch[currentKey];
      if (currentValues) {
        const replaceInput = { key: currentKey, value: currentValues.initial_value, operation: EditOperation.Replace };
        resulReverseFieldPatch.push(replaceInput);
      }
    }
  }

  return resulReverseFieldPatch;
};

// Transform a raw update patched stored in a draft_updates_patch to a list of field patch inputs
export const buildUpdateFieldPatch = (rawUpdatePatch) => {
  const resultFieldPatch = [];
  if (rawUpdatePatch) {
    const parsedUpdatePatch = JSON.parse(rawUpdatePatch);
    const updatePatchKeys = Object.keys(parsedUpdatePatch);
    for (let i = 0; i < updatePatchKeys.length; i += 1) {
      const currentKey = updatePatchKeys[i];
      const currentValues = parsedUpdatePatch[currentKey];
      if (currentValues) {
        if (currentValues.replaced_value && currentValues.replaced_value.length > 0) {
          const replaceInput = { key: currentKey, value: currentValues.replaced_value, operation: EditOperation.Replace };
          resultFieldPatch.push(replaceInput);
        } else {
          if (currentValues.added_value && currentValues.added_value.length > 0) {
            const addInput = { key: currentKey, value: currentValues.added_value, operation: EditOperation.Add };
            resultFieldPatch.push(addInput);
          }
          if (currentValues.removed_value && currentValues.removed_value.length > 0) {
            const removeInput = { key: currentKey, value: currentValues.removed_value, operation: EditOperation.Remove };
            resultFieldPatch.push(removeInput);
          }
        }
      }
    }
  }

  return resultFieldPatch;
};

export const getConsolidatedUpdatePatch = (currentUpdatePatch, updatedInputsResolved) => {
  const newUpdatePatch = currentUpdatePatch;
  const nonResolvedInput = updatedInputsResolved
    .map((i) => { return { key: i.key, value: i.value?.map((v) => v.standard_id ?? v), operation: i.operation ?? UPDATE_OPERATION_REPLACE, previous: i.previous ?? [] }; });
  for (let i = 0; i < nonResolvedInput.length; i += 1) {
    const currentNonResolvedInput = nonResolvedInput[i];
    const currentUpdates = currentUpdatePatch[currentNonResolvedInput.key];
    // If there is currently an update, we have to handle deduplication
    if (currentUpdates) {
      // If new input is an add
      if (currentNonResolvedInput.operation === UPDATE_OPERATION_ADD) {
        // if current input was a replace, add updateInput values to the replaced values
        if (currentUpdates.replaced_value.length > 0) {
          const newReplacedValues = [...new Set([...currentUpdates.replaced_value, ...currentNonResolvedInput.value])];
          newUpdatePatch[currentNonResolvedInput.key] = { ...currentUpdates, replaced_value: newReplacedValues, added_value: [], removed_value: [] };
        } else { // Otherwise, remove added inputs from removed_value and add them to added_value
          const newAddedValues = [...new Set([...currentUpdates.added_value, ...currentNonResolvedInput.value])];
          const newRemovedValues = currentUpdates.removed_value.filter((v) => !currentNonResolvedInput.value.includes(v));
          newUpdatePatch[currentNonResolvedInput.key] = { ...currentUpdates, replaced_value: [], added_value: newAddedValues, removed_value: newRemovedValues };
        }
      } else if (currentNonResolvedInput.operation === UPDATE_OPERATION_REMOVE) { // Else if new input is a remove
        // if current input was a replace, remove updateInput values from the replaced values
        if (currentUpdates.replaced_value.length > 0) {
          const newReplacedValues = currentUpdates.replaced_value.filter((v) => !currentNonResolvedInput.value.includes(v));
          newUpdatePatch[currentNonResolvedInput.key] = { ...currentUpdates, replaced_value: newReplacedValues, added_value: [], removed_value: [] };
        } else { // Otherwise, remove added inputs from added_value and add them to removed_value
          const newAddedValues = currentUpdates.added_value.filter((v) => !currentNonResolvedInput.value.includes(v));
          const newRemovedValues = [...new Set([...currentUpdates.removed_value, ...currentNonResolvedInput.value])];
          newUpdatePatch[currentNonResolvedInput.key] = { ...currentUpdates, replaced_value: [], added_value: newAddedValues, removed_value: newRemovedValues };
        }
      } else { // Else if new input is a replace or not defined, remove all added_value and removedValues, and overwrite replaced_value with current input
        newUpdatePatch[currentNonResolvedInput.key] = { ...currentUpdates, replaced_value: currentNonResolvedInput.value, added_value: [], removed_value: [] };
      }
    } else { // If no update is currently defined for this key, we just initialize it with current operation and we set the initial value
      const replaced_value = currentNonResolvedInput.operation === UPDATE_OPERATION_REPLACE ? currentNonResolvedInput.value : [];
      const added_value = currentNonResolvedInput.operation === UPDATE_OPERATION_ADD ? currentNonResolvedInput.value : [];
      const removed_value = currentNonResolvedInput.operation === UPDATE_OPERATION_REMOVE ? currentNonResolvedInput.value : [];
      const initial_value = currentNonResolvedInput.previous?.map((p) => p.standard_id ?? p);
      newUpdatePatch[currentNonResolvedInput.key] = { replaced_value, added_value, removed_value, initial_value };
    }
  }

  return newUpdatePatch;
};

// Get the resulting draft_change to apply to instance depending on updated inputs
// If instance already contained a draft_change with a draft_update_patch, consolidate updated inputs in existing draft_update_patch
export const getDraftChanges = (initialInstance, updatedInputs) => {
  const currentDraftChanges = initialInstance.draft_change ?? { draft_operation: DRAFT_OPERATION_UPDATE };
  if (updatedInputs.length === 0
      || currentDraftChanges?.draft_operation === DRAFT_OPERATION_CREATE
      || currentDraftChanges?.draft_operation === DRAFT_OPERATION_DELETE
      || currentDraftChanges?.draft_operation === DRAFT_OPERATION_DELETE_LINKED) {
    return currentDraftChanges;
  }

  const currentUpdatePatch = currentDraftChanges.draft_updates_patch ? JSON.parse(currentDraftChanges.draft_updates_patch) : {};
  const newUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, updatedInputs);
  const stringifiedUpdatePatch = JSON.stringify(newUpdatePatch);

  return { draft_operation: DRAFT_OPERATION_UPDATE, draft_updates_patch: stringifiedUpdatePatch };
};
