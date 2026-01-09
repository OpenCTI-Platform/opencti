import * as R from 'ramda';
import moment from 'moment/moment';
import { INTERNAL_USERS, isBypassUser, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from './access';
import { logApp } from '../config/conf';
import { storeFileConverter, uploadToStorage } from '../database/file-storage';
import { computeDateFromEventId, utcDate } from './format';
import { isEmptyField, isNotEmptyField, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REPLACE } from '../database/utils';
import { hasSameSourceAlreadyUpdateThisScore, INDICATOR_DEFAULT_SCORE } from '../modules/indicator/indicator-utils';
import { creators as creatorsAttribute, iAttributes, xOpenctiStixIds } from '../schema/attribute-definition';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { isObjectAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../schema/stixDomainObject';
import { externalReferences, objectLabel, RELATION_CREATED_BY, RELATION_GRANTED_TO } from '../schema/stixRefRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { FunctionalError } from '../config/errors';

const ALIGN_OLDEST = 'oldest';
const ALIGN_NEWEST = 'newest';
const computeExtendedDateValues = (newValue, currentValue, mode) => {
  const newValueDate = moment(newValue);
  if (isNotEmptyField(currentValue)) {
    const currentValueDate = moment(currentValue);
    if (mode === ALIGN_OLDEST) {
      if (newValueDate.isBefore(currentValueDate)) {
        return { updated: true, date: newValueDate.utc().toISOString() };
      }
      return { updated: false, date: currentValueDate.utc().toISOString() };
    }
    if (mode === ALIGN_NEWEST) {
      if (newValueDate.isAfter(currentValueDate)) {
        return { updated: true, date: newValueDate.utc().toISOString() };
      }
      return { updated: false, date: currentValueDate.utc().toISOString() };
    }
  }
  return { updated: true, date: newValueDate.utc().toISOString() };
};

const isOutdatedUpdate = (context, element, attributeKey) => {
  if (context.eventId) {
    const attributesMap = new Map((element[iAttributes.name] ?? []).map((obj) => [obj.name, obj]));
    const { updated_at: lastAttributeUpdateDate } = attributesMap.get(attributeKey) ?? {};
    if (lastAttributeUpdateDate) {
      try {
        const eventDate = computeDateFromEventId(context.eventId);
        return utcDate(lastAttributeUpdateDate).isAfter(eventDate);
      } catch (_e) {
        logApp.error('Error evaluating event id', { key: attributeKey, event_id: context.eventId });
      }
    }
  }
  return false;
};

const buildAttributeUpdate = (isFullSync, attribute, currentData, inputData) => { // upsertOperations
  const inputs = [];
  const fieldKey = attribute.name;
  if (attribute.multiple) {
    const operation = isFullSync ? UPDATE_OPERATION_REPLACE : UPDATE_OPERATION_ADD;
    // Only add input in case of replace or when we really need to add something
    if (operation === UPDATE_OPERATION_REPLACE || (operation === UPDATE_OPERATION_ADD && isNotEmptyField(inputData))) {
      inputs.push({ key: fieldKey, value: inputData ?? [], operation });
    }
  } else if (isObjectAttribute(fieldKey)) {
    if (isNotEmptyField(inputData)) {
      const mergedDict = R.mergeAll([currentData, inputData]);
      inputs.push({ key: fieldKey, value: [mergedDict] });
    } else if (isFullSync) { // We only allowed removal for full synchronization
      inputs.push({ key: fieldKey, value: [inputData] });
    }
  } else {
    inputs.push({ key: fieldKey, value: [inputData] });
  }
  return inputs;
};

export const buildUpdatePatchForUpsert = (user, resolvedElement, type, basePatch, confidenceForUpsert) => {
  const updatePatch = { ...basePatch };
  const { confidenceLevelToApply, isConfidenceMatch } = confidenceForUpsert;
  // Handle attributes updates
  if (isNotEmptyField(basePatch.stix_id) || isNotEmptyField(basePatch.x_opencti_stix_ids)) {
    const possibleNewStandardId = generateStandardId(type, basePatch);
    const isStandardWillChange = resolvedElement.standard_id !== possibleNewStandardId;
    const rejectedIds = isStandardWillChange && isConfidenceMatch ? [resolvedElement.standard_id, possibleNewStandardId] : [resolvedElement.standard_id];
    const ids = [...(basePatch.x_opencti_stix_ids || [])];
    if (isNotEmptyField(basePatch.stix_id) && !rejectedIds.includes(basePatch.stix_id) && !ids.includes(basePatch.stix_id)) {
      ids.push(basePatch.stix_id);
    }
    if (ids.length > 0) {
      updatePatch.x_opencti_stix_ids = ids;
    }
  }
  // Cumulate creator id
  if (!INTERNAL_USERS[user.id] && !user.no_creators) {
    updatePatch.creator_id = [user.id];
  }
  // Handle "created" upsert
  // Only upsert created if before the existing one
  if (isNotEmptyField(updatePatch.created)) {
    const { date: alignedCreated } = computeExtendedDateValues(updatePatch.created, resolvedElement.created, ALIGN_OLDEST);
    updatePatch.created = alignedCreated;
  }
  // Handle "x_opencti_modified_at" upsert
  // Only upsert modified if after the existing one
  if (isNotEmptyField(updatePatch.x_opencti_modified_at)) {
    const { date: alignedModified } = computeExtendedDateValues(updatePatch.x_opencti_modified_at, resolvedElement.x_opencti_modified_at, ALIGN_NEWEST);
    updatePatch.x_opencti_modified_at = alignedModified;
  }
  // Upsert observed data count and times extensions
  if (type === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const { date: cFo, updated: isCFoUpdated } = computeExtendedDateValues(updatePatch.first_observed, resolvedElement.first_observed, ALIGN_OLDEST);
    const { date: cLo, updated: isCLoUpdated } = computeExtendedDateValues(updatePatch.last_observed, resolvedElement.last_observed, ALIGN_NEWEST);
    updatePatch.first_observed = cFo;
    updatePatch.last_observed = cLo;
    // Only update number_observed if part of the relation dates change
    if (isCFoUpdated || isCLoUpdated) {
      updatePatch.number_observed = resolvedElement.number_observed + updatePatch.number_observed;
    }
  }
  if (type === ENTITY_TYPE_INDICATOR) {
    if (resolvedElement.decay_applied_rule) {
      // Do not compute decay again when:
      // - base score does not change
      // - same userIs has already updated to the same score previously
      const isScoreInUpsertSameAsBaseScore = updatePatch.decay_base_score === resolvedElement.decay_base_score && updatePatch.decay_base_score === resolvedElement.x_opencti_score;
      const hasSameScoreChangedBySameSource = hasSameSourceAlreadyUpdateThisScore(user.id, updatePatch.x_opencti_score, resolvedElement.decay_history);
      if (isScoreInUpsertSameAsBaseScore || hasSameScoreChangedBySameSource) {
        logApp.debug(`[OPENCTI][DECAY] on upsert indicator skip decay, do not change score, keep:${resolvedElement.x_opencti_score}`, { elementScore: resolvedElement.x_opencti_score, patchScore: updatePatch.x_opencti_score, isScoreInUpsertSameAsBaseScore, hasSameScoreChangedBySameSource });
        // don't reset score, valid_from & valid_until
        updatePatch.x_opencti_score = resolvedElement.x_opencti_score; // don't change the score
        updatePatch.valid_from = resolvedElement.valid_from;
        updatePatch.valid_until = resolvedElement.valid_until;
        // don't reset decay attributes
        updatePatch.revoked = resolvedElement.revoked;
        updatePatch.decay_base_score_date = resolvedElement.decay_base_score_date;
        updatePatch.decay_applied_rule = resolvedElement.decay_applied_rule;
        updatePatch.decay_history = []; // History is multiple, forcing to empty array will prevent any modification
        updatePatch.decay_next_reaction_date = resolvedElement.decay_next_reaction_date;
      } else {
        // As base_score as change, decay will be reset by upsert
        logApp.debug('[OPENCTI][DECAY] Decay is restarted', { elementScore: resolvedElement.x_opencti_score, initialPatchScore: basePatch.x_opencti_score, updatePatchScore: updatePatch.x_opencti_score });
      }
    }

    // When revoke is updated to true => false, we need to reset score to a valid score if no score in input
    if (resolvedElement.revoked === true && basePatch.revoked === false) {
      if (!updatePatch.x_opencti_score) {
        if (resolvedElement.decay_applied_rule) {
          updatePatch.x_opencti_score = resolvedElement.decay_base_score > INDICATOR_DEFAULT_SCORE ? resolvedElement.decay_base_score : INDICATOR_DEFAULT_SCORE;
        } else {
          updatePatch.x_opencti_score = INDICATOR_DEFAULT_SCORE;
        }
      }
    }
  }
  // Upsert relations with times extensions
  if (isStixCoreRelationship(type)) {
    const { date: cStartTime } = computeExtendedDateValues(updatePatch.start_time, resolvedElement.start_time, ALIGN_OLDEST);
    const { date: cStopTime } = computeExtendedDateValues(updatePatch.stop_time, resolvedElement.stop_time, ALIGN_NEWEST);
    updatePatch.start_time = cStartTime;
    updatePatch.stop_time = cStopTime;
  }
  if (isStixSightingRelationship(type)) {
    const { date: cFs, updated: isCFsUpdated } = computeExtendedDateValues(updatePatch.first_seen, resolvedElement.first_seen, ALIGN_OLDEST);
    const { date: cLs, updated: isCLsUpdated } = computeExtendedDateValues(updatePatch.last_seen, resolvedElement.last_seen, ALIGN_NEWEST);
    updatePatch.first_seen = cFs;
    updatePatch.last_seen = cLs;
    if (isCFsUpdated || isCLsUpdated) {
      updatePatch.attribute_count = resolvedElement.attribute_count + updatePatch.attribute_count;
    }
  }
  // region confidence control / upsert
  updatePatch.confidence = confidenceLevelToApply;
  // note that if the existing data has no confidence (null) it will still be updated below, even if isConfidenceMatch = false
  // endregion
  return updatePatch;
};

const generateFileInputsForUpsert = async (context, user, resolvedElement, updatePatch) => {
  // If file directly attached
  if (!isEmptyField(updatePatch.file)) {
    const path = `import/${resolvedElement.entity_type}/${resolvedElement.internal_id}`;
    const { upload: file } = await uploadToStorage(context, user, path, updatePatch.file, { entity: resolvedElement });
    const convertedFile = storeFileConverter(user, file);
    // The impact in the database is the completion of the files
    const fileImpact = { key: 'x_opencti_files', value: [...(resolvedElement.x_opencti_files ?? []), convertedFile] };
    return [fileImpact];
  }
  return [];
};

const mergeUpsertOperations = (upsertKey, elementCurrentValue, upsertOperations) => {
  let currentValueArray = elementCurrentValue ?? [];
  let mergedUpsertOperationValue = [...currentValueArray];
  let mergedUpsertOperationOperation;
  for (let i = 0; i < upsertOperations.length; i++) {
    const { operation: currentUpsertOperation, value: currentUpsertValue } = upsertOperations[i];
    if (currentUpsertOperation === 'remove') {
      // filter values to remove from current values in DB
      mergedUpsertOperationValue = mergedUpsertOperationValue.filter((e) =>
        !currentUpsertValue?.includes(e) && (!e?.id || !currentUpsertValue?.some((u) => u?.id === e?.id)),
      );
      mergedUpsertOperationOperation = 'replace';
    } else if (currentUpsertOperation === 'replace') {
      // replace current values in DB with upsert values
      mergedUpsertOperationValue = [...(currentUpsertValue ?? [])];
      mergedUpsertOperationOperation = 'replace';
    } else if (currentUpsertOperation === 'add') {
      // add upsert operation values to final patch values first
      mergedUpsertOperationValue.push(...(currentUpsertValue ?? []));
      mergedUpsertOperationOperation = (!mergedUpsertOperationOperation || mergedUpsertOperationOperation === 'add') ? 'add' : 'replace';
    }
  }
  return { key: upsertKey, operation: mergedUpsertOperationOperation, value: mergedUpsertOperationValue };
};

export const mergeUpsertInput = (elementCurrentValue, upsertValue, updatePatchInput, upsertOperation) => {
  const finalPatchInput = { ...updatePatchInput };
  // for now we only handle 'add' operations coming from updatePatchInput for multiple attributes
  // we need to first apply the upsertOperation on element then the updatePatchInput
  if (updatePatchInput.operation === 'add' && upsertOperation?.operation) {
    let currentValueArray = elementCurrentValue ?? [];
    currentValueArray = Array.isArray(currentValueArray) ? currentValueArray : [currentValueArray];
    let finalPatchValue = [...currentValueArray];
    if (upsertOperation.operation === 'remove') {
      // filter values to remove from current values in DB
      finalPatchValue = finalPatchValue.filter((e) => !upsertOperation.value?.includes(e) && (!e?.id || !upsertOperation.value?.some((u) => u?.id === e?.id)));
      finalPatchInput.operation = 'replace';
    } else if (upsertOperation.operation === 'replace') {
      // replace current values in DB with upsert values
      finalPatchValue = [...(upsertOperation?.value ?? [])];
      finalPatchInput.operation = 'replace';
    } else if (upsertOperation.operation === 'add') {
      // add upsert operation values to final patch values first
      finalPatchValue = [...(upsertOperation.value ?? [])];
      finalPatchInput.operation = 'add';
    }
    // add updatePatchInput values coming from upsert
    if (updatePatchInput.value?.length > 0) {
      finalPatchValue.push(...updatePatchInput.value);
    }
    // keep only unique values
    let finalDedupedPatchValuesMap = new Map();
    for (let i = 0; i < finalPatchValue.length; i++) {
      const currentPatchValue = finalPatchValue[i];
      if (!finalDedupedPatchValuesMap.has(currentPatchValue) && !finalDedupedPatchValuesMap.has(currentPatchValue?.id)) {
        if (currentPatchValue?.id) {
          finalDedupedPatchValuesMap.set(currentPatchValue.id, currentPatchValue);
        } else {
          finalDedupedPatchValuesMap.set(currentPatchValue, currentPatchValue);
        }
      }
    }
    // we replace current values
    finalPatchInput.value = Array.from(finalDedupedPatchValuesMap.values());
  }
  return finalPatchInput;
};

/**
 * should return a merged inputs list with only one element per key
 *
 * @param resolvedElement (element from DB)
 * @param updatePatch (element from bundle)
 * @param updatePatchInputs : array inputs generated from updatePatch (from element in bundle)
 * @param upsertOperations : array inputs from upsertOperations in bundle
 */
export const mergeUpsertInputs = (resolvedElement, updatePatch, updatePatchInputs, upsertOperations) => {
  // we want only to call this method for remove or replace operations that should happen on arrays
  if (!upsertOperations || upsertOperations.length === 0) {
    return updatePatchInputs;
  }

  const updatePatchInputsMap = new Map(updatePatchInputs.map((input) => [input.key, input]));
  const upsertOperationsByKeyMap = new Map();
  for (let i = 0; i < upsertOperations.length; i += 1) {
    const currentUpsertOperation = upsertOperations[i];
    if (upsertOperationsByKeyMap.has(currentUpsertOperation.key)) {
      upsertOperationsByKeyMap.get(currentUpsertOperation.key).push(currentUpsertOperation);
    } else {
      upsertOperationsByKeyMap.set(currentUpsertOperation.key, [currentUpsertOperation]);
    }
  }
  const upsertOperationsKeys = Array.from(upsertOperationsByKeyMap.keys());
  for (let i = 0; i < upsertOperationsKeys.length; i += 1) {
    const upsertOperationKey = upsertOperationsKeys[i];
    const elementCurrentValue = resolvedElement[upsertOperationKey];
    const upsertOperationValues = upsertOperationsByKeyMap.get(upsertOperationKey);
    let finalUpsertOperation;
    if (upsertOperationValues.length > 1) {
      finalUpsertOperation = mergeUpsertOperations(upsertOperationKey, elementCurrentValue, upsertOperationValues);
    } else {
      finalUpsertOperation = upsertOperationValues[0];
    }
    if (updatePatchInputsMap.has(upsertOperationKey)) {
      const updatePatchInput = updatePatchInputsMap.get(upsertOperationKey);
      const elementCurrentValue = resolvedElement[upsertOperationKey];
      const upsertValue = updatePatch[upsertOperationKey];
      const mergedInput = mergeUpsertInput(elementCurrentValue, upsertValue, updatePatchInput, finalUpsertOperation);
      updatePatchInputsMap.set(upsertOperationKey, mergedInput); // replace updatePatchInput
    } else {
      updatePatchInputsMap.set(upsertOperationKey, finalUpsertOperation); // just add the upsert operation
    }
  }
  return Array.from(updatePatchInputsMap.values());
};

export const generateAttributesInputsForUpsert = (context, _user, resolvedElement, type, updatePatch, confidenceForUpsert) => {
  const { isConfidenceMatch } = confidenceForUpsert;
  // -- Upsert attributes
  const inputs = [];
  const attributes = Array.from(schemaAttributesDefinition.getAttributes(type).values());
  for (let attrIndex = 0; attrIndex < attributes.length; attrIndex += 1) {
    const attribute = attributes[attrIndex];
    const attributeKey = attribute.name;
    const isInputAvailable = attributeKey in updatePatch;
    if (isInputAvailable) { // The attribute is explicitly available in the patch
      const inputData = updatePatch[attributeKey];
      const isOutDatedModification = isOutdatedUpdate(context, resolvedElement, attributeKey);
      const isStructuralUpsert = attributeKey === xOpenctiStixIds.name || attributeKey === creatorsAttribute.name; // Ids and creators consolidation is always granted
      const isFullSync = context.synchronizedUpsert || attribute.upsert_force_replace; // In case of full synchronization or force full upsert, just update the data
      const isInputWithData = typeof inputData === 'string' ? isNotEmptyField(inputData.trim()) : isNotEmptyField(inputData);
      const isCurrentlyEmpty = isEmptyField(resolvedElement[attributeKey]) && isInputWithData; // If the element current data is empty, we always expect to put the value
      // Field can be upsert if:
      // 1. Confidence is correct
      // 2. Attribute is declared upsert=true in the schema
      // 3. Data from the inputs is not empty to prevent any data cleaning
      const canBeUpsert = isConfidenceMatch && attribute.upsert && isInputWithData;
      // Upsert will be done if upsert is well-defined but also in full synchro mode or if the current value is empty
      if (!isOutDatedModification) {
        if (isStructuralUpsert || canBeUpsert || isFullSync || isCurrentlyEmpty) {
          inputs.push(...buildAttributeUpdate(isFullSync, attribute, resolvedElement[attributeKey], inputData));
        }
      } else {
        logApp.info('Discarding outdated attribute update mutation', { key: attributeKey });
      }
    }
  }
  return inputs;
};

const generateRefsInputsForUpsert = (context, user, resolvedElement, _type, updatePatch, confidenceForUpsert, validEnterpriseEdition) => {
  const { isConfidenceMatch, isConfidenceUpper } = confidenceForUpsert;
  const inputs = [];
  const metaInputFields = schemaRelationsRefDefinition.getRelationsRef(resolvedElement.entity_type).map((ref) => ref.name);
  for (let fieldIndex = 0; fieldIndex < metaInputFields.length; fieldIndex += 1) {
    const inputField = metaInputFields[fieldIndex];
    const relDef = schemaRelationsRefDefinition.getRelationRef(resolvedElement.entity_type, inputField);
    const isInputAvailable = inputField in updatePatch;
    if (isInputAvailable) {
      const patchInputData = updatePatch[inputField];
      const isInputWithData = isNotEmptyField(patchInputData);
      const isUpsertSynchro = context.synchronizedUpsert;
      const isOutDatedModification = isOutdatedUpdate(context, resolvedElement, inputField);
      if (!isOutDatedModification) {
        if (relDef.multiple) {
          const currentData = resolvedElement[relDef.databaseName] ?? [];
          const currentDataSet = new Set(currentData);
          const isCurrentWithData = isNotEmptyField(currentData);
          const fullPatchInputData = patchInputData ?? [];
          const fullPatchInputDataSet = new Set(fullPatchInputData.map((i) => i.internal_id));
          // Specific case for organization restriction, has EE must be activated.
          // If not supported, upsert of organization is not applied
          const isUserCanManipulateGrantedRefs = isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && validEnterpriseEdition === true;
          const allowedOperation = relDef.databaseName !== RELATION_GRANTED_TO || (relDef.databaseName === RELATION_GRANTED_TO && isUserCanManipulateGrantedRefs);
          const inputToCurrentDiff = fullPatchInputData.filter((target) => !currentDataSet.has(target.internal_id));
          const currentToInputDiff = currentData.filter((current) => !fullPatchInputDataSet.has(current));
          // If expected data is different from current data
          if (allowedOperation && (inputToCurrentDiff.length + currentToInputDiff.length) > 0) {
            // In full synchro, just replace everything
            if (isUpsertSynchro) {
              inputs.push({ key: inputField, value: fullPatchInputData, operation: UPDATE_OPERATION_REPLACE });
            } else {
              const fillEmptyData = isInputWithData && !isCurrentWithData;
              const hasDataDifferential = isCurrentWithData && isInputWithData && inputToCurrentDiff.length > 0;
              const isAllowedAddRefWithoutConfidence = relDef.name === objectLabel.name || relDef.name === externalReferences.name;
              const isConfidenceAllowed = isConfidenceMatch || isAllowedAddRefWithoutConfidence;
              if ((hasDataDifferential && isConfidenceAllowed) || fillEmptyData) {
                // If data is provided, different from existing data, and of higher confidence
                // OR if existing data is empty and data is provided (even if lower confidence, it's better than nothing),
                // --> apply an add operation
                inputs.push({ key: inputField, value: inputToCurrentDiff, operation: UPDATE_OPERATION_ADD });
              }
            }
          }
        } else { // not multiple
          // If expected data is different from current data...
          const currentData = resolvedElement[relDef.databaseName];
          const isCurrentEmptyData = isEmptyField(currentData);
          const isInputDifferentFromCurrent = !R.equals(currentData, patchInputData);
          // ... and data can be updated:
          // forced synchro
          // OR the field is currently null (auto consolidation)
          // OR the confidence matches
          // To prevent too much flickering on multi sources the created-by will be replaced only for strict upper confidence
          const isProtectedCreatedBy = relDef.databaseName === RELATION_CREATED_BY && !isCurrentEmptyData && !isConfidenceUpper;
          const updatable = ((isInputWithData && isCurrentEmptyData) || isConfidenceMatch) && !isProtectedCreatedBy;
          if (isInputDifferentFromCurrent && (isUpsertSynchro || updatable)) {
            inputs.push({ key: inputField, value: [patchInputData] });
          }
        }
      } else {
        logApp.info('Discarding outdated attribute update mutation', { key: inputField });
      }
    }
  }
  return inputs;
};

export const generateInputsForUpsert = async (context, user, resolvedElement, type, updatePatch, confidenceForUpsert, validEnterpriseEdition) => {
  const inputs = []; // All inputs impacted by modifications (+inner)
  // if file in updatePatch, we need to upload it and update x_opencti_files
  const fileInputs = await generateFileInputsForUpsert(context, user, resolvedElement, updatePatch);
  inputs.push(...fileInputs);
  // -- Upsert attributes
  const attributesInputs = generateAttributesInputsForUpsert(context, user, resolvedElement, type, updatePatch, confidenceForUpsert);
  inputs.push(...attributesInputs);
  // -- Upsert refs
  const refsInputs = generateRefsInputsForUpsert(context, user, resolvedElement, type, updatePatch, confidenceForUpsert, validEnterpriseEdition);
  inputs.push(...refsInputs);
  // -- merge inputs with upsertOperations
  if (updatePatch.upsertOperations?.length > 0 && !isBypassUser(user)) {
    throw FunctionalError('User has insufficient rights to use upsertOperations', { user_id: user.id, element_id: resolvedElement.id });
  }
  return mergeUpsertInputs(resolvedElement, updatePatch, inputs, updatePatch.upsertOperations);
};
