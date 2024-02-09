import type { AuthUser } from '../types/user';
import { cropNumber } from './math';
import { isEmptyField } from '../database/utils';
import { FunctionalError } from '../config/errors';
import { logApp } from '../config/conf';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../generated/graphql';
import { isFilterGroupNotEmpty } from './filtering/filtering-utils';

type ObjectWithConfidence = {
  id: string,
  entity_type: string,
  confidence?: number | null
};

export const computeUserEffectiveConfidenceLevel = (user: AuthUser) => {
  // if user has a specific confidence level, it overrides everything and we return it
  if (user.user_confidence_level) {
    return {
      // we make sure the levels are cropped in between 0-100
      // other values were possibly injected in octi <6.0 though API calls
      max_confidence: cropNumber(user.user_confidence_level.max_confidence, 0, 100),
      overrides: user.user_confidence_level.overrides.map((override) => ({
        max_confidence: cropNumber(override.max_confidence, 0, 100),
        entity_type: override.entity_type,
      })),
      source: user,
    };
  }

  // otherwise we get all groups for this user, and select the lowest max_confidence found
  let minLevel = null;
  let source = null;
  if (user.groups) {
    for (let i = 0; i < user.groups.length; i += 1) {
      // groups were not migrated when introducing group_confidence_level, so group_confidence_level might be null
      const groupLevel = user.groups[i].group_confidence_level?.max_confidence ?? null;
      if (groupLevel !== null && (minLevel === null || groupLevel < minLevel)) {
        minLevel = groupLevel;
        source = user.groups[i];
      }
    }
  }

  if (minLevel !== null) {
    return {
      max_confidence: cropNumber(minLevel, 0, 100),
      // TODO: handle overrides and their sources
      overrides: [],
      source,
    };
  }

  // finally, if this user has no effective confidence level, we can return null
  return null;
};

const capInputConfidenceWithUserMaxConfidence = (userMaxConfidence: number, inputConfidence?: number | null) => {
  const input = cropNumber(inputConfidence ?? 100, 0, 100); // input always untrusted, crop in 0-100
  return Math.min(userMaxConfidence, input); // will always equal userMaxConfidence if no inputConfidence
};

/**
 * Assert the confidence control on an input object from create operations
 * Returns the confidence to apply on the resulting element.
 */
export const controlCreateInputWithUserConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputElement: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw FunctionalError('User has no effective max confidence level and cannot create this element', { user_id: user.id });
  }
  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const inputConfidence = inputElement.confidence;
  const confidenceLevelToApply = capInputConfidenceWithUserMaxConfidence(userMaxConfidence, inputConfidence);
  return {
    confidenceLevelToApply,
  };
};

/**
 * Assert the confidence control on an input object from update or upsert operation.
 * Returns a flag to know if the confidences match properly, plus the confidence to apply on the resulting element.
 */
export const controlUpsertInputWithUserConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputElementOrPatch: T, existingElement: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw FunctionalError('User has no effective max confidence level and cannot update this element', { user_id: user.id, element_id: existingElement.id });
  }
  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const confidenceLevelToApply = capInputConfidenceWithUserMaxConfidence(userMaxConfidence, inputElementOrPatch.confidence);
  const existing = cropNumber(existingElement.confidence ?? 0, 0, 100);
  const isConfidenceMatch = confidenceLevelToApply >= existing; // always true if no existingConfidence

  return {
    confidenceLevelToApply,
    isConfidenceMatch,
  };
};

/**
 * Assert the confidence control for a given user over a given object in the platform.
 */
export const controlUserConfidenceAgainstElement = <T extends ObjectWithConfidence>(user: AuthUser, existingElement: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw FunctionalError('User has no effective max confidence level and cannot update this element', { user_id: user.id, element_id: existingElement.id });
  }

  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const existing = cropNumber(existingElement.confidence ?? 0, 0, 100);
  const isConfidenceMatch = userMaxConfidence >= existing; // always true if no existingConfidence

  // contrary to upsert (where we might still update fields that were empty even if confidence control is negative)
  // a user cannot update an object without the right confidence
  if (!isConfidenceMatch) {
    throw FunctionalError('User effective max confidence level is insufficient to update this element', { user_id: user.id, element_id: existingElement.id });
  }
};

type UpdateInput = {
  key: string | string[]
  value: string[]
};

export const adaptUpdateInputsConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputs: UpdateInput | UpdateInput[], element: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw FunctionalError('User has no effective max confidence level and cannot update this element', { user_id: user.id, element_id: element.id });
  }
  const inputsArray = Array.isArray(inputs) ? inputs : [inputs];
  const userMaxConfidenceLevel = user.effective_confidence_level?.max_confidence as number;
  let hasConfidenceInput = false;

  // cap confidence change with user's confidence
  const newInputs = inputsArray.map((input) => {
    const keysArray = Array.isArray(input.key) ? input.key : [input.key];
    if (keysArray.includes('confidence')) {
      const newValue = parseInt(input.value[0], 10);
      if (userMaxConfidenceLevel < newValue) {
        logApp.warn('Object confidence cannot be updated above user\'s max confidence level, the value has been capped.', { user_id: user.id, element_id: element.id });
      }
      hasConfidenceInput = true;
      return {
        ...input,
        value: [Math.min(userMaxConfidenceLevel, newValue).toString()]
      };
    }
    return input;
  });

  // if the initial element does not have any confidence prior to this update, and we are not setting one now
  // then we force the element confidence to the user's confidence
  const hasConfidenceAttribute = schemaAttributesDefinition.getAttribute(element.entity_type, 'confidence');
  if (hasConfidenceAttribute && isEmptyField(element.confidence) && inputsArray.length > 0 && !hasConfidenceInput) {
    newInputs.push({ key: 'confidence', value: [userMaxConfidenceLevel.toString()] });
  }

  return newInputs;
};

export const adaptFiltersWithUserConfidence = (user: AuthUser, filters: FilterGroup): FilterGroup => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw FunctionalError('User has no effective max confidence level and cannot run this filter', { user_id: user.id });
  }
  const userMaxConfidenceLevel = user.effective_confidence_level?.max_confidence as number;
  const confidenceFilter: Filter = {
    key: ['confidence'],
    mode: FilterMode.And,
    operator: FilterOperator.Lte,
    values: [userMaxConfidenceLevel]
  };

  // nest: this filter AND the input filters
  return {
    mode: FilterMode.And,
    filters: [confidenceFilter],
    filterGroups: isFilterGroupNotEmpty(filters) ? [filters] : [],
  };
};
