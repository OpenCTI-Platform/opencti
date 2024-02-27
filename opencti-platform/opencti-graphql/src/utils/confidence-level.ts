import type { AuthUser } from '../types/user';
import { cropNumber } from './math';
import { isEmptyField } from '../database/utils';
import { FunctionalError, LockTimeoutError } from '../config/errors';
import { logApp } from '../config/conf';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../generated/graphql';
import { isFilterGroupNotEmpty } from './filtering/filtering-utils';
import { isBypassUser } from './access';

type ObjectWithConfidence = {
  id: string,
  entity_type: string,
  confidence?: number | null
};

export const computeUserEffectiveConfidenceLevel = (user: AuthUser) => {
  // if a user has BYPASS capability, we consider a level 100
  if (isBypassUser(user)) {
    return {
      max_confidence: 100,
      overrides: [],
      source: {
        type: 'Bypass',
      },
    };
  }

  // if user has a specific confidence level, it overrides everything and we return it
  if (user.user_confidence_level) {
    return {
      // we make sure the levels are cropped in between 0-100
      // other values were possibly injected in octi <6.0 though API calls
      max_confidence: cropNumber(user.user_confidence_level.max_confidence, 0, 100),
      overrides: (user.user_confidence_level.overrides ?? []).map((override) => ({
        max_confidence: cropNumber(override.max_confidence, 0, 100),
        entity_type: override.entity_type,
      })),
      source: {
        type: 'User',
        object: user,
      },
    };
  }

  // otherwise we get all groups for this user, and select the highest max_confidence found
  let maxLevel = null;
  let source = null;
  if (user.groups) {
    for (let i = 0; i < user.groups.length; i += 1) {
      // groups were not migrated when introducing group_confidence_level, so group_confidence_level might be null
      const groupLevel = user.groups[i].group_confidence_level?.max_confidence ?? null;
      if (groupLevel !== null && (maxLevel === null || groupLevel > maxLevel)) {
        maxLevel = groupLevel;
        source = {
          type: 'Group',
          object: user.groups[i]
        };
      }
    }
  }

  if (maxLevel !== null) {
    return {
      max_confidence: cropNumber(maxLevel, 0, 100),
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
    // using LockTimeoutError allows us to leverage the worker infinite auto-retry, so that connectors and feeds won't lose messages
    // this is a configuration error that might appear when upgrading to 6.X, but shall disappear in future when everyone has confidence level set up.
    throw LockTimeoutError({ user_id: user.id }, 'User has no effective max confidence level and cannot create this element');
  }
  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const inputConfidence = inputElement.confidence;
  const confidenceLevelToApply = capInputConfidenceWithUserMaxConfidence(userMaxConfidence, inputConfidence);
  return {
    confidenceLevelToApply,
  };
};

/**
 * Assert the confidence control on an input object during upsert operation.
 * Returns a flag to know if the confidences match properly, plus the confidence to apply on the resulting element.
 */
export const controlUpsertInputWithUserConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputElementOrPatch: T, existingElement: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw LockTimeoutError({ user_id: user.id, element_id: existingElement.id }, 'User has no effective max confidence level and cannot upsert this element');
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
 * Throw errors by default, use the flag noThrow to return a boolean instead (false in case of error).
 */
export const controlUserConfidenceAgainstElement = <T extends ObjectWithConfidence>(user: AuthUser, existingElement: T, noThrow = false) => {
  const hasConfidenceAttribute = schemaAttributesDefinition.getAttribute(existingElement.entity_type, 'confidence');
  if (!hasConfidenceAttribute) {
    return true; // no confidence to check, it's ok
  }

  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    if (noThrow) {
      return false;
    }
    throw LockTimeoutError({ user_id: user.id, element_id: existingElement.id }, 'User has no effective max confidence level and cannot update this element');
  }

  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const existing = cropNumber(existingElement.confidence ?? 0, 0, 100);
  const isConfidenceMatch = userMaxConfidence >= existing; // always true if no existingConfidence

  // contrary to upsert (where we might still update fields that were empty even if confidence control is negative)
  // a user cannot update an object without the right confidence
  if (!isConfidenceMatch) {
    if (noThrow) {
      return false;
    }
    throw FunctionalError('User effective max confidence level is insufficient to update this element', { user_id: user.id, element_id: existingElement.id });
  }

  return true; // ok
};

type UpdateInput = {
  key: string | string[]
  value: string[]
};

/**
 * Adapt the input data during an update operation, according to confidence control.
 *   1) If input contains a new confidence level, it is capped by user's level,
 *   2) if the element has no confidence, we make sure it has one after update (fallback to user's level)
 */
export const adaptUpdateInputsConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputs: UpdateInput | UpdateInput[], element: T) => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw LockTimeoutError({ user_id: user.id, element_id: element.id }, 'User has no effective max confidence level and cannot update this element');
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

/**
 * Narrow the input filter with a AND on the user's max confidence.
 * Result filter will filter out any element without the required confidence (+ input filter).
 */
export const adaptFiltersWithUserConfidence = (user: AuthUser, filters: FilterGroup): FilterGroup => {
  if (isEmptyField(user.effective_confidence_level?.max_confidence)) {
    throw LockTimeoutError({ user_id: user.id }, 'User has no effective max confidence level and cannot run this filter');
  }
  const userMaxConfidenceLevel = user.effective_confidence_level?.max_confidence as number;

  // we will filter to get only elements that have...
  // ... no confidence attribute (no control to do)
  const entitiesWithoutConfidence: Filter = {
    key: [
      'entity_type'
    ],
    operator: FilterOperator.NotEq,
    values: ['Stix-Domain-Object', 'Stix-Relationship'] // only types with confidence judging from schema
  };
  // ... a confidence level lower or equal to the user's level
  const userConfidenceFilter: Filter = {
    key: ['confidence'],
    operator: FilterOperator.Lte,
    values: [userMaxConfidenceLevel]
  };
  // ... or no confidence level at all (might happen when inserting data with the API with version <6.0, we consider zero)
  const nilConfidenceFilter: Filter = {
    key: ['confidence'],
    operator: FilterOperator.Nil,
    values: [],
  };
  const orFilterGroup: FilterGroup = {
    mode: FilterMode.Or,
    filters: [entitiesWithoutConfidence, userConfidenceFilter, nilConfidenceFilter,],
    filterGroups: [],
  };

  // nest: this filter AND the input filters
  return {
    mode: FilterMode.And,
    filters: [],
    filterGroups: isFilterGroupNotEmpty(filters) ? [orFilterGroup, filters] : [orFilterGroup],
  };
};
