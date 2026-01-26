import type { AuthUser } from '../types/user';
import { cropNumber } from './math';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { FunctionalError, INSUFFICIENT_CONFIDENCE_LEVEL } from '../config/errors';
import { logApp } from '../config/conf';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { isBypassUser } from './access';
import type { Group } from '../types/group';
import { RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT_LABEL } from '../schema/stixRefRelationship';
import { INPUT_EXTERNAL_REFS, INPUT_LABELS } from '../schema/general';

type ObjectWithConfidence = {
  id: string;
  entity_type: string;
  confidence?: number | null;
};

type ConfidenceSource = {
  type: 'Group' | 'User' | 'Bypass';
  object: Group | AuthUser | null;
};

type ConfidenceOverride = {
  entity_type: string;
  max_confidence: number;
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

  // otherwise we get all groups for this user, and select the highest max_confidence found
  let maxLevel = null;
  let source: ConfidenceSource | null = null;
  const overridesMap = new Map<string, { max_confidence: number; source: ConfidenceSource }>();
  if (user.groups) {
    for (let i = 0; i < user.groups.length; i += 1) {
      // groups were not migrated when introducing group_confidence_level, so group_confidence_level might be null
      const groupLevel = user.groups[i].group_confidence_level?.max_confidence ?? null;
      if (groupLevel !== null && (maxLevel === null || groupLevel > maxLevel)) {
        maxLevel = groupLevel;
        source = {
          type: 'Group',
          object: user.groups[i],
        };
      }
      const groupOverrides = user.groups[i].group_confidence_level?.overrides ?? [];
      for (let j = 0; j < groupOverrides.length; j += 1) {
        const { entity_type, max_confidence } = groupOverrides[j];
        if (!overridesMap.has(entity_type) || (overridesMap.get(entity_type)?.max_confidence ?? 0) < max_confidence) {
          overridesMap.set(entity_type, { max_confidence, source: { object: user.groups[i], type: 'Group' } });
        }
      }
    }
  }

  if (isNotEmptyField(user.user_confidence_level?.max_confidence)) {
    maxLevel = user.user_confidence_level?.max_confidence;
    // source only tells where max_confidence comes, not the overrides (TODO: add sources for each override?)
    source = { type: 'User', object: user };
    // discard any overrides info from the group, user definition takes priority over groups
    overridesMap.clear();
  }

  if (isNotEmptyField(user.user_confidence_level?.overrides) && user.user_confidence_level?.overrides) {
    // for each user override, overridesMap.set
    (user.user_confidence_level.overrides as ConfidenceOverride[]).forEach(({ entity_type, max_confidence }) => {
      // user's overrides overwrite any override set at the groups level
      overridesMap.set(entity_type, { max_confidence, source: { object: user, type: 'User' } });
    });
  }

  // turn map into array
  const overrides = Array.from(overridesMap.entries())
    .map(([key, value]) => ({ entity_type: key, max_confidence: value.max_confidence, source: value.source }));

  // note that a user cannot have only overrides
  if (isEmptyField(maxLevel)) {
    return null;
  }

  return {
    max_confidence: cropNumber(maxLevel as number, 0, 100),
    overrides,
    source,
  };
};

const capInputConfidenceWithUserMaxConfidence = (overrideMaxConfidence: number, inputConfidence?: number | null) => {
  const input = cropNumber(inputConfidence ?? 100, 0, 100); // input always untrusted, crop in 0-100
  return Math.min(overrideMaxConfidence, input); // will always equal userMaxConfidence if no inputConfidence
};

/**
 * Assert the confidence control on an input object from create operations
 * Returns the confidence to apply on the resulting element.
 */
export const controlCreateInputWithUserConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputElement: T, type: string) => {
  const hasMaxConfidence = isNotEmptyField(user.effective_confidence_level?.max_confidence);
  const override = user.effective_confidence_level?.overrides?.find((e) => e.entity_type === type);
  if (!hasMaxConfidence && !override) {
    throw FunctionalError('User has no effective max confidence level and cannot create this element', { user_id: user.id });
  }
  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const overrideMaxConfidence = override?.max_confidence ?? userMaxConfidence;
  const inputConfidence = inputElement.confidence;
  const confidenceLevelToApply = capInputConfidenceWithUserMaxConfidence(overrideMaxConfidence, inputConfidence);
  return {
    confidenceLevelToApply,
  };
};

/**
 * Assert the confidence control on an input object during upsert operation.
 * Returns a flag to know if the confidences match properly, plus the confidence to apply on the resulting element.
 */
export const controlUpsertInputWithUserConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputElementOrPatch: T, existingElement: T) => {
  const hasMaxConfidence = isNotEmptyField(user.effective_confidence_level?.max_confidence);
  const override = user.effective_confidence_level?.overrides?.find((e) => e.entity_type === existingElement.entity_type);
  if (!hasMaxConfidence && !override) {
    throw FunctionalError('User has no effective max confidence level and cannot upsert this element', { user_id: user.id, element_id: existingElement.id });
  }
  const userMaxConfidence = user.effective_confidence_level?.max_confidence;
  const overrideMaxConfidence = (override?.max_confidence ?? userMaxConfidence) as number; // thanks to our if clause, we know one of them is defined
  const confidenceLevelToApply = capInputConfidenceWithUserMaxConfidence(overrideMaxConfidence, inputElementOrPatch.confidence);
  const existingConfidenceLevel = cropNumber(existingElement.confidence ?? 0, 0, 100);
  const isConfidenceMatch = confidenceLevelToApply >= existingConfidenceLevel; // always true if no existingConfidence
  const isConfidenceUpper = confidenceLevelToApply > existingConfidenceLevel;

  return {
    confidenceLevelToApply,
    isConfidenceMatch,
    isConfidenceUpper,
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

  const hasMaxConfidence = isNotEmptyField(user.effective_confidence_level?.max_confidence);
  const override = user.effective_confidence_level?.overrides?.find((e) => e.entity_type === existingElement.entity_type);
  if (!hasMaxConfidence && !override) {
    if (noThrow) {
      return false;
    }
    throw FunctionalError('User has no effective max confidence level and cannot update this element', { user_id: user.id, element_id: existingElement.id });
  }

  const userMaxConfidence = user.effective_confidence_level?.max_confidence as number;
  const overrideMaxConfidence = override?.max_confidence ?? userMaxConfidence;
  const existingConfidenceLevel = cropNumber(existingElement.confidence ?? 0, 0, 100);
  const isConfidenceMatch = overrideMaxConfidence >= existingConfidenceLevel; // always true if no existingConfidence

  // contrary to upsert (where we might still update fields that were empty even if confidence control is negative)
  // a user cannot update an object without the right confidence
  if (!isConfidenceMatch) {
    if (noThrow) {
      return false;
    }
    const data = { user_id: user.id, element_id: existingElement.id, doc_code: INSUFFICIENT_CONFIDENCE_LEVEL };
    throw FunctionalError('User effective max confidence level is insufficient to update this element', data);
  }

  return true; // ok
};

type UpdateInput = {
  key: string | string[];
  value: string[];
};

/**
 * Adapt the input data during an update operation, according to confidence control.
 *   1) If input contains a new confidence level, it is capped by user's level,
 *   2) if the element has no confidence, we make sure it has one after update (fallback to user's level)
 */
export const adaptUpdateInputsConfidence = <T extends ObjectWithConfidence>(user: AuthUser, inputs: UpdateInput | UpdateInput[], element: T) => {
  const hasMaxConfidence = isNotEmptyField(user.effective_confidence_level?.max_confidence);
  const override = user.effective_confidence_level?.overrides?.find((e) => e.entity_type === element.entity_type);
  if (!hasMaxConfidence && !override) {
    throw FunctionalError('User has no effective max confidence level and cannot update this element', { user_id: user.id, element_id: element.id });
  }
  const inputsArray = Array.isArray(inputs) ? inputs : [inputs];
  const userMaxConfidenceLevel = user.effective_confidence_level?.max_confidence as number;
  const overrideMaxConfidence = override?.max_confidence ?? userMaxConfidenceLevel;
  let hasConfidenceInput = false;

  // cap confidence change with user's confidence
  const newInputs = inputsArray.map((input) => {
    const keysArray = Array.isArray(input.key) ? input.key : [input.key];
    if (keysArray.includes('confidence')) {
      const newValue = parseInt(input.value[0], 10);
      if (overrideMaxConfidence < newValue) {
        logApp.info('Object confidence cannot be updated above user\'s max confidence level, the value has been capped.', { user_id: user.id, element_id: element.id });
      }
      hasConfidenceInput = true;
      return {
        ...input,
        value: [Math.min(overrideMaxConfidence, newValue).toString()],
      };
    }
    return input;
  });

  // if the initial element does not have any confidence prior to this update, and we are not setting one now
  // then we force the element confidence to the user's confidence
  const hasConfidenceAttribute = schemaAttributesDefinition.getAttribute(element.entity_type, 'confidence');
  if (hasConfidenceAttribute && isEmptyField(element.confidence) && inputsArray.length > 0 && !hasConfidenceInput) {
    newInputs.push({ key: 'confidence', value: [overrideMaxConfidence.toString()] });
  }

  return newInputs;
};

/**
 * Determine if a ref relationship is concerned by confidence level.
 * A user can add external references and labels even with a lower confidence level.
 *
 * @param refType The type of the ref relationship
 * @returns True if the confidence should be checked on the ref.
 */
export const shouldCheckConfidenceOnRefRelationship = (refType: string) => {
  const checkRelationRef = ![RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT_LABEL].includes(refType);
  const checkInputRefName = ![INPUT_EXTERNAL_REFS, INPUT_LABELS].includes(refType);
  return checkInputRefName && checkRelationRef;
};
