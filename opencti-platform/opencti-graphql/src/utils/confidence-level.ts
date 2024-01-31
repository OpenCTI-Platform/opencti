import { cropNumber } from './math';
import type { ConfidenceLevelInput, ConfidenceLevelOverrideInput } from '../generated/graphql';
import { FunctionalError } from '../config/errors';
import type { AuthUser } from '../types/user';

type EditInputValue = number | ConfidenceLevelInput | ConfidenceLevelOverrideInput;

export const cropMaxConfidenceInEditValue = (value: EditInputValue, object_path?: string) => {
  let sanitizedValue = value;

  // edited as object_path patching, value might be different depending on the path
  if (object_path) {
    // using regexp to accommodate for the optional presence of a leading "/" in object_path
    if (/(user|group)_confidence_level\/max_confidence$/.test(object_path)) {
      // object_path ~= "user_confidence_level/max_confidence", value is supposedly a number
      sanitizedValue = cropNumber(value as number, { min: 0, max: 100 });
    } else if (/\/overrides\/(\d+)$/.test(object_path)) {
      // object_path ~= "user_confidence_level/overrides/[n]", value is a ConfidenceLevelOverrideInput
      sanitizedValue = {
        entity_type: (value as ConfidenceLevelOverrideInput).entity_type,
        max_confidence: cropNumber((value as ConfidenceLevelOverrideInput).max_confidence, { min: 0, max: 100 }),
      };
    } else if (/\/overrides\/(\d+)\/max_confidence$/.test(object_path)) {
      // object_path ~= "user_confidence_level/overrides/[n]/max_confidence", value is a number
      sanitizedValue = cropNumber((value as number), { min: 0, max: 100 });
    } else {
      throw FunctionalError('Unhandled object_path for patching a confidence level', { object_path, value });
    }
  } else if ((value as ConfidenceLevelInput).max_confidence !== undefined) {
    // edited as full object, value is a ConfidenceLevelInput
    sanitizedValue = {
      max_confidence: cropNumber((value as ConfidenceLevelInput).max_confidence, { min: 0, max: 100 }),
      overrides: (value as ConfidenceLevelInput).overrides.map((override) => ({
        entity_type: override.entity_type,
        max_confidence: cropNumber(override.max_confidence, { min: 0, max: 100 })
      }))
    };
  }

  return sanitizedValue;
};

export const computeUserEffectiveConfidenceLevel = (user: AuthUser) => {
  // if user has a specific confidence level, it overrides everything and we return it
  if (user.user_confidence_level) {
    return {
      ...user.user_confidence_level,
      source: user,
    };
  }

  // otherwise we get all groups for this user, and select the lowest max_confidence found
  let minLevel = null;
  let source = null;
  if (user.groups) {
    for (let i = 0; i < user.groups.length; i += 1) {
      const groupLevel = user.groups[i].group_confidence_level?.max_confidence ?? null;
      if (minLevel === null || (groupLevel !== null && groupLevel < minLevel)) {
        minLevel = groupLevel;
        source = user.groups[i];
      }
    }
  }

  if (minLevel !== null) {
    return {
      max_confidence: cropNumber(minLevel, { min: 0, max: 100 }),
      // TODO: handle overrides and their sources
      overrides: [],
      source,
    };
  }

  // finally, if this user has no effective confidence level, we can return null
  return null;
};
