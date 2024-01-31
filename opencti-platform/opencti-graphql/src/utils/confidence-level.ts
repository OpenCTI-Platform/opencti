import type { AuthUser } from '../types/user';
import { cropNumber } from './math';

export const computeUserEffectiveConfidenceLevel = (user: AuthUser) => {
  // if user has a specific confidence level, it overrides everything and we return it
  if (user.user_confidence_level) {
    return {
      // we make sure the levels are cropped in between 0-100
      // other values were possibly injected in octi <6.0 though API calls
      max_confidence: cropNumber(user.user_confidence_level.max_confidence, { min: 0, max: 100 }),
      overrides: user.user_confidence_level.overrides.map((override) => ({
        max_confidence: cropNumber(override.max_confidence, { min: 0, max: 100 }),
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
      max_confidence: cropNumber(minLevel, { min: 0, max: 100 }),
      // TODO: handle overrides and their sources
      overrides: [],
      source,
    };
  }

  // finally, if this user has no effective confidence level, we can return null
  return null;
};
