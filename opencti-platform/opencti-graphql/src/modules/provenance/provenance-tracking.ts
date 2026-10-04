import type { AuthContext } from '../../types/user';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';
import { getAvailableSettings, getEntitySettingFromCache } from '../entitySetting/entitySetting-utils';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { getParentTypes } from '../../schema/schemaUtils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { PROVENANCE_DEFAULT_TRACKED_TYPES } from './provenance-config';

// Entity setting enabling provenance tracking (sources, corroboration, conflicts, freshness) per entity type.
export const ENTITY_SETTING_PROVENANCE_TRACKING = 'provenance_tracking';

export const isProvenanceTrackedByDefault = (entityType: string) => {
  return PROVENANCE_DEFAULT_TRACKED_TYPES.includes('*') || PROVENANCE_DEFAULT_TRACKED_TYPES.includes(entityType);
};

const isProvenanceTrackingAvailable = (entityType: string) => {
  try {
    return getAvailableSettings(entityType).includes(ENTITY_SETTING_PROVENANCE_TRACKING);
  } catch {
    return false;
  }
};

type TrackingSetting = Pick<BasicStoreEntityEntitySetting, 'target_type' | 'provenance_tracking'>;

/**
 * Provenance tracking of a type under its own setting or under the setting of its abstract type: an explicit value
 * wins; otherwise the platform default of the type itself, or of the abstract type when the defaults list it.
 */
export const isProvenanceTrackedUnderSetting = (entitySetting: TrackingSetting, entityType: string) => {
  if (!isProvenanceTrackingAvailable(entitySetting.target_type)) {
    return false;
  }
  return entitySetting.provenance_tracking ?? (isProvenanceTrackedByDefault(entityType) || isProvenanceTrackedByDefault(entitySetting.target_type));
};

/**
 * Provenance tracking of the entity type of a setting: its explicit value, otherwise the platform default.
 */
export const isProvenanceTrackingEnabled = (entitySetting: TrackingSetting) => {
  return isProvenanceTrackedUnderSetting(entitySetting, entitySetting.target_type);
};

/**
 * Provenance tracking of an element type (cache only), inherited from its abstract type setting when it has none.
 */
export const isProvenanceTrackedForType = async (context: AuthContext, entityType: string) => {
  const entitySetting = await getEntitySettingFromCache(context, entityType);
  return entitySetting ? isProvenanceTrackedUnderSetting(entitySetting, entityType) : isProvenanceTrackedByDefault(entityType);
};

// Concrete types whose provenance tracking follows the setting of an abstract type when they have no setting of their own
const typesInheritingSetting = (targetType: string): string[] => {
  if (targetType === ABSTRACT_STIX_CORE_RELATIONSHIP) {
    return [...STIX_CORE_RELATIONSHIPS];
  }
  if (targetType === ABSTRACT_STIX_CYBER_OBSERVABLE) {
    return [...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE)];
  }
  return [targetType];
};

/**
 * Types governed by a setting whose provenance is not tracked: the type of the setting, or the concrete types that
 * inherit it (a concrete type with a setting of its own is governed by that one), with the same rule as the write path.
 */
export const listProvenanceUntrackedTypesOfSetting = async (context: AuthContext, entitySetting: TrackingSetting) => {
  if (!isProvenanceTrackingAvailable(entitySetting.target_type)) {
    return [];
  }
  const governed = typesInheritingSetting(entitySetting.target_type);
  const untracked: string[] = [];
  for (let index = 0; index < governed.length; index += 1) {
    const type = governed[index];
    const governing = type === entitySetting.target_type ? entitySetting : await getEntitySettingFromCache(context, type);
    const isGovernedHere = !governing || governing.target_type === entitySetting.target_type;
    if (isGovernedHere && !isProvenanceTrackedUnderSetting(entitySetting, type)) {
      untracked.push(type);
    }
  }
  return untracked;
};

/**
 * Concrete entity, observable, relationship and sighting types whose provenance is tracked.
 */
export const listProvenanceTrackedTypes = async (context: AuthContext) => {
  const candidates = [
    ...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT),
    ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE),
    ...STIX_CORE_RELATIONSHIPS,
    STIX_SIGHTING_RELATIONSHIP,
  ];
  const tracked: string[] = [];
  for (let index = 0; index < candidates.length; index += 1) {
    if (await isProvenanceTrackedForType(context, candidates[index])) {
      tracked.push(candidates[index]);
    }
  }
  return tracked;
};

/**
 * The given types whose provenance is tracked, an abstract type standing for its tracked concrete types.
 */
export const restrictToTrackedTypes = (types: string[], trackedTypes: string[]) => {
  const tracked = new Set(trackedTypes);
  return [...new Set(types.flatMap((type) => (tracked.has(type)
    ? [type]
    : trackedTypes.filter((candidate) => (getParentTypes(candidate) as string[]).includes(type)))))];
};
