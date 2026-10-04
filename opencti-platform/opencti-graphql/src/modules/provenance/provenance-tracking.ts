import type { AuthContext } from '../../types/user';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';
import { getAvailableSettings, getEntitySettingFromCache } from '../entitySetting/entitySetting-utils';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { getParentTypes } from '../../schema/schemaUtils';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
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

/**
 * Provenance tracking of the entity type of a setting: its explicit value, otherwise the platform default.
 */
export const isProvenanceTrackingEnabled = (entitySetting: Pick<BasicStoreEntityEntitySetting, 'target_type' | 'provenance_tracking'>) => {
  if (!isProvenanceTrackingAvailable(entitySetting.target_type)) {
    return false;
  }
  return entitySetting.provenance_tracking ?? isProvenanceTrackedByDefault(entitySetting.target_type);
};

/**
 * Provenance tracking of an element type (cache only), inherited from its abstract type setting when it has none.
 */
export const isProvenanceTrackedForType = async (context: AuthContext, entityType: string) => {
  const entitySetting = await getEntitySettingFromCache(context, entityType);
  return entitySetting ? isProvenanceTrackingEnabled(entitySetting) : isProvenanceTrackedByDefault(entityType);
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
