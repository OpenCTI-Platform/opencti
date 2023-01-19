import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT
} from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { isStixDomainObject } from '../../schema/stixDomainObject';
import { UnsupportedError } from '../../config/errors';

export const defaultEntitySetting: Record<string, () => boolean> = {
  platform_entity_files_ref: () => false,
  platform_hidden_type: () => false,
  enforce_reference: () => false,
};

export const availableSettings: Record<string, Array<string>> = {
  [ABSTRACT_STIX_DOMAIN_OBJECT]: ['platform_entity_files_ref', 'platform_hidden_type', 'enforce_reference'],
  [ABSTRACT_STIX_CYBER_OBSERVABLE]: ['platform_entity_files_ref'],
  [ABSTRACT_STIX_CORE_RELATIONSHIP]: ['enforce_reference'],
  [STIX_SIGHTING_RELATIONSHIP]: ['platform_entity_files_ref'],
};

export const getAvailableSettings = (targetType: string) => {
  let settings;
  if (isStixDomainObject(targetType)) {
    settings = availableSettings[ABSTRACT_STIX_DOMAIN_OBJECT];
  } else {
    settings = availableSettings[targetType];
  }

  if (!settings) {
    throw UnsupportedError('This entity type is not support for entity settings', { target_type: targetType });
  }

  return settings;
};
