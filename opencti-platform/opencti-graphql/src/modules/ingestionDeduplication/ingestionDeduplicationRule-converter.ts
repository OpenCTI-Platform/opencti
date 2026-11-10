import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixIngestionDeduplicationRule, StoreEntityIngestionDeduplicationRule } from './ingestionDeduplicationRule-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertIngestionDeduplicationRuleToStix = (instance: StoreEntityIngestionDeduplicationRule): StixIngestionDeduplicationRule => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    user_id: instance.user_id,
    target_type: instance.target_type,
    excluded_fields: instance.excluded_fields,
    ttl: instance.ttl,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertIngestionDeduplicationRuleToStix;
