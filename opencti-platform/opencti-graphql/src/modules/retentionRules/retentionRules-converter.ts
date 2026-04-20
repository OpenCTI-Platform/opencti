import type { StixRetentionRule, StoreEntityRetentionRule } from './retentionRules-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertRetentionRuleToStix = (instance: StoreEntityRetentionRule): StixRetentionRule => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    filters: instance.filters,
    max_retention: instance.max_retention,
    retention_unit: instance.retention_unit,
    scope: instance.scope,
    last_execution_date: instance.last_execution_date,
    last_deleted_count: instance.last_deleted_count,
    remaining_count: instance.remaining_count,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertRetentionRuleToStix;
