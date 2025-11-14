import { buildStixObject } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { StixDecayExclusionRule, StoreEntityDecayExclusionRule } from './decayExclusionRule-types';
import { cleanObject } from '../../../database/stix-converter-utils';

const convertDecayExclusionRuleToStix = (instance: StoreEntityDecayExclusionRule): StixDecayExclusionRule => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    decay_exclusion_observable_types: instance.decay_exclusion_observable_types,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertDecayExclusionRuleToStix;
