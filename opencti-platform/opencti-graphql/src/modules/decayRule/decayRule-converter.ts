import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixDecayRule, StoreEntityDecayRule } from './decayRule-types';

const convertDecayRuleToStix = (instance: StoreEntityDecayRule): StixDecayRule => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    decay_lifetime: instance.decay_lifetime,
    decay_points: instance.decay_points,
    decay_pound: instance.decay_pound,
    decay_revoke_score: instance.decay_revoke_score,
    decay_observable_types: instance.decay_observable_types,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertDecayRuleToStix;
