import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixIntelligenceRequirement, StoreEntityIntelligenceRequirement } from './intelligenceRequirement-types';

const convertIntelligenceRequirementToStix = (instance: StoreEntityIntelligenceRequirement): StixIntelligenceRequirement => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertIntelligenceRequirementToStix;
