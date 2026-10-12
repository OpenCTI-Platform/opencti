import { buildStixObject } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { cleanObject } from '../../../database/stix-converter-utils';
import type { StixDefenseGap, StoreEntityDefenseGap } from './defenseGap-types';

const convertDefenseGapToStix = (instance: StoreEntityDefenseGap): StixDefenseGap => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    attack_pattern_id: instance.attack_pattern_id,
    platform_id: instance.platform_id,
    level: instance.level,
    recommended_action: instance.recommended_action,
    status: instance.status,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertDefenseGapToStix;
