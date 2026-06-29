import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import type { StixDataSanityConfiguration, StoreEntityDataSanityConfiguration } from './dataSanityConfiguration-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertDataSanityConfigurationToStix = (instance: StoreEntityDataSanityConfiguration): StixDataSanityConfiguration => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    maintenance_planning: instance.maintenance_planning,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertDataSanityConfigurationToStix;
