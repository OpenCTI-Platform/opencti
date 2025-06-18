import type { StixPir, StoreEntityPir } from './pir-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertEntityPirToStix = (instance: StoreEntityPir): StixPir => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertEntityPirToStix;
