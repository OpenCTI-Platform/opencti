import { buildStixObject, cleanObject } from '../../../database/stix-converter';
import type { StixJsonMapper, StoreEntityJsonMapper } from './jsonMapper-types';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

const convertJsonMapperToStix = (instance: StoreEntityJsonMapper): StixJsonMapper => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    representations: instance.representations,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertJsonMapperToStix;
