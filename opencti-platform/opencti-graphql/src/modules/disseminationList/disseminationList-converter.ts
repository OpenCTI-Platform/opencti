import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixDisseminationList, StoreEntityDisseminationList } from './disseminationList-types';

const convertDisseminationListToStix = (instance: StoreEntityDisseminationList): StixDisseminationList => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    emails: instance.emails,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertDisseminationListToStix;
