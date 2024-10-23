import { buildStixObject, cleanObject } from '../../../database/stix-converter';
import type { StixCsvMapper, StoreEntityCsvMapper } from './csvMapper-types';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

const convertCsvMapperToStix = (instance: StoreEntityCsvMapper): StixCsvMapper => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    has_header: instance.has_header,
    separator: instance.separator,
    representations: instance.representations,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertCsvMapperToStix;
