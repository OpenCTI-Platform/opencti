import type { StixStreamCollection, StoreEntityStreamCollection } from './streamCollection-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertStreamCollectionToStix = (instance: StoreEntityStreamCollection): StixStreamCollection => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    filters: instance.filters,
    stream_public: instance.stream_public,
    stream_public_user_id: instance.stream_public_user_id,
    stream_live: instance.stream_live,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertStreamCollectionToStix;
