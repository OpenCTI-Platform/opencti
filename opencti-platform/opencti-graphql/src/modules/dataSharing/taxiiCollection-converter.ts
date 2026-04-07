import type { StixTaxiiCollection, StoreEntityTaxiiCollection } from './taxiiCollection-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertTaxiiCollectionToStix = (instance: StoreEntityTaxiiCollection): StixTaxiiCollection => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    filters: instance.filters,
    taxii_public: instance.taxii_public,
    taxii_public_user_id: instance.taxii_public_user_id,
    include_inferences: instance.include_inferences,
    score_to_confidence: instance.score_to_confidence,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertTaxiiCollectionToStix;
