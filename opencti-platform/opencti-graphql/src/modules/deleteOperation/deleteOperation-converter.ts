import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixDeleteOperation, StoreEntityDeleteOperation } from './deleteOperation-types';

const convertDeleteOperationToStix = (instance: StoreEntityDeleteOperation): StixDeleteOperation => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    main_entity_type: instance.main_entity_type,
    main_entity_id: instance.main_entity_id,
    main_entity_name: instance.main_entity_name,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertDeleteOperationToStix;
