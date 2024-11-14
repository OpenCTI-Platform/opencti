import type { StixExclusionList, StoreEntityExclusionList } from './exclusionList-types';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

const convertExclusionListToStix = (instance: StoreEntityExclusionList): StixExclusionList => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    list_entity_types: instance.list_entity_types,
    file_id: instance.file_id,
    enabled: instance.enabled,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertExclusionListToStix;
