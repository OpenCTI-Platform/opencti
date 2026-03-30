import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import type { StixCustomView, StoreEntityCustomView } from './customView-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertCustomViewToStix = (instance: StoreEntityCustomView): StixCustomView => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    path: instance.path,
    description: instance.description,
    manifest: instance.manifest,
    target_entity_type: instance.target_entity_type,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertCustomViewToStix;
