import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import type { StixCustomView, StoreEntityCustomView } from './customView-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertCustomViewToStix = (instance: StoreEntityCustomView): StixCustomView => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    manifest: instance.manifest,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertCustomViewToStix;
