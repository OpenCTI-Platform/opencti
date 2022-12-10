import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import type { StixDataComponent, StoreEntityDataComponent } from './dataComponent-types';
import { INPUT_DATA_SOURCE } from './dataComponent-types';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';

const convertDataComponentToStix = (instance: StoreEntityDataComponent): StixDataComponent => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases,
    data_source_ref: instance[INPUT_DATA_SOURCE]?.standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'property-extension',
      }),
      [STIX_EXT_MITRE]: {
        extension_type: 'new-sdo',
      }
    }
  };
};

export default convertDataComponentToStix;
