import { buildStixDomain } from '../../database/stix-converter';
import type { StixDataComponent, StoreEntityDataComponent } from './dataComponent-types';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixMitreExtension } from '../../types/stix-common';

const convertDataComponentToStix = (instance: StoreEntityDataComponent): StixDataComponent => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases,
    dataSource: instance.dataSource,
    extensions: {
      [STIX_EXT_OCTI]: stixDomainObject.extensions[STIX_EXT_OCTI],
      [STIX_EXT_MITRE]: {
        extension_type: 'new-sdo'
      } as StixMitreExtension
    }
  };
};

export default convertDataComponentToStix;
