import type { StixDataSource, StoreEntityDataSource } from './dataSource-types';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';

const convertDataSourceToStix = (instance: StoreEntityDataSource): StixDataSource => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    platforms: instance.x_mitre_platforms,
    collection_layers: instance.collection_layers,
    aliases: instance.aliases,
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

export default convertDataSourceToStix;
