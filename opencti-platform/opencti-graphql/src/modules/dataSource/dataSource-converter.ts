import type { Stix2DataSource, StixDataSource, StoreEntityDataSource } from './dataSource-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

export const convertDataSourceToStix_2_1 = (instance: StoreEntityDataSource): StixDataSource => {
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
      },
    },
  };
};

export const convertDataSourceToStix_2_0 = (instance: StoreEntityDataSource): Stix2DataSource => {
  assertType(ENTITY_TYPE_DATA_SOURCE, instance.entity_type);
  const dataSource = buildStixDomain2(instance);
  return {
    ...dataSource,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases ?? [],
    x_mitre_platforms: instance.x_mitre_platforms ?? [],
    x_mitre_collection_layers: instance.collection_layers ?? [],
  };
};
