import type { StixDataSource, StoreEntityDataSource } from './dataSource-types';
import { buildMITREExtensions, buildStixDomain } from '../../database/stix-converter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixMitreExtension } from '../../types/stix-common';

const convertDataSourceToStix = (instance: StoreEntityDataSource): StixDataSource => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.aliases,
    dataComponent: instance.dataComponent,
    extensions: {
      [STIX_EXT_OCTI]: stixDomainObject.extensions[STIX_EXT_OCTI],
      [STIX_EXT_MITRE]: {
        ...buildMITREExtensions(instance),
        extension_type: 'new-sdo',
      } as StixMitreExtension
    }
  };
};

export default convertDataSourceToStix;
