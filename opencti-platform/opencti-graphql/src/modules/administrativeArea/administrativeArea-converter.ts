import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import type { StixAdministrativeArea, StoreEntityAdministrativeArea } from './administrativeArea-types';

const convertAdministrativeAreaToStix = (instance: StoreEntityAdministrativeArea): StixAdministrativeArea => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.x_opencti_aliases ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertAdministrativeAreaToStix;
