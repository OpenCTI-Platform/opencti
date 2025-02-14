import { buildStixDomain, cleanObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixTheme, StoreEntityTheme } from './theme-types';

const convertThemeToStix = (instance: StoreEntityTheme): StixTheme => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    manifest: instance.manifest,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    },
  };
};

export default convertThemeToStix;
