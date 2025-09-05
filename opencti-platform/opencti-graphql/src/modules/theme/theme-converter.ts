import { buildStixDomain } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixTheme, StoreEntityTheme } from './theme-types';

const convertThemeToStix = (instance: StoreEntityTheme): StixTheme => {
  const stixObject = buildStixDomain(instance);
  return {
    ...stixObject,
    name: instance.name,
    manifest: instance.manifest,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    },
  };
};

export default convertThemeToStix;
