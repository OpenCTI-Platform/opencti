import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixAuthenticationProvider, StoreEntityAuthenticationProvider } from './authenticationProvider-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertAuthenticationProviderToStix = (instance: StoreEntityAuthenticationProvider): StixAuthenticationProvider => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    enabled: instance.enabled,
    type: instance.type,
    button_label_override: instance.button_label_override,
    identifier_override: instance.identifier_override,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertAuthenticationProviderToStix;
