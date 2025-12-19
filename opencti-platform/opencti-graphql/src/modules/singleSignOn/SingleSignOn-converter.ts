import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixSingleSignOn, StoreEntitySingleSignOn } from './SingleSignOn-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertSingleSignOnToStix = (instance: StoreEntitySingleSignOn): StixSingleSignOn => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    enabled: instance.enabled,
    strategy: instance.strategy,
    label: instance.label,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  }
}

export default convertSingleSignOnToStix;