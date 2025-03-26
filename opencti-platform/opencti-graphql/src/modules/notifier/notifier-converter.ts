import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-2-1-converter';
import type { StixNotifier, StoreEntityNotifier } from './notifier-types';

export const convertNotifierToStix = (instance: StoreEntityNotifier): StixNotifier => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
