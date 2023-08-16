import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixPlaybook, StoreEntityPlaybook } from './playbook-types';

const convertEntityPlaybookToStix = (instance: StoreEntityPlaybook): StixPlaybook => {
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

export default convertEntityPlaybookToStix;
