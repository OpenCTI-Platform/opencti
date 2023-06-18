import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import type { StixTaskTemplate, StoreEntityTaskTemplate } from './task-template-types';

const convertCaseTaskToStix = (instance: StoreEntityTaskTemplate): StixTaskTemplate => {
  const caseTask = buildStixDomain(instance);
  return {
    ...caseTask,
    name: instance.name,
    description: instance.description,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseTask.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertCaseTaskToStix;
