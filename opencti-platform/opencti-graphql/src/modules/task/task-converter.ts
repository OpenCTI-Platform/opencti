import { buildStixDomain, cleanObject, convertObjectReferences } from '../../database/stix-converter';
import { INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixTask, StoreEntityTask } from './task-types';

const convertCaseTaskToStix = (instance: StoreEntityTask): StixTask => {
  const caseTask = buildStixDomain(instance);
  return {
    ...caseTask,
    name: instance.name,
    description: instance.description,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseTask.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        object_refs_inferred: convertObjectReferences(instance, true),
      })
    }
  };
};

export default convertCaseTaskToStix;
