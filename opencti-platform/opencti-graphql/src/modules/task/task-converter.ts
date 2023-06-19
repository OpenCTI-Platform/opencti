import { buildStixDomain, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-converter';
import { INPUT_CREATED_BY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixTask, StoreEntityTask } from './task-types';

const convertCaseTaskToStix = (instance: StoreEntityTask): StixTask => {
  const task = buildStixDomain(instance);
  return {
    ...task,
    name: instance.name,
    description: instance.description,
    due_date: convertToStixDate(instance.due_date),
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...task.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        object_refs_inferred: convertObjectReferences(instance, true),
      })
    }
  };
};

export default convertCaseTaskToStix;
