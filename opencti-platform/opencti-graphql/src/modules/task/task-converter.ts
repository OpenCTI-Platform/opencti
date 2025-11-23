import { buildStixDomain } from '../../database/stix-2-1-converter';
import { INPUT_CREATED_BY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { ENTITY_TYPE_CONTAINER_TASK, type Stix2Task, type StixTask, type StoreEntityTask } from './task-types';
import { assertType, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

export const convertCaseTaskToStix_2_1 = (instance: StoreEntityTask): StixTask => {
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

export const convertTaskToStix_2_0 = (instance: StoreEntityTask): Stix2Task => {
  assertType(ENTITY_TYPE_CONTAINER_TASK, instance.entity_type);
  const task = buildStixDomain2(instance);
  return {
    ...task,
    name: instance.name,
    description: instance.description,
    due_date: convertToStixDate(instance.due_date),
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    object_refs: convertObjectReferences(instance)
  };
};
