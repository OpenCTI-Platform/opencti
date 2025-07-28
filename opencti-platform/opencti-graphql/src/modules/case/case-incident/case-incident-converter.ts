import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import {
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  type Stix2CaseIncident,
  type StixCaseIncident,
  type StoreEntityCaseIncident,
  type StoreEntityCaseIncident2
} from './case-incident-types';
import { assertType, cleanObject } from '../../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../../database/stix-2-0-converter';

export const convertCaseIncidentToStix_2_1 = (instance: StoreEntityCaseIncident): StixCaseIncident => {
  const caseIncident = buildStixDomain(instance);
  return {
    ...caseIncident,
    name: instance.name,
    description: instance.description,
    content: instance.content,
    content_mapping: instance.content_mapping,
    severity: instance.severity,
    priority: instance.priority,
    response_types: instance.response_types,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseIncident.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertCaseIncidentToStix_2_0 = (instance: StoreEntityCaseIncident): Stix2CaseIncident => {
  assertType(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, instance.entity_type);
  const caseIncident = buildStixDomain2(instance);
  return {
    ...caseIncident,
    name: instance.name,
    description: instance.description,
    severity: instance.severity,
    priority: instance.priority,
    response_types: instance.response_types,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
  };
};
