import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import type { StixCaseIncident, StoreEntityCaseIncident } from './case-incident-types';

const convertCaseIncidentToStix = (instance: StoreEntityCaseIncident): StixCaseIncident => {
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
      })
    }
  };
};

export default convertCaseIncidentToStix;
