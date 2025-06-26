import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import { ENTITY_TYPE_CONTAINER_CASE_RFI, type Stix2CaseRfi, type StixCaseRfi, type StoreEntityCaseRfi, type StoreEntityCaseRfi2 } from './case-rfi-types';
import { assertType, cleanObject, convertObjectReferences } from '../../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../../database/stix-2-0-converter';

export const convertCaseRfiToStix_2_1 = (instance: StoreEntityCaseRfi): StixCaseRfi => {
  const caseRfi = buildStixDomain(instance);
  return {
    ...caseRfi,
    name: instance.name,
    description: instance.description,
    content: instance.content,
    content_mapping: instance.content_mapping,
    information_types: instance.information_types,
    severity: instance.severity,
    priority: instance.priority,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseRfi.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const convertCaseRfiToStix_2_0 = (instance: StoreEntityCaseRfi2, type: string): Stix2CaseRfi => {
  assertType(ENTITY_TYPE_CONTAINER_CASE_RFI, type);
  const caseRFI = buildStixDomain2(instance);
  return {
    ...caseRFI,
    name: instance.name,
    description: instance.description,
    severity: instance.severity,
    priority: instance.priority,
    information_types: instance.information_types,
    object_refs: convertObjectReferences(instance),
  };
};
