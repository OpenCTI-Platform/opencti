import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import { ENTITY_TYPE_CONTAINER_CASE_RFT, type Stix2CaseRft, type StixCaseRft, type StoreEntityCaseRft, type StoreEntityCaseRft2 } from './case-rft-types';
import { assertType, cleanObject, convertObjectReferences } from '../../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../../database/stix-2-0-converter';

export const convertCaseRftToStix_2_1 = (instance: StoreEntityCaseRft): StixCaseRft => {
  const caseRft = buildStixDomain(instance);
  return {
    ...caseRft,
    name: instance.name,
    description: instance.description,
    content: instance.content,
    content_mapping: instance.content_mapping,
    takedown_types: instance.takedown_types,
    severity: instance.severity,
    priority: instance.priority,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseRft.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const convertCaseRftToStix_2_0 = (instance: StoreEntityCaseRft2, type: string): Stix2CaseRft => {
  assertType(ENTITY_TYPE_CONTAINER_CASE_RFT, type);
  const caseRft = buildStixDomain2(instance);
  return {
    ...caseRft,
    name: instance.name,
    description: instance.description,
    severity: instance.severity,
    priority: instance.priority,
    takedown_types: instance.takedown_types,
    object_refs: convertObjectReferences(instance),
  };
};
