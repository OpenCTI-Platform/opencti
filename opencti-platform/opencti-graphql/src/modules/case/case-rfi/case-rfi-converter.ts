import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import type { StixCaseRfi, StoreEntityCaseRfi } from './case-rfi-types';

const convertCaseRfiToStix = (instance: StoreEntityCaseRfi): StixCaseRfi => {
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

export default convertCaseRfiToStix;
