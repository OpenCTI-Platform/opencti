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
    severity: instance.severity,
    priority: instance.priority,
    information_types: instance.information_types,
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
