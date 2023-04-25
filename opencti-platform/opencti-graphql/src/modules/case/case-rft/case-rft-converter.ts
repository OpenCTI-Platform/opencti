import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import type { StixCaseRft, StoreEntityCaseRft } from './case-rft-types';

const convertCaseRftToStix = (instance: StoreEntityCaseRft): StixCaseRft => {
  const caseRft = buildStixDomain(instance);
  return {
    ...caseRft,
    name: instance.name,
    description: instance.description,
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

export default convertCaseRftToStix;
