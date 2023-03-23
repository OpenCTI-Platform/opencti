import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixCase, StoreEntityCase } from './case-types';

const convertCaseToStix = (instance: StoreEntityCase): StixCase => {
  const cases = buildStixDomain(instance);
  return {
    ...instance,
    ...cases,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...cases.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertCaseToStix;
