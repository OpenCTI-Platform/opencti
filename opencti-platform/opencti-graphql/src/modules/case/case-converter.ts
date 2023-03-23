import type { StixCase, StoreEntityCase } from './case-types';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../schema/general';

const convertCaseToStix = (instance: StoreEntityCase): StixCase => {
  const cases = buildStixDomain(instance);
  return {
    ...cases,
    name: instance.name,
    description: instance.description,
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
