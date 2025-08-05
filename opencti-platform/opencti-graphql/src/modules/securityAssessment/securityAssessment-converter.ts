import type { StixSecurityAssessment, StoreEntitySecurityAssessment } from './securityAssessment-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import { INPUT_OBJECTS } from '../../schema/general';

const convertSecurityAssessmentToStix = (instance: StoreEntitySecurityAssessment): StixSecurityAssessment => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    latest_coverage: instance.latest_coverage,
    filters: instance.filters,
    periodicity: instance.periodicity,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertSecurityAssessmentToStix;
