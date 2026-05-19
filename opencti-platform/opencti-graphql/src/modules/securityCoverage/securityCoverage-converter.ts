import { ATTRIBUTE_COVERED, INPUT_COVERED, type StixSecurityCoverage, type StoreEntitySecurityCoverage } from './securityCoverage-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import { ATTRIBUTE_RESULT_OF, INPUT_RESULT_OF } from './securityCoverageResult/securityCoverageResult-types';

const convertSecurityCoverageToStix = (instance: StoreEntitySecurityCoverage): StixSecurityCoverage => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    periodicity: instance.periodicity,
    type_affinity: instance.type_affinity,
    platforms_affinity: instance.platforms_affinity,
    duration: instance.duration,
    [ATTRIBUTE_COVERED]: instance[INPUT_COVERED].standard_id,
    [ATTRIBUTE_RESULT_OF]: (instance[INPUT_RESULT_OF] ?? []).map((scr) => scr.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertSecurityCoverageToStix;
