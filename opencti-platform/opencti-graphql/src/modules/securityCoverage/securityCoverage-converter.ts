import {
  ATTRIBUTE_COVERED,
  ENTITY_TYPE_SECURITY_COVERAGE,
  INPUT_COVERED,
  type Stix2SecurityCoverage,
  type StixSecurityCoverage,
  type StoreEntitySecurityCoverage,
} from './securityCoverage-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
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
    [ATTRIBUTE_COVERED]: instance[INPUT_COVERED]?.standard_id,
    [ATTRIBUTE_RESULT_OF]: (instance[INPUT_RESULT_OF] ?? []).map((scr) => scr.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

// As in 2.1, no results nor values that the API computes from them (coverage information, `external_uri`).
export const convertSecurityCoverageToStix_2_0 = (instance: StoreEntitySecurityCoverage): Stix2SecurityCoverage => {
  assertType(ENTITY_TYPE_SECURITY_COVERAGE, instance.entity_type);
  const securityCoverage = buildStixDomain2(instance);
  return {
    ...securityCoverage,
    name: instance.name,
    description: instance.description,
    periodicity: instance.periodicity,
    duration: instance.duration,
    type_affinity: instance.type_affinity,
    platforms_affinity: instance.platforms_affinity ?? [],
    [ATTRIBUTE_COVERED]: instance[INPUT_COVERED]?.standard_id,
  };
};

export default convertSecurityCoverageToStix;
