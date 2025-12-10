import { INPUT_COVERED, type StixSecurityCoverage, type StoreEntitySecurityCoverage } from './securityCoverage-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import { isNotEmptyField } from '../../database/utils';

const convertSecurityCoverageToStix = (instance: StoreEntitySecurityCoverage): StixSecurityCoverage => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    covered: isNotEmptyField(instance.coverage_information),
    coverage: (instance.coverage_information ?? [])
      .map((c) => ({ name: c.coverage_name, score: c.coverage_score })),
    periodicity: instance.periodicity,
    type_affinity: instance.type_affinity,
    platforms_affinity: instance.platforms_affinity,
    duration: instance.duration,
    covered_ref: instance[INPUT_COVERED].standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertSecurityCoverageToStix;
