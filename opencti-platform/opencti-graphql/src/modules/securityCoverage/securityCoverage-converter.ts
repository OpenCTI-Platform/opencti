import { INPUT_COVERED, type StixSecurityCoverage, type StoreEntitySecurityCoverage } from './securityCoverage-types';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertSecurityCoverageToStix = (instance: StoreEntitySecurityCoverage): StixSecurityCoverage => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    coverage: instance.coverage,
    periodicity: instance.periodicity,
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
