import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { cleanObject } from '../../../database/stix-converter-utils';
import { ATTRIBUTE_RESULT_OF, INPUT_RESULT_OF, type StixSecurityCoverageResult, type StoreEntitySecurityCoverageResult } from './securityCoverageResult-types';
import { isNotEmptyField } from '../../../database/utils';

const convertSecurityCoverageResultToStix = (instance: StoreEntitySecurityCoverageResult): StixSecurityCoverageResult => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    external_uri: instance.external_uri,
    coverage_last_result: instance.coverage_last_result,
    coverage_valid_from: instance.coverage_valid_from,
    coverage_valid_to: instance.coverage_valid_to,
    covered: isNotEmptyField(instance.coverage_information),
    coverage: (instance.coverage_information ?? [])
      .map((c) => ({ name: c.coverage_name, score: c.coverage_score })),
    [ATTRIBUTE_RESULT_OF]: (instance[INPUT_RESULT_OF] ?? []).standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertSecurityCoverageResultToStix;
