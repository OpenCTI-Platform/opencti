import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';
import { coverageInformation } from './security-coverage';

// pycti/entities/opencti_security_coverage_result.py
const SECURITY_COVERAGE_RESULT_ADD = `
  mutation SecurityCoverageResultAdd($input: SecurityCoverageResultAddInput!) {
    securityCoverageResultAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

const COVERAGE_RESULT_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_granted_refs', 'granted_refs'],
];

// pycti opencti_security_coverage_result.py:create (no update flag)
const createSecurityCoverageResult = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'resultOf') === null) {
    context.logger.error('[opencti_security_coverage_result] Missing parameters: result_of');
    return null;
  }
  return mutate(context, SECURITY_COVERAGE_RESULT_ADD, 'securityCoverageResultAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    resultOf: kw(kwargs, 'resultOf'),
    external_uri: kw(kwargs, 'external_uri'),
    externalReferences: kw(kwargs, 'externalReferences'),
    coverage_last_result: kw(kwargs, 'coverage_last_result'),
    coverage_valid_from: kw(kwargs, 'coverage_valid_from'),
    coverage_valid_to: kw(kwargs, 'coverage_valid_to'),
    coverage_information: kw(kwargs, 'coverage_information'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
  });
};

// pycti opencti_security_coverage_result.py:import_from_stix2 (unlike the coverage, the
// coverage_* names are read as is; the update flag is not used)
export const importSecurityCoverageResult = async (context: ImportContext, object: StixObject, extras: Kwargs) => {
  backfillFromExtension(object, COVERAGE_RESULT_EXTENSION_FIELDS);
  return createSecurityCoverageResult(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    name: required(object, 'name'),
    external_uri: field(object, 'external_uri'),
    coverage_last_result: field(object, 'coverage_last_result'),
    coverage_valid_from: field(object, 'coverage_valid_from'),
    coverage_valid_to: field(object, 'coverage_valid_to'),
    coverage_information: coverageInformation(object),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    resultOf: field(object, 'result_of_ref'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
  });
};
