import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { contains, convertMarkdown, iterate, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_security_coverage.py
const SECURITY_COVERAGE_ADD = `
  mutation SecurityCoverageAdd($input: SecurityCoverageAddInput!) {
    securityCoverageAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

const COVERAGE_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_granted_refs', 'granted_refs'],
];

// pycti coverage entries: only the ones with a score
export const coverageInformation = (object: StixObject) => {
  const rawCoverages = field(object, 'coverage', []);
  return iterate(rawCoverages)
    .filter((coverage) => contains(coverage, 'score'))
    .map((coverage) => ({ coverage_name: required(coverage, 'name'), coverage_score: required(coverage, 'score') }));
};

// pycti opencti_security_coverage.py:create (no update flag)
const createSecurityCoverage = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null || kw(kwargs, 'objectCovered') === null) {
    context.logger.error('[opencti_security_coverage] Missing parameters: name or object_covered');
    return null;
  }
  return mutate(context, SECURITY_COVERAGE_ADD, 'securityCoverageAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectCovered: kw(kwargs, 'objectCovered'),
    external_uri: kw(kwargs, 'external_uri'),
    externalReferences: kw(kwargs, 'externalReferences'),
    coverage_last_result: kw(kwargs, 'coverage_last_result'),
    coverage_valid_from: kw(kwargs, 'coverage_valid_from'),
    coverage_valid_to: kw(kwargs, 'coverage_valid_to'),
    coverage_information: kw(kwargs, 'coverage_information'),
    auto_enrichment_disable: kw(kwargs, 'auto_enrichment_disable'),
    periodicity: kw(kwargs, 'periodicity'),
    tenant_name: kw(kwargs, 'tenant_name'),
    tenant_id: kw(kwargs, 'tenant_id'),
    duration: kw(kwargs, 'duration'),
    type_affinity: kw(kwargs, 'type_affinity'),
    platforms_affinity: kw(kwargs, 'platforms_affinity'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
  });
};

// pycti opencti_security_coverage.py:import_from_stix2 (the update flag is not used)
export const importSecurityCoverage = async (context: ImportContext, object: StixObject, extras: Kwargs) => {
  backfillFromExtension(object, COVERAGE_EXTENSION_FIELDS);
  return createSecurityCoverage(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    name: required(object, 'name'),
    external_uri: field(object, 'external_uri'),
    auto_enrichment_disable: field(object, 'auto_enrichment_disable', false),
    periodicity: field(object, 'periodicity'),
    tenant_name: field(object, 'tenant_name'),
    tenant_id: field(object, 'tenant_id'),
    duration: field(object, 'duration'),
    type_affinity: field(object, 'type_affinity'),
    platforms_affinity: field(object, 'platforms_affinity'),
    coverage_last_result: field(object, 'last_result'),
    coverage_valid_from: field(object, 'valid_from'),
    coverage_valid_to: field(object, 'valid_to'),
    coverage_information: coverageInformation(object),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    objectCovered: field(object, 'covered_ref'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
  });
};
