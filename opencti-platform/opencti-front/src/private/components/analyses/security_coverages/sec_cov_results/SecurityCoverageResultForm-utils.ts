import { convertCreatedBy, convertMarkings } from '../../../../../utils/edition';
import { FieldOption } from '../../../../../utils/field';
import type { SecurityCoverageResultFormData } from './SecurityCoverageResultFormDetails';
import type { SecurityCoverageResultFormDrawerFragment$data } from './__generated__/SecurityCoverageResultFormDrawerFragment.graphql';

export interface ExistingSecurityCoverageResult {
  name: string;
  external_uri?: string | null;
}

export type SecurityCoverageResultToEdit = NonNullable<SecurityCoverageResultFormDrawerFragment$data['results']>[number];

export const isManualResult = (result: ExistingSecurityCoverageResult) => !result.external_uri;

export const resultToFormData = (result: SecurityCoverageResultToEdit): SecurityCoverageResultFormData => ({
  name: result.name,
  description: result.description ?? '',
  confidence: result.confidence ?? undefined,
  createdBy: result.createdBy ? convertCreatedBy(result) as FieldOption : undefined,
  objectMarking: convertMarkings(result),
  objectLabel: (result.objectLabel ?? []).map((label) => ({
    label: label.value ?? '',
    value: label.id,
    color: label.color ?? undefined,
  })),
  coverageInformation: result.coverage_information?.length
    ? result.coverage_information.map(({ coverage_name, coverage_score }) => ({ coverage_name, coverage_score }))
    : [{ coverage_name: null, coverage_score: null }],
  externalUri: result.external_uri ?? '',
  validFrom: result.coverage_valid_from ? new Date(result.coverage_valid_from) : null,
  validTo: result.coverage_valid_to ? new Date(result.coverage_valid_to) : null,
});

// Same normalization as the backend identifier of a security coverage result:
// the name is case insensitive, the external link is not.
const normalizeName = (value?: string | null) => (value ?? '').toLowerCase().trim();
const normalizeUri = (value?: string | null) => (value ?? '').trim();

/**
 * Find the field of a new security coverage result that collides with an
 * existing result of the same security coverage.
 *
 * Mirrors the backend identifier of a result: it is built from the external
 * link and the security coverage when a link is given, from the name and the
 * security coverage otherwise. A collision means the backend would silently
 * update the existing result instead of creating a new one.
 *
 * @param values Name and external link of the result to create.
 * @param existingResults Results already attached to the security coverage.
 * @returns The colliding field, or null if the result is not a duplicate.
 */
export const findDuplicateResultField = (
  values: { name: string; externalUri?: string | null },
  existingResults?: readonly ExistingSecurityCoverageResult[] | null,
): 'name' | 'externalUri' | null => {
  const results = existingResults ?? [];
  const externalUri = normalizeUri(values.externalUri);
  if (externalUri) {
    return results.some((r) => normalizeUri(r.external_uri) === externalUri) ? 'externalUri' : null;
  }
  const name = normalizeName(values.name);
  const isDuplicateName = results.some((r) => !normalizeUri(r.external_uri) && normalizeName(r.name) === name);
  return name && isDuplicateName ? 'name' : null;
};
