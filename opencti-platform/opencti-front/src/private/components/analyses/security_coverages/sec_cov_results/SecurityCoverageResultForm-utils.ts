export interface ExistingSecurityCoverageResult {
  name: string;
  external_uri?: string | null;
}

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
