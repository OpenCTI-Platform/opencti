import { isFilterGroupFormatCorrect, canonicalizeFilterGroupForBackend } from '../../utils/filters/filtersUtils';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';

/**
 * Serializes a filter group for saved filters persistence.
 * /!\ Saved filters are persisted in the FRONTEND format (single string keys, empty filters kept)
 * and are re-read with a bare JSON.parse: only the frontend-only ids are stripped here.
 */
export const serializeSavedFilterGroup = (filters?: FilterGroup | null) => JSON.stringify(filters ? canonicalizeFilterGroupForBackend(filters) : filters);

/**
 * Normalizes a persisted saved filter string so that it can be compared with a freshly serialized
 * filter group. Rows saved before the id strip was introduced still hold frontend-only ids in their
 * json: they are re-serialized here through the very same canonical strip, so that both sides of a
 * comparison are always built the same way.
 * Anything that is not a parsable filter group is returned untouched.
 */
export const normalizeSavedFilterGroupString = (savedFilters?: string | null): string | undefined => {
  if (!savedFilters) return undefined;
  try {
    const parsed = JSON.parse(savedFilters);
    return isFilterGroupFormatCorrect(parsed) ? serializeSavedFilterGroup(parsed) : savedFilters;
  } catch {
    return savedFilters;
  }
};

/**
 * Tells whether the current filters state matches the persisted saved filter, comparing the
 * STRIPPED value on both sides (the state carries frontend-only group ids, the persisted row must
 * not). Returns false when there is no saved filter to compare with.
 */
export const hasSameSavedFilters = (savedFilters?: string | null, filters?: FilterGroup | null): boolean => {
  const normalized = normalizeSavedFilterGroupString(savedFilters);
  if (normalized === undefined) return false;
  return normalized === serializeSavedFilterGroup(filters);
};

/**
 * Tells whether a filter group holds nothing worth saving. A group carrying only empty nested
 * groups is considered empty: nested groups are just containers, saving them would persist a filter
 * that filters nothing.
 */
export const isEmptySavedFilterGroup = (filters?: FilterGroup | null): boolean => (
  !filters
  || ((filters.filters ?? []).length === 0 && (filters.filterGroups ?? []).every((group) => isEmptySavedFilterGroup(group)))
);
