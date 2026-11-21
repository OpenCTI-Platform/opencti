import type { FilterSearchContext } from '../../../../../utils/filters/filtersUtils';

/**
 * Filters restricting the entities the result tab filters offer to the ones of the security coverage:
 * - Security coverage result (fromId): its results,
 * - Target entity (toId): the entities its results have covered.
 *
 * @param resultIds Ids of the results of the security coverage.
 */
export const buildSecurityCoverageResultSearchFilters = (resultIds: string[]): NonNullable<FilterSearchContext['searchFilters']> => ({
  fromId: {
    mode: 'and',
    filterGroups: [],
    filters: [{ key: ['id'], values: resultIds }],
  },
  toId: {
    mode: 'and',
    filterGroups: [],
    filters: [{
      key: ['regardingOf'],
      values: [
        { key: 'id', values: resultIds },
        { key: 'relationship_type', values: ['has-covered'] },
      ],
    }],
  },
});
