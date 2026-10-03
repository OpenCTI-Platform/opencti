import { expect } from 'vitest';
import { FilterGroup } from '../filters/filtersHelpers-types';

/**
 * Test helper asserting that no frontend-only `id` property remains anywhere
 * (deep) in a filter group, whatever the nesting level (filterGroups, filters,
 * or nested filter groups held in `dynamicRegardingOf` values).
 */
export const expectNoFrontendIds = (filterGroup: FilterGroup) => {
  const serialized = JSON.stringify(filterGroup);
  expect(serialized).not.toMatch(/"id"\s*:/);
};
