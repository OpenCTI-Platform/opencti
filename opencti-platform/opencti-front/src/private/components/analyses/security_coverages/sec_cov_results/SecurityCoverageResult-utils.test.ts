import { describe, expect, it } from 'vitest';
import { buildSecurityCoverageResultSearchFilters } from './SecurityCoverageResult-utils';

describe('buildSecurityCoverageResultSearchFilters', () => {
  it('offers the results of the security coverage and the entities they have covered', () => {
    const searchFilters = buildSecurityCoverageResultSearchFilters(['result-1', 'result-2']);
    expect(Object.keys(searchFilters)).toEqual(['fromId', 'toId']);
    expect(searchFilters.fromId.filters).toEqual([{ key: ['id'], values: ['result-1', 'result-2'] }]);
    expect(searchFilters.toId.filters).toEqual([{
      key: ['regardingOf'],
      values: [
        { key: 'id', values: ['result-1', 'result-2'] },
        { key: 'relationship_type', values: ['has-covered'] },
      ],
    }]);
  });
});
