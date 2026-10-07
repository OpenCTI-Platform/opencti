import { describe, expect, it } from 'vitest';
import { buildContainerRelationshipsContextFilters } from './ContainerStixCoreRelationships';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

describe('buildContainerRelationshipsContextFilters', () => {
  it('keeps the relationship type constraint, with no user filters', () => {
    const result = buildContainerRelationshipsContextFilters('container-id', undefined);

    expect(result).toEqual({
      mode: 'and',
      filters: [
        { key: 'objects', values: ['container-id'], operator: 'eq', mode: 'or' },
        { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    });
  });

  it('keeps user filters nested under the relationship type constraint', () => {
    const userFilters: FilterGroup = {
      mode: 'or',
      filters: [{ key: 'relationship_type', values: ['uses'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };

    const result = buildContainerRelationshipsContextFilters('container-id', userFilters);

    expect(result.filters).toEqual([
      { key: 'objects', values: ['container-id'], operator: 'eq', mode: 'or' },
      { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
    ]);
    expect(result.filterGroups).toEqual([userFilters]);
    // The relationship type filter and user filters are combined with AND.
    expect(result.mode).toEqual('and');
  });

  it('drops empty user filter groups instead of nesting them', () => {
    const emptyUserFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };

    const result = buildContainerRelationshipsContextFilters('container-id', emptyUserFilters);

    expect(result.filterGroups).toEqual([]);
  });
});
