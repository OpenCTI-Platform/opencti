import { describe, expect, it } from 'vitest';
import { buildReportRelationshipsContextFilters } from './ReportStixCoreRelationships';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

describe('buildReportRelationshipsContextFilters', () => {
  it('scopes the query to the report objects, with no user filters', () => {
    const result = buildReportRelationshipsContextFilters('report-id', undefined);

    expect(result).toEqual({
      mode: 'and',
      filters: [
        { key: 'objects', values: ['report-id'], operator: 'eq', mode: 'or' },
        { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    });
  });

  it('keeps the report membership filter mandatory, nesting user filters instead of merging them', () => {
    const userFilters: FilterGroup = {
      mode: 'or',
      filters: [{ key: 'relationship_type', values: ['uses'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };

    const result = buildReportRelationshipsContextFilters('report-id', userFilters);

    expect(result.filters).toEqual([
      { key: 'objects', values: ['report-id'], operator: 'eq', mode: 'or' },
      { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
    ]);
    expect(result.filterGroups).toEqual([userFilters]);
    // The mandatory filter and the user filters are combined with AND: user filters,
    // however permissive ('or' mode), can never widen the query outside the report.
    expect(result.mode).toEqual('and');
  });

  it('drops empty user filter groups instead of nesting them', () => {
    const emptyUserFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };

    const result = buildReportRelationshipsContextFilters('report-id', emptyUserFilters);

    expect(result.filterGroups).toEqual([]);
  });
});
