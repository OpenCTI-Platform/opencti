import React, { createRef } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { FilterDefinition } from '../../utils/hooks/useAuth';
import type { Filter, FilterGroup } from '../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { FilterRepresentative } from './FiltersModel';

vi.mock('../../utils/hooks/useAttributes', () => ({
  default: () => ({ stixCoreObjectTypes: [] }),
}));

import FilterChipLine from './FilterChipLine';

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['entity_type', {
      filterKey: 'entity_type',
      type: 'string',
      label: 'Entity type',
      multiple: true,
      subEntityTypes: ['Stix-Core-Object'],
      elementsForFilterValuesSearch: [],
    } as FilterDefinition],
  ])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema, scos: [], sdos: [], smos: [], scrs: [] } });

const filtersRepresentativesMap = new Map<string, FilterRepresentative>();
const filterKeysMap = new Map<string, FilterDefinition>([
  ['entity_type', filterKeysSchema.get('Stix-Core-Object')!.get('entity_type') as FilterDefinition],
]);

const simpleFilter: Filter = { id: 'filter-1', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' };
const nestedGroup: FilterGroup = {
  id: 'group-1',
  mode: 'and',
  filters: [{ id: 'filter-2', key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const renderLine = (
  displayedFilters: Filter[],
  displayedFilterGroups: FilterGroup[],
  showGroupsSummaryButtonOnReadOnly?: boolean,
) => testRender(
  <FilterChipLine
    displayedFilters={displayedFilters}
    displayedFilterGroups={displayedFilterGroups}
    globalMode="and"
    showGroupsSummaryButtonOnReadOnly={showGroupsSummaryButtonOnReadOnly}
    filterKeysMap={filterKeysMap}
    filtersRepresentativesMap={filtersRepresentativesMap}
    variant="small"
    registerChipRef={() => {}}
    onToggleGroup={() => {}}
    onChipClick={() => {}}
    latestFilterChipRef={createRef<HTMLDivElement>()}
    lineRef={createRef<HTMLDivElement>()}
  />,
  { userContext },
);

describe('FilterChipLine on a read-only line opted into the groups summary button (triggers list)', () => {
  it('shows the chips of simple top-level filters when there is no nested group', () => {
    renderLine([simpleFilter], [], true);
    expect(screen.getByText(/Entity type/)).toBeInTheDocument();
    expect(screen.getByText('Report')).toBeInTheDocument();
    expect(screen.queryByText('Click to display filters')).toBeNull();
  });

  it('shows only the summary button when there are nested groups, as it already lists every filter', () => {
    renderLine([simpleFilter], [nestedGroup], true);
    expect(screen.getByText('Click to display filters')).toBeInTheDocument();
    expect(screen.queryByText('Report')).toBeNull();
  });

  it('shows only the summary button for a lone nested group', () => {
    renderLine([], [nestedGroup], true);
    expect(screen.getByText('Click to display filters')).toBeInTheDocument();
  });

  it('keeps showing the chips of simple filters without the opt-in', () => {
    renderLine([simpleFilter], [], false);
    expect(screen.getByText('Report')).toBeInTheDocument();
  });
});
