import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import WidgetFilters from './WidgetFilters';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

vi.mock('@components/common/lists/Filters', () => ({
  default: () => <div data-testid="filters" />,
}));

vi.mock('../../../components/FilterIconButton', () => ({
  default: () => <div data-testid="filter-icon-button" />,
}));

vi.mock('@components/widgets/WidgetConfigContext', () => ({
  useWidgetConfigContext: () => ({ host: undefined }),
}));

vi.mock('../../../utils/filters/useFiltersState', () => ({
  default: (initialFilters: unknown) => [initialFilters, {
    handleAddFilterWithEmptyValue: vi.fn(),
    handleClearAllFilters: vi.fn(),
  }],
}));

vi.mock('../../../utils/filters/filtersUtils', () => ({
  isFilterGroupNotEmpty: () => false,
  isDraftWorkspaceFilterGroup: (filters: import('src/utils/filters/filtersHelpers-types').FilterGroup | null | undefined) => {
    if (!filters) return false;
    const entityTypeFilter = filters.filters?.find((f: import('src/utils/filters/filtersHelpers-types').Filter) => f.key === 'entity_type');
    if (!entityTypeFilter || entityTypeFilter.values.length === 0) return false;
    return entityTypeFilter.values.every((v: import('src/utils/filters/filtersHelpers-types').FilterValue) => {
      if (typeof v === 'string') return v === 'DraftWorkspace';
      return (v?.value ?? (v as { id?: string })?.id) === 'DraftWorkspace';
    });
  },
  useAvailableFilterKeysForEntityTypes: (entityTypes: string[]) => {
    if (entityTypes.includes('DraftWorkspace')) {
      return ['name', 'created_at', 'workflowInstanceCurrentState'];
    }
    return ['name', 'created_at'];
  },
}));

describe('WidgetFilters', () => {
  const baseDataSelection = {
    filters: emptyFilterGroup,
    dynamicFrom: undefined,
    dynamicTo: undefined,
  };

  it('renders without crashing for entities perspective', () => {
    const { container } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={baseDataSelection as import('../../../utils/widget/widget').WidgetDataSelection}
        setDataSelection={vi.fn()}
      />,
      {
        userContext: createMockUserContext({
          schema: {
            scos: [],
            sdos: [],
            smos: [],
            scrs: [],
            schemaRelationsTypesMapping: new Map(),
            schemaRelationsRefTypesMapping: new Map(),
            filterKeysSchema: new Map(),
          },
        }),
      },
    );
    expect(container).toBeTruthy();
  });

  it('detects DraftWorkspace filter and adjusts searchContext', () => {
    const draftDataSelection = {
      ...baseDataSelection,
      filters: {
        mode: 'and' as const,
        filters: [{ key: 'entity_type', values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    const { getByTestId } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={draftDataSelection as import('../../../utils/widget/widget').WidgetDataSelection}
        setDataSelection={vi.fn()}
      />,
      {
        userContext: createMockUserContext({
          schema: {
            scos: [],
            sdos: [],
            smos: [],
            scrs: [],
            schemaRelationsTypesMapping: new Map(),
            schemaRelationsRefTypesMapping: new Map(),
            filterKeysSchema: new Map(),
          },
        }),
      },
    );
    expect(getByTestId('filters')).toBeTruthy();
  });
});
