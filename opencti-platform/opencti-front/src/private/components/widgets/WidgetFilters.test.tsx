import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

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
  isDraftWorkspaceFilterGroup: (filters: any) => {
    if (!filters) return false;
    const entityTypeFilter = filters.filters?.find((f: any) => f.key === 'entity_type');
    if (!entityTypeFilter || entityTypeFilter.values.length === 0) return false;
    return entityTypeFilter.values.every((v: any) => {
      if (typeof v === 'string') return v === 'DraftWorkspace';
      return (v?.value ?? v?.id) === 'DraftWorkspace';
    });
  },
  useAvailableFilterKeysForEntityTypes: (entityTypes: string[]) => {
    if (entityTypes.includes('DraftWorkspace')) {
      return ['name', 'created_at', 'workflowInstanceCurrentState'];
    }
    return ['name', 'created_at'];
  },
}));

import WidgetFilters from './WidgetFilters';

describe('WidgetFilters', () => {
  const baseDataSelection = {
    filters: { mode: 'and' as const, filters: [], filterGroups: [] },
    dynamicFrom: undefined,
    dynamicTo: undefined,
  };

  it('renders without crashing for entities perspective', () => {
    const { container } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={baseDataSelection as any}
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
        dataSelection={draftDataSelection as any}
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
