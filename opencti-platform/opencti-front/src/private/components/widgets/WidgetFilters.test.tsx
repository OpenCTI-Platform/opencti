import React from 'react';
import { beforeEach, describe, it, expect, vi } from 'vitest';
import { fireEvent, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import WidgetFilters from './WidgetFilters';

vi.mock('@components/common/lists/Filters', () => ({
  default: () => <div data-testid="filters" />,
}));

vi.mock('../../../components/FilterIconButton', () => ({
  default: () => <div data-testid="filter-icon-button" />,
}));

vi.mock('@components/widgets/WidgetConfigContext', () => ({
  useWidgetConfigContext: () => ({ host: { kind: 'workspace' } }),
}));

vi.mock('../../../utils/filters/useFiltersState', async () => {
  const ReactLib = await import('react');
  const emptyGroup = { mode: 'and', filters: [], filterGroups: [] };
  return {
    default: (initialFilters: unknown) => {
      const [state, setState] = ReactLib.useState(initialFilters ?? emptyGroup);
      return [
        state,
        {
          handleAddFilterWithEmptyValue: vi.fn(),
          handleClearAllFilters: () => setState(emptyGroup),
        },
      ];
    },
  };
});

vi.mock('./WidgetSavedFiltersSelection', () => ({
  widgetSavedFiltersSelectionQuery: {},
  default: ({
    onSelect,
    onDeselect,
    onClear,
  }: {
    onSelect: (id: string) => void;
    onDeselect: () => void;
    onClear: () => void;
  }) => (
    <div>
      <button type="button" data-testid="saved-select" onClick={() => onSelect('saved-filter-id')}>
        select saved
      </button>
      <button type="button" data-testid="saved-deselect" onClick={onDeselect}>
        custom mode
      </button>
      <button type="button" data-testid="saved-clear" onClick={onClear}>
        clear saved
      </button>
    </div>
  ),
}));

vi.mock('./WidgetSavedFilterChips', () => ({
  default: () => <div data-testid="saved-filter-chips" />,
}));

vi.mock('../../../relay/environment', () => ({
  fetchQuery: vi.fn(() => ({
    toPromise: async () => ({
      savedFilters: {
        edges: [{ node: { scope: 'entities' } }, { node: { scope: 'relationships' } }],
      },
    }),
  })),
}));

vi.mock('src/components/saved_filters/WidgetSavedFiltersIcon', () => ({
  default: ({ onClick }: { onClick: () => void }) => (
    <button type="button" data-testid="switch-to-saved" onClick={onClick}>
      saved mode
    </button>
  ),
}));

vi.mock('../../../utils/filters/filtersUtils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../utils/filters/filtersUtils')>();
  return {
    ...actual,
    isFilterGroupNotEmpty: () => false,
    isDraftWorkspaceFilterGroup: (
      filters: import('src/utils/filters/filtersHelpers-types').FilterGroup | null | undefined,
    ) => {
      if (!filters) return false;
      const entityTypeFilter = filters.filters?.find(
        (f: import('src/utils/filters/filtersHelpers-types').Filter) => f.key === 'entity_type',
      );
      if (!entityTypeFilter || entityTypeFilter.values.length === 0) return false;
      return entityTypeFilter.values.every(
        (v: import('src/utils/filters/filtersHelpers-types').FilterValue) => {
          if (typeof v === 'string') return v === 'DraftWorkspace';
          return (v?.value ?? (v as { id?: string })?.id) === 'DraftWorkspace';
        },
      );
    },
    useAvailableFilterKeysForEntityTypes: (entityTypes: string[]) => {
      if (entityTypes.includes('DraftWorkspace')) {
        return ['name', 'created_at', 'workflowInstanceCurrentState'];
      }
      return ['name', 'created_at'];
    },
  };
});

const createRenderOptions = () => ({
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
});

describe('WidgetFilters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const baseDataSelection = {
    filters: {
      mode: 'and',
      filters: [{ key: 'name', values: ['custom-main'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
    dynamicFrom: {
      mode: 'and',
      filters: [{ key: 'name', values: ['custom-from'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
    dynamicTo: {
      mode: 'and',
      filters: [{ key: 'name', values: ['custom-to'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
  };

  it('renders without crashing for entities perspective', () => {
    const { container } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={baseDataSelection}
        setDataSelection={vi.fn()}
      />,
      createRenderOptions(),
    );
    expect(container).toBeTruthy();
  });

  it('detects DraftWorkspace filter and adjusts searchContext', () => {
    const draftDataSelection = {
      ...baseDataSelection,
      filters: {
        mode: 'and',
        filters: [{ key: 'entity_type', values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    const { getByTestId } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={draftDataSelection}
        setDataSelection={vi.fn()}
      />,
      createRenderOptions(),
    );
    expect(getByTestId('filters')).toBeTruthy();
  });

  it('keeps custom filters in local state when switching to saved mode and restores them when returning to custom mode', () => {
    const setDataSelection = vi.fn();
    const { queryAllByTestId, getAllByTestId } = testRender(
      <WidgetFilters
        perspective="relationships"
        type="number"
        dataSelection={baseDataSelection}
        setDataSelection={setDataSelection}
      />,
      createRenderOptions(),
    );

    // Each click switches one section to saved mode, so the number of buttons shrinks.
    let savedSwitchButtons = queryAllByTestId('switch-to-saved');
    while (savedSwitchButtons.length > 0) {
      fireEvent.click(savedSwitchButtons[0]);
      savedSwitchButtons = queryAllByTestId('switch-to-saved');
    }
    getAllByTestId('saved-select').forEach((button) => {
      fireEvent.click(button);
    });

    const savedModeCalls = setDataSelection.mock.calls.map((call) => call[0]);
    expect(
      savedModeCalls.some(
        (call) => call.filters_id === 'saved-filter-id' && call.filters === undefined,
      ),
    ).toBe(true);
    expect(
      savedModeCalls.some(
        (call) => call.dynamicFrom_id === 'saved-filter-id' && call.dynamicFrom === undefined,
      ),
    ).toBe(true);
    expect(
      savedModeCalls.some(
        (call) => call.dynamicTo_id === 'saved-filter-id' && call.dynamicTo === undefined,
      ),
    ).toBe(true);

    let savedDeselectButtons = queryAllByTestId('saved-deselect');
    while (savedDeselectButtons.length > 0) {
      fireEvent.click(savedDeselectButtons[0]);
      savedDeselectButtons = queryAllByTestId('saved-deselect');
    }

    const restoredCustomCalls = setDataSelection.mock.calls.map((call) => call[0]);
    expect(
      restoredCustomCalls.some(
        (call) =>
          call.filters_id === null &&
          JSON.stringify(call.filters) === JSON.stringify(baseDataSelection.filters),
      ),
    ).toBe(true);
    expect(
      restoredCustomCalls.some(
        (call) =>
          call.dynamicFrom_id === null &&
          JSON.stringify(call.dynamicFrom) === JSON.stringify(baseDataSelection.dynamicFrom),
      ),
    ).toBe(true);
    expect(
      restoredCustomCalls.some(
        (call) =>
          call.dynamicTo_id === null &&
          JSON.stringify(call.dynamicTo) === JSON.stringify(baseDataSelection.dynamicTo),
      ),
    ).toBe(true);
  });

  it('clears the saved filter id without leaving saved mode', () => {
    const setDataSelection = vi.fn();
    const { getByTestId } = testRender(
      <WidgetFilters
        perspective="entities"
        type="number"
        dataSelection={{
          ...baseDataSelection,
          filters_id: 'saved-filter-id',
          filters: undefined,
        }}
        setDataSelection={setDataSelection}
      />,
      createRenderOptions(),
    );

    fireEvent.click(getByTestId('saved-clear'));

    const clearCall = setDataSelection.mock.calls.at(-1)?.[0];
    expect(clearCall.filters_id).toBeNull();
    expect(clearCall.filters).toBeUndefined();
  });

  it('does not persist previously set custom filters in dataSelection when already in saved filters mode', async () => {
    const setDataSelection = vi.fn();
    testRender(
      <WidgetFilters
        perspective="relationships"
        type="number"
        dataSelection={{
          ...baseDataSelection,
          filters_id: 'saved-main-id',
          dynamicFrom_id: 'saved-from-id',
          dynamicTo_id: 'saved-to-id',
        }}
        setDataSelection={setDataSelection}
      />,
      createRenderOptions(),
    );

    await waitFor(() => {
      expect(setDataSelection).toHaveBeenCalled();
    });

    const savedModeCall = setDataSelection.mock.calls.at(-1)?.[0];
    expect(savedModeCall.filters_id).toBe('saved-main-id');
    expect(savedModeCall.dynamicFrom_id).toBe('saved-from-id');
    expect(savedModeCall.dynamicTo_id).toBe('saved-to-id');
    expect(savedModeCall.filters).toBeUndefined();
    expect(savedModeCall.dynamicFrom).toBeUndefined();
    expect(savedModeCall.dynamicTo).toBeUndefined();
  });
});
