import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { FilterGroup, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

vi.mock('../fields/FilterRow', () => ({
  default: ({ filter }: { filter: { id?: string } }) => (
    <div data-testid={`filter-row-stub-${filter.id}`}>row</div>
  ),
}));

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

const buildDefinition = (filterKey: string, type: string, label: string): FilterDefinition => ({
  filterKey,
  type,
  label,
  multiple: false,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
} as unknown as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['name', buildDefinition('name', 'string', 'Name')],
    ['description', buildDefinition('description', 'string', 'Description')],
  ])],
]);

const userContext = createMockUserContext({ schema: { filterKeysSchema } });

const buildHelpers = () => ({
  handleSwitchGlobalMode: vi.fn(),
  handleSwitchLocalMode: vi.fn(),
  handleRemoveRepresentationFilter: vi.fn(),
  handleRemoveFilterById: vi.fn(),
  handleChangeOperatorFilters: vi.fn(),
  handleAddSingleValueFilter: vi.fn(),
  handleAddRepresentationFilter: vi.fn(),
  handleAddFilterWithEmptyValue: vi.fn(),
  handleAddFilterGroup: vi.fn(),
  handleRemoveFilterGroup: vi.fn(),
  handleClearAllFilters: vi.fn(),
  getLatestAddFilterId: vi.fn(),
  handleChangeRepresentationFilter: vi.fn(),
  handleReplaceFilterValues: vi.fn(),
  handleChangeFilterKey: vi.fn(),
}) as unknown as handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

import FilterGroupPanel from './FilterGroupPanel';
import { FilterEditorProvider } from '../fields/FilterEditorContext';

const availableFilterKeys = ['name', 'description'];

const group: FilterGroup = {
  id: 'group-1',
  mode: 'and',
  filters: [
    { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' },
    { id: 'filter-2', key: 'description', values: ['def'], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [
    {
      id: 'group-1-1',
      mode: 'or',
      filters: [{ id: 'filter-3', key: 'name', values: [], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
  ],
};

const deepGroup: FilterGroup = {
  id: 'level-1',
  mode: 'and',
  filters: [],
  filterGroups: [
    {
      id: 'level-2',
      mode: 'or',
      filters: [],
      filterGroups: [
        { id: 'level-3', mode: 'and', filters: [], filterGroups: [] },
      ],
    },
  ],
};

describe('Component: FilterGroupPanel', () => {
  let helpers: ReturnType<typeof buildHelpers>;

  beforeEach(() => {
    helpers = buildHelpers();
  });

  const renderPanel = (g: FilterGroup) => testRender(
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={availableFilterKeys}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={new Map()}
    >
      <FilterGroupPanel group={g} />
    </FilterEditorProvider>,
    { userContext },
  );

  it('renders the filters, the mode separator and the nested group', () => {
    renderPanel(group);
    expect(screen.getByTestId('filter-row-stub-filter-1')).toBeInTheDocument();
    expect(screen.getByTestId('filter-row-stub-filter-2')).toBeInTheDocument();
    const separators = screen.getAllByTestId('filter-group-mode-separator');
    expect(separators.length).toEqual(1);
    expect(separators[0].textContent?.toUpperCase()).toEqual('AND');
    expect(screen.getByTestId('filter-group-panel-group-1')).toBeInTheDocument();
    expect(screen.getByTestId('filter-group-panel-group-1-1')).toBeInTheDocument();
  });

  it('renders nested panels at every level (unlimited depth)', () => {
    renderPanel(deepGroup);
    expect(screen.getByTestId('filter-group-panel-level-1')).toBeInTheDocument();
    expect(screen.getByTestId('filter-group-panel-level-2')).toBeInTheDocument();
    expect(screen.getByTestId('filter-group-panel-level-3')).toBeInTheDocument();
  });

  it('adds a condition in that group', async () => {
    const { user } = renderPanel(group);
    await user.click(screen.getByTestId('filter-group-add-condition-group-1-1'));
    expect(helpers.handleAddFilterWithEmptyValue).toHaveBeenCalledTimes(1);
    expect(helpers.handleAddFilterWithEmptyValue).toHaveBeenCalledWith(expect.objectContaining({ key: 'name' }), 'group-1-1');
  });

  it('adds a sub-group in that group', async () => {
    const { user } = renderPanel(group);
    await user.click(screen.getByTestId('filter-group-add-group-group-1'));
    expect(helpers.handleAddFilterGroup).toHaveBeenCalledWith('group-1');
  });

  it('switches the mode of the sub-group only', async () => {
    const { user } = renderPanel(group);
    await user.click(screen.getByTestId('filter-group-mode-select-group-1-1'));
    const options = await screen.findAllByRole('option', { hidden: true });
    const andOption = options.find((o) => o.textContent?.toUpperCase() === 'AND');
    await user.click(andOption as HTMLElement);
    expect(helpers.handleSwitchGlobalMode).toHaveBeenCalledWith('group-1-1');
    expect(helpers.handleSwitchGlobalMode).toHaveBeenCalledTimes(1);
  });

  it('removes that group', async () => {
    const { user } = renderPanel(group);
    await user.click(screen.getByTestId('filter-group-remove-group-1-1'));
    expect(helpers.handleRemoveFilterGroup).toHaveBeenCalledWith('group-1-1');
  });
});
