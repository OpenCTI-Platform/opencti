import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{}, vi.fn()],
}));

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

vi.mock('../../../utils/hooks/useAttributes', () => ({
  default: () => ({ typesWithFintelTemplates: [] }),
}));

import FilterRow from './FilterRow';
import { FilterEditorProvider } from './FilterEditorContext';

const buildDefinition = (filterKey: string, type: string, label: string, subFilters?: FilterDefinition[]): FilterDefinition => ({
  filterKey,
  type,
  label,
  multiple: false,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
  ...(subFilters ? { subFilters } : {}),
} as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['name', buildDefinition('name', 'string', 'Name')],
    ['description', buildDefinition('description', 'string', 'Description')],
    ['dynamicRegardingOf', buildDefinition('dynamicRegardingOf', 'nested', 'In regards of (dynamic)', [
      buildDefinition('relationship_type', 'id', 'Relationship type'),
      buildDefinition('dynamic', 'filters', 'Dynamic filter'),
    ])],
  ])],
]);

const filtersRepresentativesMap = new Map([
  ['targets', { value: 'Targets', entity_type: 'Relationship', color: null, representativeId: 'targets' }],
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
}) as handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

const filter: Filter = { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' };

describe('FilterRow', () => {
  let helpers: handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

  const renderRow = (rowFilter: Filter = filter) => testRender(
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={['name', 'description', 'dynamicRegardingOf']}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={filtersRepresentativesMap}
    >
      <FilterRow filter={rowFilter} />
    </FilterEditorProvider>,
    { userContext },
  );

  beforeEach(() => {
    helpers = buildHelpers();
  });

  it('renders the three controls and the remove button', () => {
    renderRow();
    expect(screen.getByTestId('filter-row-key-select')).toBeDefined();
    expect(screen.getByTestId('filter-row-operator-select')).toBeDefined();
    expect(screen.getByTestId('filter-row-value')).toBeDefined();
    expect(screen.getByTestId('filter-row-remove-button')).toBeDefined();
  });

  it('calls handleChangeFilterKey when selecting another filter key', async () => {
    const { user } = renderRow();
    await user.click(within(screen.getByTestId('filter-row-key-select')).getByRole('combobox'));
    // options render in a Radix portal (FDS SelectContent portals unconditionally), query them by text
    await user.click(await screen.findByText('Description'));
    expect(helpers.handleChangeFilterKey).toHaveBeenCalledWith('filter-1', expect.objectContaining({ key: 'description' }));
  });

  it('calls handleChangeOperatorFilters when selecting an operator', async () => {
    const { user } = renderRow();
    await user.click(within(screen.getByTestId('filter-row-operator-select')).getByRole('combobox'));
    await user.click(await screen.findByText('Not equals'));
    expect(helpers.handleChangeOperatorFilters).toHaveBeenCalledWith('filter-1', 'not_eq');
  });

  it('calls handleRemoveFilterById when clicking the remove button', async () => {
    const { user } = renderRow();
    await user.click(screen.getByTestId('filter-row-remove-button'));
    expect(helpers.handleRemoveFilterById).toHaveBeenCalledWith('filter-1');
  });

  describe('relationship type of a dynamicRegardingOf filter', () => {
    const dynamicGroup = { mode: 'and', filters: [{ key: 'name', values: ['abc'] }], filterGroups: [] };
    const withoutDynamic = {
      id: 'filter-dyn',
      key: 'dynamicRegardingOf',
      operator: 'eq',
      mode: 'or',
      values: [{ key: 'relationship_type', values: ['targets'] }],
    } as unknown as Filter;
    const withDynamic = {
      ...withoutDynamic,
      values: [...withoutDynamic.values, { key: 'dynamic', values: [dynamicGroup] }],
    } as unknown as Filter;

    it('can be emptied while no dynamic filter is defined', () => {
      renderRow(withoutDynamic);
      const relationshipType = screen.getByTestId('filter-row-relationship-type');
      expect(within(relationshipType).getByRole('button', { name: 'Remove Targets' })).toBeInTheDocument();
      expect(within(relationshipType).getByLabelText('Clear')).toBeInTheDocument();
      expect(within(screen.getByTestId('filter-row-operator-select')).getByLabelText('Condition')).not.toBeDisabled();
    });

    it('cannot be emptied once a dynamic filter is defined', () => {
      renderRow(withDynamic);
      const relationshipType = screen.getByTestId('filter-row-relationship-type');
      expect(within(relationshipType).getByText('Targets')).toBeInTheDocument();
      expect(within(relationshipType).queryByRole('button', { name: 'Remove Targets' })).toBeNull();
      expect(within(relationshipType).queryByLabelText('Clear')).toBeNull();
      expect(within(screen.getByTestId('filter-row-operator-select')).getByLabelText('Condition')).toBeDisabled();
    });
  });
});
