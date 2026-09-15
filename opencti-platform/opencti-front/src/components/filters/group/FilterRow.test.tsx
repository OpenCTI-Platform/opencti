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

const filter: Filter = { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' };

describe('FilterRow', () => {
  let helpers: handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

  const renderRow = () => testRender(
    <FilterRow
      filter={filter}
      helpers={helpers}
      availableFilterKeys={['name', 'description']}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={new Map()}
    />,
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
});
