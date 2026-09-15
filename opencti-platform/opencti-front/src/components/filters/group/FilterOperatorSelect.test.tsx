import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import { addDays } from 'date-fns';
import type { Dispatch, SetStateAction } from 'react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import type { FilterEditorInputValue } from './useFilterEditorState';

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

import FilterOperatorSelect from './FilterOperatorSelect';

const buildDefinition = (filterKey: string, type: string, label: string, subFilters?: FilterDefinition[]): FilterDefinition => ({
  filterKey,
  type,
  label,
  multiple: false,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
  ...(subFilters ? { subFilters } : {}),
} as unknown as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['name', buildDefinition('name', 'string', 'Name')],
    ['created_at', buildDefinition('created_at', 'date', 'Creation date')],
    ['regardingOf', buildDefinition('regardingOf', 'nested', 'In regards of', [
      buildDefinition('relationship_type', 'string', 'Relationship type'),
      buildDefinition('id', 'id', 'Entity'),
    ])],
  ])],
]);

const userContext = createMockUserContext({ schema: { filterKeysSchema } });

const buildHelpers = () => ({
  handleChangeOperatorFilters: vi.fn(),
  handleAddSingleValueFilter: vi.fn(),
}) as unknown as handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

type SetInputValuesMock = Dispatch<SetStateAction<FilterEditorInputValue[]>> & ReturnType<typeof vi.fn>;

describe('FilterOperatorSelect', () => {
  let helpers: handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;
  let setInputValues: SetInputValuesMock;

  const renderSelect = (filter: Filter, subKey?: string) => testRender(
    <FilterOperatorSelect
      filter={filter}
      filterKey={filter.key}
      helpers={helpers}
      setInputValues={setInputValues}
      entityTypes={['Stix-Core-Object']}
      subKey={subKey}
    />,
    { userContext },
  );

  beforeEach(() => {
    helpers = buildHelpers();
    setInputValues = vi.fn() as unknown as SetInputValuesMock;
  });

  it('changes the operator of a plain filter without touching its value', async () => {
    const filter: Filter = { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' };
    const { user } = renderSelect(filter);
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByText('Not equals'));
    expect(helpers.handleChangeOperatorFilters).toHaveBeenCalledWith('filter-1', 'not_eq');
    expect(helpers.handleAddSingleValueFilter).not.toHaveBeenCalled();
    expect(setInputValues).not.toHaveBeenCalled();
  });

  // A date filter stores a timestamp but is edited as a day: 'lte the 10th' and 'lt the 10th' do not
  // cover the same days, so switching between the two inclusive/exclusive families shifts the stored date.
  it('shifts the stored date by one day when switching a date filter from lte to lt', async () => {
    const storedDate = '2024-01-10T00:00:00.000Z';
    const filter: Filter = { id: 'filter-1', key: 'created_at', values: [storedDate], operator: 'lte', mode: 'or' };
    const { user } = renderSelect(filter);
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByText('Lower than'));

    const expectedDate = addDays(new Date(storedDate), 1).toISOString();
    expect(helpers.handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1', expectedDate);
    expect(setInputValues).toHaveBeenCalledWith([expect.objectContaining({ key: 'created_at', values: [expectedDate] })]);
    expect(helpers.handleChangeOperatorFilters).toHaveBeenCalledWith('filter-1', 'lt');
  });

  it('leaves the stored date alone when switching between two operators of the same family', async () => {
    const filter: Filter = { id: 'filter-1', key: 'created_at', values: ['2024-01-10T00:00:00.000Z'], operator: 'lte', mode: 'or' };
    const { user } = renderSelect(filter);
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByText('Greater than'));
    expect(helpers.handleAddSingleValueFilter).not.toHaveBeenCalled();
    expect(setInputValues).not.toHaveBeenCalled();
    expect(helpers.handleChangeOperatorFilters).toHaveBeenCalledWith('filter-1', 'gt');
  });

  it('renders nothing for a subfilter that allows no operator choice', () => {
    const filter: Filter = { id: 'filter-1', key: 'regardingOf', values: [], operator: 'eq', mode: 'or' };
    renderSelect(filter, 'id');
    expect(screen.queryByRole('combobox')).toBeNull();
  });
});
