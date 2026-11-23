import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

// Records the text of each search the autocomplete triggers, and returns the entities set by the test
const searchedValues = vi.hoisted(() => [] as string[]);
const searchedEntities = vi.hoisted(() => ({ current: {} as Record<string, FilterOptionValue[]> }));
vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [searchedEntities.current, (_key: string, _cache: unknown, _setCache: unknown, event: { target: { value: string } }) => {
    searchedValues.push(event.target.value);
  }],
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

import FilterEntityAutocomplete from './FilterEntityAutocomplete';
import { FilterEditorProvider } from './FilterEditorContext';

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['createdBy', {
      filterKey: 'createdBy',
      type: 'id',
      label: 'Author',
      multiple: true,
      subEntityTypes: ['Stix-Core-Object'],
      elementsForFilterValuesSearch: ['Identity'],
    } as FilterDefinition],
  ])],
]);

const authorFilter: Filter = { id: 'filter-1', key: 'createdBy', operator: 'eq', values: [], mode: 'or' };

const renderAuthorAutocomplete = () => testRender(
  <FilterEditorProvider availableFilterKeys={[]} entityTypes={['Stix-Core-Object']} filtersRepresentativesMap={new Map()}>
    <FilterEntityAutocomplete filter={authorFilter} filterKey="createdBy" setInputValues={vi.fn()} label="Author" />
  </FilterEditorProvider>,
  { userContext: createMockUserContext({ schema: { filterKeysSchema } }) },
);

describe('FilterEntityAutocomplete', () => {
  beforeEach(() => {
    searchedEntities.current = {};
  });

  it('keeps the order of the search, most relevant first, when a term is typed', async () => {
    // the server returned these authors for "zeta", most relevant first: not the alphabetical order
    searchedEntities.current = {
      createdBy: ['Zeta Corp', 'Acme Zeta', 'Beta Zeta'].map((label) => ({ label, value: label, type: 'Organization', ranked: true })),
    };
    const { user } = renderAuthorAutocomplete();

    await user.type(screen.getByRole('combobox', { name: 'Author' }), 'zeta');

    const options = within(await screen.findByRole('listbox')).getAllByRole('option');
    expect(options.map((option) => option.getAttribute('aria-label'))).toEqual(['Zeta Corp', 'Acme Zeta', 'Beta Zeta']);
  });

  it('gives focus back to the input when the search is cleared, searching once for the empty text', async () => {
    const { user } = renderAuthorAutocomplete();

    const input = screen.getByRole('combobox', { name: 'Author' });
    await user.type(input, 'acme');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Clear search' })).toHaveFocus();

    searchedValues.length = 0;
    await user.keyboard('{Enter}');

    expect(input).toHaveFocus();
    expect(input).toHaveValue('');
    expect(screen.queryByRole('button', { name: 'Clear search' })).not.toBeInTheDocument();
    expect(searchedValues).toEqual(['']);
  });
});
