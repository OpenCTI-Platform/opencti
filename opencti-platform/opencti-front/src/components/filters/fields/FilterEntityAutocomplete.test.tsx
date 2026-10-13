import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

// Records the text of each search the autocomplete triggers
const searchedValues = vi.hoisted(() => [] as string[]);
vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{}, (_key: string, _cache: unknown, _setCache: unknown, event: { target: { value: string } }) => {
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

describe('FilterEntityAutocomplete', () => {
  it('gives focus back to the input when the search is cleared, searching once for the empty text', async () => {
    const { user } = testRender(
      <FilterEditorProvider availableFilterKeys={[]} entityTypes={['Stix-Core-Object']} filtersRepresentativesMap={new Map()}>
        <FilterEntityAutocomplete filter={authorFilter} filterKey="createdBy" setInputValues={vi.fn()} label="Author" />
      </FilterEditorProvider>,
      { userContext: createMockUserContext({ schema: { filterKeysSchema } }) },
    );

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
