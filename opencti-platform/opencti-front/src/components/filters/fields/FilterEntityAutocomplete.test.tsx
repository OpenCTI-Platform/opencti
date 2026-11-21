import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

// Records the text of each search the autocomplete triggers
const searchedValues = vi.hoisted(() => [] as string[]);
vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{
    objectLabel: [
      { value: 'label-1', label: 'Ransomware', type: 'Label', color: '#ff0000' },
      { value: 'label-2', label: 'APT', type: 'Label', color: '#00ff00' },
      { value: 'label-3', label: 'Finance', type: 'Label', color: '#0000ff' },
    ],
  }, (_key: string, _cache: unknown, _setCache: unknown, event: { target: { value: string } }) => {
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
    ['objectLabel', {
      filterKey: 'objectLabel',
      type: 'id',
      label: 'Label',
      multiple: true,
      subEntityTypes: ['Stix-Core-Object'],
      elementsForFilterValuesSearch: ['Label'],
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

  describe('with values already selected', () => {
    const labelFilter: Filter = { id: 'filter-1', key: 'objectLabel', operator: 'eq', values: ['label-1', 'label-2'], mode: 'or' };

    const renderWithSelection = () => {
      const helpers = {
        handleAddRepresentationFilter: vi.fn(),
        handleRemoveRepresentationFilter: vi.fn(),
      } as unknown as handleFilterHelpers;
      const rendered = testRender(
        <FilterEditorProvider helpers={helpers} availableFilterKeys={[]} entityTypes={['Stix-Core-Object']} filtersRepresentativesMap={new Map()}>
          <FilterEntityAutocomplete filter={labelFilter} filterKey="objectLabel" setInputValues={vi.fn()} label="Label" />
        </FilterEditorProvider>,
        { userContext: createMockUserContext({ schema: { filterKeysSchema } }) },
      );
      return { ...rendered, helpers };
    };

    it('lists in the dropdown only the values not added yet', async () => {
      const { user } = renderWithSelection();
      await user.click(screen.getByRole('combobox', { name: 'Label' }));
      const listbox = await screen.findByRole('listbox');
      const rows = Array.from(listbox.querySelectorAll('.MuiAutocomplete-groupLabel, li[role="option"]'))
        .map((node) => (node.getAttribute('role') === 'option' ? node.getAttribute('aria-label') : `[${node.textContent}]`));
      expect(rows).toEqual(['[Label]', 'Finance']);
    });

    it('shows the selected values once, as chips that remove their value', async () => {
      const { user, helpers } = renderWithSelection();
      const field = screen.getByRole('combobox', { name: 'Label' }).closest('.MuiAutocomplete-root') as HTMLElement;
      expect(within(field).getByText('Ransomware')).toBeInTheDocument();
      expect(within(field).getByText('APT')).toBeInTheDocument();

      await user.click(within(field).getByRole('button', { name: 'Remove APT' }));
      expect(helpers.handleRemoveRepresentationFilter).toHaveBeenCalledWith('filter-1', 'label-2');
    });
  });
});
