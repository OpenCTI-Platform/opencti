import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import type { WidgetHost } from '../../../utils/widget/widget';
import type { DashboardVariable } from '../../dashboard/dashboard-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

// Three entities per searched key, as the search would answer them.
vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{
    objectLabel: [
      { value: 'label-1', label: 'Ransomware', type: 'Label', color: '#ff0000' },
      { value: 'label-2', label: 'APT', type: 'Label', color: '#00ff00' },
      { value: 'label-3', label: 'Finance', type: 'Label', color: '#0000ff' },
    ],
    objectMarking: [
      { value: 'marking-1', label: 'TLP:RED', type: 'Marking-Definition', color: '#ff0000' },
    ],
  }, vi.fn()],
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
import { DashboardVariablesProvider } from '../../dashboard/DashboardVariablesContext';

const LABEL_VARIABLE_ID = '11111111-1111-4111-8111-111111111111';
const MARKING_VARIABLE_ID = '22222222-2222-4222-8222-222222222222';
const DELETED_VARIABLE_ID = '99999999-9999-4999-8999-999999999999';
const labelVariable: DashboardVariable = { id: LABEL_VARIABLE_ID, name: 'Client label', type: 'label', restriction: { mode: 'none' }, defaultValue: null };
const markingVariable: DashboardVariable = { id: MARKING_VARIABLE_ID, name: 'Client marking', type: 'marking', restriction: { mode: 'none' }, defaultValue: null };

const definition = (filterKey: string, elementsForFilterValuesSearch: string[]) => ({
  filterKey,
  type: 'id',
  label: filterKey,
  multiple: true,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch,
} as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['objectLabel', definition('objectLabel', ['Label'])],
    ['objectMarking', definition('objectMarking', ['Marking-Definition'])],
  ])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema } });
const WORKSPACE: WidgetHost = { kind: 'workspace' };

const buildFilter = (key: string, values: string[] = []): Filter => ({ id: 'filter-1', key, values, operator: 'eq', mode: 'or' });

describe('FilterEntityAutocomplete with dashboard variables', () => {
  let helpers: handleFilterHelpers;

  beforeEach(() => {
    helpers = {
      handleAddRepresentationFilter: vi.fn(),
      handleRemoveRepresentationFilter: vi.fn(),
      handleReplaceFilterValues: vi.fn(),
      handleChangeRepresentationFilter: vi.fn(),
    } as unknown as handleFilterHelpers;
  });

  const renderAutocomplete = (
    filter: Filter,
    { variables, host = WORKSPACE, withProvider = true }: { variables?: DashboardVariable[]; host?: WidgetHost; withProvider?: boolean } = {},
  ) => {
    const editor = (
      <FilterEditorProvider
        helpers={helpers}
        availableFilterKeys={[]}
        entityTypes={['Stix-Core-Object']}
        filtersRepresentativesMap={new Map()}
        host={host}
      >
        <FilterEntityAutocomplete filter={filter} filterKey={filter.key} setInputValues={vi.fn()} label={filter.key} />
      </FilterEditorProvider>
    );
    return testRender(
      withProvider ? <DashboardVariablesProvider variables={variables}>{editor}</DashboardVariablesProvider> : editor,
      { userContext },
    );
  };

  // The open list, read in display order: group headers and options, as the user sees them.
  const readOpenList = async (user: ReturnType<typeof testRender>['user']) => {
    await user.click(screen.getByRole('combobox'));
    const listbox = await screen.findByRole('listbox');
    return Array.from(listbox.querySelectorAll('.MuiAutocomplete-groupLabel, li[role="option"]'))
      .map((node) => (node.getAttribute('role') === 'option' ? node.getAttribute('aria-label') : `[${node.textContent}]`));
  };

  // The group of the searched entities is the translated filter label.
  const OPTIONS_WITHOUT_VARIABLES = ['[Label]', 'APT', 'Finance', 'Ransomware'];

  it('lists exactly the searched entities outside a dashboard (no provider)', async () => {
    const { user } = renderAutocomplete(buildFilter('objectLabel'), { withProvider: false });
    expect(await readOpenList(user)).toEqual(OPTIONS_WITHOUT_VARIABLES);
  });

  it('lists exactly the same options when the dashboard gives no variables (feature off, home dashboard)', async () => {
    const { user } = renderAutocomplete(buildFilter('objectLabel'), { variables: undefined });
    expect(await readOpenList(user)).toEqual(OPTIONS_WITHOUT_VARIABLES);
  });

  it('lists exactly the same options when no variable of the dashboard is compatible', async () => {
    const { user } = renderAutocomplete(buildFilter('objectLabel'), { variables: [markingVariable] });
    expect(await readOpenList(user)).toEqual(OPTIONS_WITHOUT_VARIABLES);
  });

  it('offers the compatible variables first, in a Variables group, then the same options as before', async () => {
    const { user } = renderAutocomplete(buildFilter('objectLabel'), { variables: [labelVariable, markingVariable] });
    expect(await readOpenList(user)).toEqual(['[Variables]', 'Client label', ...OPTIONS_WITHOUT_VARIABLES]);
  });

  it('offers on another filter only the variables compatible with it', async () => {
    const { user } = renderAutocomplete(buildFilter('objectMarking'), { variables: [labelVariable, markingVariable] });
    expect(await readOpenList(user)).toEqual(['[Variables]', 'Client marking', '[Marking definition]', 'TLP:RED']);
  });

  it('offers no variable outside a workspace host, even under a provider', async () => {
    const customView = { kind: 'custom-view' } as WidgetHost;
    const { user, unmount } = renderAutocomplete(buildFilter('objectLabel'), { host: customView, withProvider: false });
    const withoutProvider = await readOpenList(user);
    unmount();
    const { user: otherUser } = renderAutocomplete(buildFilter('objectLabel'), { variables: [labelVariable], host: customView });
    expect(await readOpenList(otherUser)).toEqual(withoutProvider);
    expect(withoutProvider).not.toContain('Client label');
  });

  it('adds the variable token as a filter value when the variable is selected', async () => {
    const { user } = renderAutocomplete(buildFilter('objectLabel'), { variables: [labelVariable] });
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByRole('option', { name: 'Client label' }));
    expect(helpers.handleAddRepresentationFilter).toHaveBeenCalledWith('filter-1', `$var:${LABEL_VARIABLE_ID}`);
  });

  it('shows a selected token under the variable name, or as a deleted variable, never raw', () => {
    renderAutocomplete(
      buildFilter('objectLabel', [`$var:${LABEL_VARIABLE_ID}`, `$var:${DELETED_VARIABLE_ID}`]),
      { variables: [labelVariable] },
    );
    const field = screen.getByRole('combobox').closest('.MuiAutocomplete-root') as HTMLElement;
    expect(within(field).getByText('Client label')).toBeInTheDocument();
    expect(within(field).getByText('Deleted variable')).toBeInTheDocument();
    expect(field.textContent).not.toContain('$var:');
  });
});
