import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, FilterEditorInputValue, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import type { WidgetHost } from '../../../utils/widget/widget';
import type { DashboardVariable } from '../../dashboard/dashboard-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

// The boolean filter goes to the entity autocomplete, whose static options are 'true' and 'false'.
vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{
    revoked: [
      { value: 'true', label: 'true', type: 'Boolean' },
      { value: 'false', label: 'false', type: 'Boolean' },
    ],
  }, vi.fn()],
}));

vi.mock('../../../utils/hooks/useAttributes', () => ({
  default: () => ({ typesWithFintelTemplates: [] }),
}));

// Spied to prove that a variable token never reaches the date conversion of FilterDate.
const dateFiltersValueForDisplay = vi.hoisted(() => vi.fn());
vi.mock('../../../utils/Time', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../utils/Time')>();
  dateFiltersValueForDisplay.mockImplementation(actual.dateFiltersValueForDisplay);
  return { ...actual, dateFiltersValueForDisplay };
});

import FilterValueInput from './FilterValueInput';
import { FilterEditorProvider } from './FilterEditorContext';
import { DashboardVariablesProvider } from '../../dashboard/DashboardVariablesContext';

const DATE_VARIABLE_ID = '11111111-1111-4111-8111-111111111111';
const NUMERIC_VARIABLE_ID = '22222222-2222-4222-8222-222222222222';
const TEXT_VARIABLE_ID = '33333333-3333-4333-8333-333333333333';
const BOOLEAN_VARIABLE_ID = '44444444-4444-4444-8444-444444444444';
const LABEL_VARIABLE_ID = '55555555-5555-4555-8555-555555555555';
const DELETED_VARIABLE_ID = '99999999-9999-4999-8999-999999999999';
const token = (id: string) => `$var:${id}`;

const variable = (id: string, name: string, type: 'date' | 'numeric' | 'text' | 'boolean' | 'label'): DashboardVariable => (
  { id, name, type, restriction: { mode: 'none' }, defaultValue: null }
);
const dateVariable = variable(DATE_VARIABLE_ID, 'Report date', 'date');
const numericVariable = variable(NUMERIC_VARIABLE_ID, 'Minimum score', 'numeric');
const textVariable = variable(TEXT_VARIABLE_ID, 'Client name', 'text');
const booleanVariable = variable(BOOLEAN_VARIABLE_ID, 'Revoked only', 'boolean');
const labelVariable = variable(LABEL_VARIABLE_ID, 'Client label', 'label');

const definition = (filterKey: string, type: string, label: string) => ({
  filterKey,
  type,
  label,
  multiple: type !== 'date',
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
} as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['created_at', definition('created_at', 'date', 'Creation date')],
    ['confidence', definition('confidence', 'integer', 'Confidence')],
    ['name', definition('name', 'string', 'Name')],
    ['revoked', definition('revoked', 'boolean', 'Revoked')],
  ])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema, scos: [], sdos: [], smos: [], scrs: [] } });
const WORKSPACE: WidgetHost = { kind: 'workspace' };

const buildFilter = (key: string, operator: string, values: string[] = []): Filter => ({ id: 'filter-1', key, values, operator, mode: 'or' });

// The same filter for each family: the date, a number, a free text.
const FAMILIES = [
  { family: 'date', filter: buildFilter('created_at', 'gt', ['2024-01-10T00:00:00.000Z']), compatible: dateVariable, incompatible: numericVariable },
  { family: 'numeric', filter: buildFilter('confidence', 'gt', ['50']), compatible: numericVariable, incompatible: dateVariable },
  { family: 'text', filter: buildFilter('name', 'starts_with', ['APT']), compatible: textVariable, incompatible: numericVariable },
];

// React and MUI generated ids differ from one render to the next: they are not a DOM difference.
const normalizeIds = (html: string) => html.replace(/(:|«|_)r_?[0-9a-z]+_?(:|»|_)/g, ':id:').replace(/mui-\d+/g, 'mui-id');

describe('FilterValueInput with dashboard variables (date and free inputs)', () => {
  let helpers: handleFilterHelpers;

  beforeEach(() => {
    dateFiltersValueForDisplay.mockClear();
    helpers = {
      handleAddSingleValueFilter: vi.fn(),
      handleAddRepresentationFilter: vi.fn(),
      handleRemoveRepresentationFilter: vi.fn(),
      handleReplaceFilterValues: vi.fn(),
      handleChangeRepresentationFilter: vi.fn(),
    } as unknown as handleFilterHelpers;
  });

  const renderInput = (
    filter: Filter,
    { variables, host = WORKSPACE, withProvider = true }: { variables?: DashboardVariable[]; host?: WidgetHost; withProvider?: boolean } = {},
  ) => {
    const inputValues: FilterEditorInputValue[] = [filter as FilterEditorInputValue];
    const editor = (
      <FilterEditorProvider
        helpers={helpers}
        availableFilterKeys={[]}
        entityTypes={['Stix-Core-Object']}
        filtersRepresentativesMap={new Map()}
        host={host}
      >
        <FilterValueInput filter={filter} filterKey={filter.key} inputValues={inputValues} setInputValues={vi.fn()} />
      </FilterEditorProvider>
    );
    return testRender(
      withProvider ? <DashboardVariablesProvider variables={variables}>{editor}</DashboardVariablesProvider> : editor,
      { userContext },
    );
  };

  const renderedHtml = (filter: Filter, options: Parameters<typeof renderInput>[1]) => {
    const { container, unmount } = renderInput(filter, options);
    const html = normalizeIds(container.innerHTML);
    unmount();
    return html;
  };

  const fixedRadio = () => screen.queryByRole('radio', { name: 'Fixed value' });
  const variableRadio = () => screen.queryByRole('radio', { name: 'Variable' });

  describe.each(FAMILIES)('$family filter', ({ filter, compatible, incompatible }) => {
    it('renders exactly the same DOM as outside a dashboard when no variable is compatible', () => {
      const outsideDashboard = renderedHtml(filter, { withProvider: false });
      expect(renderedHtml(filter, { variables: undefined })).toEqual(outsideDashboard);
      expect(renderedHtml(filter, { variables: [] })).toEqual(outsideDashboard);
      expect(renderedHtml(filter, { variables: [incompatible, labelVariable] })).toEqual(outsideDashboard);
      expect(outsideDashboard).not.toContain('Fixed value');
    });

    it('offers no switch outside a workspace host, even under a provider', () => {
      const customView = { kind: 'custom-view' } as WidgetHost;
      const outsideDashboard = renderedHtml(filter, { host: customView, withProvider: false });
      expect(renderedHtml(filter, { host: customView, variables: [compatible] })).toEqual(outsideDashboard);
    });

    it('offers the fixed value / variable switch, fixed value first, when a variable is compatible', () => {
      renderInput(filter, { variables: [compatible, incompatible] });
      expect(fixedRadio()).toHaveAttribute('aria-checked', 'true');
      expect(variableRadio()).toHaveAttribute('aria-checked', 'false');
    });

    it('writes the variable token as the single filter value when a variable is chosen', async () => {
      const { user } = renderInput(filter, { variables: [compatible, incompatible] });
      await user.click(variableRadio() as HTMLElement);
      await user.click(screen.getByRole('combobox', { name: 'Variable' }));
      // Only the compatible variables are offered.
      expect(screen.queryByRole('option', { name: incompatible.name })).toBeNull();
      await user.click(await screen.findByRole('option', { name: compatible.name }));
      // Stored as-is: no day shift on a variable, whatever the operator. (Outside a popover, the free input
      // also commits its unchanged value when the switch takes the focus.)
      expect(helpers.handleAddSingleValueFilter).toHaveBeenLastCalledWith('filter-1', token(compatible.id));
    });

    it('opens on the variable when the current value is a token, and never shows the token', () => {
      const { container } = renderInput({ ...filter, values: [token(compatible.id)] }, { variables: [compatible] });
      expect(variableRadio()).toHaveAttribute('aria-checked', 'true');
      expect(screen.getByRole('combobox', { name: 'Variable' })).toHaveTextContent(compatible.name);
      expect(container.innerHTML).not.toContain('$var:');
      expect(container.textContent).not.toContain('Invalid Date');
    });

    it('shows the name of an existing variable that is not compatible, never "Deleted variable"', () => {
      renderInput({ ...filter, values: [token(incompatible.id)] }, { variables: [compatible, incompatible] });
      const trigger = screen.getByRole('combobox', { name: 'Variable' });
      expect(trigger).toHaveTextContent(incompatible.name);
      expect(trigger).not.toHaveTextContent('Deleted variable');
    });

    it('shows "Deleted variable" for a token of a variable that no longer exists', () => {
      renderInput({ ...filter, values: [token(DELETED_VARIABLE_ID)] }, { variables: [compatible, incompatible] });
      expect(screen.getByRole('combobox', { name: 'Variable' })).toHaveTextContent('Deleted variable');
    });

    it('offers only the compatible variables, even while an incompatible one is the current value', async () => {
      const { user } = renderInput({ ...filter, values: [token(incompatible.id)] }, { variables: [compatible, incompatible] });
      await user.click(screen.getByRole('combobox', { name: 'Variable' }));
      const listbox = await screen.findByRole('listbox');
      expect(within(listbox).getAllByRole('option').map((option) => option.textContent)).toEqual([compatible.name]);
    });

    it('back to fixed value, restores an empty fixed input and drops the token', async () => {
      const { user, container } = renderInput({ ...filter, values: [token(compatible.id)] }, { variables: [compatible] });
      await user.click(fixedRadio() as HTMLElement);
      // No value: the filter is emptied.
      expect(helpers.handleAddSingleValueFilter).toHaveBeenLastCalledWith('filter-1');
      expect(screen.queryByRole('combobox', { name: 'Variable' })).toBeNull();
      expect(container.innerHTML).not.toContain('$var:');
      expect(container.textContent).not.toContain('Invalid Date');
      expect(dateFiltersValueForDisplay).not.toHaveBeenCalledWith(expect.stringContaining('$var:'), expect.anything());
    });

    it('in a dashboard, never hands a token of a deleted variable to the fixed input', () => {
      const { container } = renderInput({ ...filter, values: [token(DELETED_VARIABLE_ID)] }, { variables: [labelVariable] });
      expect(fixedRadio()).toBeNull();
      expect(container.innerHTML).not.toContain('$var:');
      expect(container.textContent).not.toContain('Invalid Date');
      expect(dateFiltersValueForDisplay).not.toHaveBeenCalledWith(expect.stringContaining('$var:'), expect.anything());
    });
  });

  it('never gives a token to the date conversion, from the variable mode to the fixed one', async () => {
    const filter = buildFilter('created_at', 'lte', [token(DATE_VARIABLE_ID)]);
    const { user } = renderInput(filter, { variables: [dateVariable] });
    await user.click(fixedRadio() as HTMLElement);
    expect(screen.getByLabelText('Creation date')).toBeInTheDocument();
    expect(dateFiltersValueForDisplay).not.toHaveBeenCalledWith(expect.stringContaining('$var:'), expect.anything());
  });

  it('offers no variable on a within (date range) filter', () => {
    const filter = buildFilter('created_at', 'within', ['now-7d', 'now']);
    const outsideDashboard = renderedHtml(filter, { withProvider: false });
    expect(renderedHtml(filter, { variables: [dateVariable] })).toEqual(outsideDashboard);
  });

  it('offers boolean variables in the value list of a boolean filter, with no switch', async () => {
    const { user } = renderInput(buildFilter('revoked', 'eq'), { variables: [booleanVariable, numericVariable] });
    expect(fixedRadio()).toBeNull();
    await user.click(screen.getByRole('combobox'));
    expect(screen.queryByRole('option', { name: 'Minimum score' })).toBeNull();
    await user.click(await screen.findByRole('option', { name: 'Revoked only' }));
    expect(helpers.handleAddRepresentationFilter).toHaveBeenCalledWith('filter-1', token(BOOLEAN_VARIABLE_ID));
  });
});
