import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { FilterDefinition } from '../../utils/hooks/useAuth';
import type { Filter } from '../../utils/filters/filtersHelpers-types';
import type { DashboardVariable } from '../dashboard/dashboard-types';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { FilterRepresentative } from './FiltersModel';

vi.mock('../../utils/hooks/useAttributes', () => ({
  default: () => ({ stixCoreObjectTypes: [] }),
}));

import FilterValues from './FilterValues';
import { DashboardVariablesProvider } from '../dashboard/DashboardVariablesContext';

const VARIABLE_ID = '11111111-1111-4111-8111-111111111111';
const DELETED_VARIABLE_ID = '99999999-9999-4999-8999-999999999999';
const TOKEN = `$var:${VARIABLE_ID}`;
const DELETED_TOKEN = `$var:${DELETED_VARIABLE_ID}`;
const labelVariable: DashboardVariable = { id: VARIABLE_ID, name: 'Client label', type: 'label', restriction: { mode: 'none' }, defaultValue: null };

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['objectLabel', {
      filterKey: 'objectLabel',
      type: 'id',
      label: 'Label',
      multiple: true,
      subEntityTypes: ['Stix-Core-Object'],
      elementsForFilterValuesSearch: ['Label'],
    } as FilterDefinition],
    ...([['created_at', 'date'], ['confidence', 'integer'], ['name', 'string'], ['revoked', 'boolean']] as const).map(([key, type]) => [key, {
      filterKey: key,
      type,
      label: key,
      multiple: type !== 'date',
      subEntityTypes: ['Stix-Core-Object'],
      elementsForFilterValuesSearch: [],
    } as FilterDefinition] as const),
  ])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema, scos: [], sdos: [], smos: [], scrs: [] } });

// What the representatives query answers: the back cannot resolve a token, it answers null.
const representatives = new Map<string, FilterRepresentative>([
  ['label-1', { representativeId: 'label-1', value: 'APT', entity_type: 'Label', color: null }],
  [TOKEN, { representativeId: TOKEN, value: null, entity_type: null, color: null }],
  [DELETED_TOKEN, { representativeId: DELETED_TOKEN, value: null, entity_type: null, color: null }],
]);

const filter = (values: string[]): Filter => ({ id: 'filter-1', key: 'objectLabel', values, operator: 'eq', mode: 'or' });

const renderValues = (values: string[], variables?: DashboardVariable[]) => {
  const ui = <FilterValues label="Label" currentFilter={filter(values)} filtersRepresentativesMap={representatives} />;
  return testRender(
    variables ? <DashboardVariablesProvider variables={variables}>{ui}</DashboardVariablesProvider> : ui,
    { userContext },
  );
};

describe('FilterValues with dashboard variable tokens', () => {
  it('shows a token under the variable name, styled apart from the literal values', () => {
    const { container } = renderValues(['label-1', TOKEN], [labelVariable]);
    const token = container.querySelector(`[data-variable-token="${VARIABLE_ID}"]`);
    expect(token).toHaveTextContent('Client label');
    expect(screen.getByText('APT').closest('[data-variable-token]')).toBeNull();
    expect(container.textContent).not.toContain('$var:');
  });

  it('shows a token of a variable that no longer exists as a deleted variable, whatever the representatives say', () => {
    const { container } = renderValues([DELETED_TOKEN], [labelVariable]);
    expect(container.querySelector(`[data-variable-token="${DELETED_VARIABLE_ID}"]`)).toHaveTextContent('Deleted variable');
    expect(screen.queryByText('deleted')).toBeNull();
    expect(container.textContent).not.toContain('$var:');
  });

  it('still recognizes a token when the dashboard has no variable left', () => {
    const { container } = renderValues([DELETED_TOKEN], []);
    expect(container.querySelector('[data-variable-token]')).toHaveTextContent('Deleted variable');
  });

  it('outside a dashboard (no provider), renders the values exactly as before', () => {
    const { container } = renderValues(['label-1', TOKEN]);
    expect(container.querySelector('[data-variable-token]')).toBeNull();
    expect(screen.getByText('APT')).toBeInTheDocument();
    // The legacy rendering of a value the representatives cannot resolve.
    expect(screen.getByText('deleted')).toBeInTheDocument();
  });

  // The free inputs and the date filter format their values (date, number, boolean): a token must skip it.
  it.each([
    ['created_at', 'gt'],
    ['confidence', 'gt'],
    ['name', 'starts_with'],
    ['revoked', 'eq'],
  ])('shows a token of a %s filter (%s) under the variable name', (key, operator) => {
    const ui = (
      <FilterValues
        label={key}
        currentFilter={{ id: 'filter-1', key, values: [TOKEN], operator, mode: 'or' }}
        filtersRepresentativesMap={new Map()}
      />
    );
    const { container } = testRender(<DashboardVariablesProvider variables={[labelVariable]}>{ui}</DashboardVariablesProvider>, { userContext });
    expect(container.querySelector(`[data-variable-token="${VARIABLE_ID}"]`)).toHaveTextContent('Client label');
    expect(container.textContent).not.toContain('$var:');
    expect(container.textContent).not.toContain('Invalid');
  });
});

const plainUserContext = createMockUserContext({ schema: { scrs: [], sdos: [], scos: [], smos: [], filterKeysSchema: new Map() } });

const emptyNameFilter: Filter = { id: 'filter-1', key: 'name', operator: 'nil', values: [], mode: 'or' };

describe('FilterValues', () => {
  it('renders the label as a button that opens the filter editor', async () => {
    const onClickLabel = vi.fn();
    const { user } = testRender(
      <FilterValues label="Name" currentFilter={emptyNameFilter} filtersRepresentativesMap={new Map()} isReadWriteFilter onClickLabel={onClickLabel} />,
      { userContext: plainUserContext },
    );

    await user.click(screen.getByRole('button', { name: 'Name' }));
    expect(onClickLabel).toHaveBeenCalledTimes(1);
  });

  it('renders the label of a read-only filter as plain text, not as a button that does nothing', () => {
    testRender(
      <FilterValues label="Name" currentFilter={emptyNameFilter} filtersRepresentativesMap={new Map()} isReadWriteFilter={false} onClickLabel={vi.fn()} />,
      { userContext: plainUserContext },
    );

    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Name' })).not.toBeInTheDocument();
  });
});
