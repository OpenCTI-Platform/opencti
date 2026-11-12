import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { PreloadedQuery } from 'react-relay';
import type { FilterDefinition } from '../utils/hooks/useAuth';
import type { FilterGroup } from '../utils/filters/filtersHelpers-types';
import type { DashboardVariable } from './dashboard/dashboard-types';
import type { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import testRender, { createMockUserContext } from '../utils/tests/test-render';

const VARIABLE_ID = '11111111-1111-4111-8111-111111111111';
const DELETED_VARIABLE_ID = '99999999-9999-4999-8999-999999999999';
const TOKEN = `$var:${VARIABLE_ID}`;
const DELETED_TOKEN = `$var:${DELETED_VARIABLE_ID}`;

// What the representatives query answers: the back cannot resolve a token, its representative has no value.
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => ({
    filtersRepresentatives: [
      { representativeId: 'label-1', value: 'APT', entity_type: 'Label', color: null },
      { representativeId: '$var:11111111-1111-4111-8111-111111111111', value: null, entity_type: null, color: null },
      { representativeId: '$var:99999999-9999-4999-8999-999999999999', value: null, entity_type: null, color: null },
    ],
  }),
}));

import TaskFilterValue from './TaskFilterValue';
import { DashboardVariablesProvider } from './dashboard/DashboardVariablesContext';

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
  ])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema, scos: [], sdos: [], smos: [], scrs: [] } });

// The content of the tooltip of a dynamic sub group chip (`dynamicRegardingOf`).
const dynamicFilters = (values: string[]): FilterGroup => ({
  mode: 'and',
  filters: [{ key: 'objectLabel', values, operator: 'eq', mode: 'or' }],
  filterGroups: [],
});

const renderTooltip = (values: string[], variables?: DashboardVariable[]) => {
  const ui = <TaskFilterValue filters={dynamicFilters(values)} queryRef={{} as PreloadedQuery<FilterValuesContentQuery>} />;
  return testRender(
    variables ? <DashboardVariablesProvider variables={variables}>{ui}</DashboardVariablesProvider> : ui,
    { userContext },
  );
};

describe('TaskFilterValue (dynamic filter tooltip) with dashboard variable tokens', () => {
  it('shows a token under the variable name, never raw', () => {
    const { container } = renderTooltip(['label-1', TOKEN], [labelVariable]);
    expect(container).toHaveTextContent('Label = APT OR Client label');
    expect(container.textContent).not.toContain('$var:');
  });

  it('shows a token of a variable that no longer exists as a deleted variable', () => {
    const { container } = renderTooltip([DELETED_TOKEN], [labelVariable]);
    expect(container).toHaveTextContent('Label = Deleted variable');
    expect(container.textContent).not.toContain('$var:');
  });

  it('outside a dashboard (no provider), renders the values exactly as before', () => {
    const { container } = renderTooltip([TOKEN]);
    // The legacy rendering: the raw value (truncated).
    expect(container).toHaveTextContent(`Label = ${TOKEN.substring(0, 40)}...`);
  });
});
