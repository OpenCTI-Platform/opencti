import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { FilterGroup, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { DashboardVariablesProvider, useOptionalDashboardVariableDefinitions } from '../DashboardVariablesContext';
import type { DashboardVariable } from '../dashboard-types';

// The shared filter components have their own tests: these stand-ins expose what the field hands them, and what
// the filters would read from the dashboard variables context.
vi.mock('@components/common/lists/Filters', () => ({
  default: ({ helpers, availableEntityTypes }: { helpers: handleFilterHelpers; availableEntityTypes: string[] }) => {
    const variables = useOptionalDashboardVariableDefinitions();
    return (
      <div>
        <span data-testid="filters-variables">{variables === undefined ? 'none' : variables.length}</span>
        <span data-testid="filters-entity-types">{availableEntityTypes.join()}</span>
        <button type="button" onClick={() => helpers.handleAddSingleValueFilter('f1', 'label-2')}>Add a label</button>
      </div>
    );
  },
}));
// The filter keys come from the schema of the platform, absent from the test user context.
vi.mock('../../../utils/filters/filtersUtils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/filters/filtersUtils')>()),
  useAvailableFilterKeysForEntityTypes: () => ['objectLabel'],
}));
vi.mock('../../FilterIconButton', () => ({
  default: ({ filters }: { filters: FilterGroup }) => (
    <span data-testid="rule">{filters.filters.map((filter) => `${filter.key}=${filter.values.join()}`).join(';')}</span>
  ),
}));

import RestrictionFiltersField from './RestrictionFiltersField';

const rule: FilterGroup = {
  mode: 'and',
  filters: [{ id: 'f1', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const variable: DashboardVariable = { id: 'v1', name: 'Topic', type: 'label', restriction: { mode: 'none' }, defaultValue: 'label-1' };

const renderField = (value: FilterGroup | undefined, error?: string) => {
  const onChange = vi.fn();
  const rendered = testRender(
    <DashboardVariablesProvider variables={[variable]}>
      <RestrictionFiltersField entityTypes={['Sector']} value={value} onChange={onChange} label="Rule" error={error} />
    </DashboardVariablesProvider>,
  );
  return { ...rendered, onChange };
};

describe('RestrictionFiltersField', () => {
  it('shows the filters of an existing rule', () => {
    renderField(rule);
    expect(screen.getByTestId('rule')).toHaveTextContent('objectLabel=label-1');
  });

  it('does not call onChange on mount, then reports each change of the rule', async () => {
    const { user, onChange } = renderField(rule);
    expect(onChange).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Add a label' }));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(onChange.mock.calls[0][0])).toContain('label-2');
  });

  it('offers no Variables section inside a dashboard with variables', () => {
    renderField(undefined);
    expect(screen.getByTestId('filters-variables')).toHaveTextContent('none');
  });

  it('only offers the entity types of the variable', () => {
    renderField(undefined);
    expect(screen.getByTestId('filters-entity-types')).toHaveTextContent('Sector');
  });

  it('shows the error of the rule', () => {
    renderField(undefined, 'At least one filter is required');
    expect(screen.getByText('At least one filter is required')).toBeInTheDocument();
  });
});
