import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import type { DashboardVariable } from '../../dashboard/dashboard-types';
import testRender from '../../../utils/tests/test-render';

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

import FilterValueVariableSwitch from './FilterValueVariableSwitch';
import { FilterEditorProvider } from './FilterEditorContext';
import { DashboardVariablesProvider } from '../../dashboard/DashboardVariablesContext';

const VARIABLE_ID = '22222222-2222-4222-8222-222222222222';
const token = `$var:${VARIABLE_ID}`;
const minimumScore: DashboardVariable = { id: VARIABLE_ID, name: 'Minimum score', type: 'numeric', restriction: { mode: 'none' }, defaultValue: null };

const buildFilter = (values: string[]): Filter => ({ id: 'filter-1', key: 'confidence', values, operator: 'gt', mode: 'or' });

describe('FilterValueVariableSwitch', () => {
  let helpers: handleFilterHelpers;

  beforeEach(() => {
    helpers = { handleAddSingleValueFilter: vi.fn() } as unknown as handleFilterHelpers;
  });

  // The switch alone: its fixed input is a plain stand-in, the filter only changes when a test re-renders it.
  const switchFor = (filter: Filter) => (
    <DashboardVariablesProvider variables={[minimumScore]}>
      <FilterEditorProvider helpers={helpers} availableFilterKeys={[]} entityTypes={['Stix-Core-Object']} filtersRepresentativesMap={new Map()} host={{ kind: 'workspace' }}>
        <FilterValueVariableSwitch filter={filter} variables={[minimumScore]}>
          <input aria-label="Fixed input" />
        </FilterValueVariableSwitch>
      </FilterEditorProvider>
    </DashboardVariablesProvider>
  );

  const fixedRadio = () => screen.getByRole('radio', { name: 'Fixed value' });
  const variableRadio = () => screen.getByRole('radio', { name: 'Variable' });

  it('empties the filter when switched to a variable, before any variable is picked', async () => {
    const { user } = testRender(switchFor(buildFilter(['50'])));
    await user.click(variableRadio());
    expect(helpers.handleAddSingleValueFilter).toHaveBeenCalledTimes(1);
    expect(helpers.handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1');
    expect(variableRadio()).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('combobox', { name: 'Variable' })).toHaveTextContent('Select a variable');
  });

  it('does not touch an empty filter switched to a variable', async () => {
    const { user } = testRender(switchFor(buildFilter([])));
    await user.click(variableRadio());
    expect(helpers.handleAddSingleValueFilter).not.toHaveBeenCalled();
    expect(variableRadio()).toHaveAttribute('aria-checked', 'true');
  });

  it('keeps showing the variable mode once the filter has been emptied, until a variable is picked', async () => {
    const { user, rerender } = testRender(switchFor(buildFilter(['50'])));
    await user.click(variableRadio());
    // The editor applies the emptying.
    rerender(switchFor(buildFilter([])));
    expect(variableRadio()).toHaveAttribute('aria-checked', 'true');
    expect(screen.queryByRole('textbox', { name: 'Fixed input' })).toBeNull();
  });

  it('follows a variable token written in the filter from outside, and a fixed value replacing it', () => {
    const { rerender } = testRender(switchFor(buildFilter(['50'])));
    expect(fixedRadio()).toHaveAttribute('aria-checked', 'true');
    rerender(switchFor(buildFilter([token])));
    expect(variableRadio()).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('combobox', { name: 'Variable' })).toHaveTextContent('Minimum score');
    rerender(switchFor(buildFilter(['70'])));
    expect(fixedRadio()).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('textbox', { name: 'Fixed input' })).toBeInTheDocument();
    expect(helpers.handleAddSingleValueFilter).not.toHaveBeenCalled();
  });
});
