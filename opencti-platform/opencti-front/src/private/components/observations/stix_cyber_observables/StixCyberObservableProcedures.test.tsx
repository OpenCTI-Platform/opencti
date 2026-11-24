import React from 'react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import StixCyberObservableProcedures, { buildObservableProceduresFilters } from './StixCyberObservableProcedures';

const mocks = vi.hoisted(() => ({
  useQueryLoading: vi.fn(),
  paginationOptions: {} as Record<string, unknown>,
}));

vi.mock('../../../../utils/hooks/useQueryLoading', () => ({
  default: mocks.useQueryLoading,
}));

vi.mock('../../../../utils/hooks/useLocalStorage', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../utils/hooks/useLocalStorage')>();
  return {
    ...actual,
    usePaginationLocalStorage: () => ({
      viewStorage: {},
      helpers: { handleSetNumberOfElements: vi.fn() },
      paginationOptions: mocks.paginationOptions,
    }),
  };
});

vi.mock('../../../../components/dataGrid/DataTable', () => ({
  default: () => null,
}));

describe('buildObservableProceduresFilters', () => {
  it('finds the procedures that have the observable, or run it as their command', () => {
    expect(buildObservableProceduresFilters('obs-1')).toEqual({
      mode: 'or',
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          values: [
            { key: 'id', values: ['obs-1'] },
            { key: 'relationship_type', values: ['has-observable'] },
          ],
          operator: 'eq',
          mode: 'or',
        },
        { key: ['procedureCommand'], values: ['obs-1'], operator: 'eq', mode: 'or' },
      ],
    });
  });
});

describe('StixCyberObservableProcedures', () => {
  beforeEach(() => {
    mocks.useQueryLoading.mockReset();
    mocks.useQueryLoading.mockReturnValue(null);
  });

  it('queries with the stored sort and always applies the observable filter', () => {
    mocks.paginationOptions = {
      count: 25,
      orderBy: 'created',
      orderMode: 'desc',
      filters: { mode: 'and', filters: [], filterGroups: [] },
    };
    testRender(<StixCyberObservableProcedures observableId="obs-1" />);
    const variables = mocks.useQueryLoading.mock.calls[0][1];
    expect(variables.orderBy).toBe('created');
    expect(variables.orderMode).toBe('desc');
    expect(variables.filters).toEqual(buildObservableProceduresFilters('obs-1'));
  });
});
