import React from 'react';
import { describe, expect, it } from 'vitest';
import { renderHook } from '@testing-library/react';
import { DashboardVariableValuesProvider, useDashboardDateVariableIds, useDashboardVariableValues } from './DashboardVariableValuesContext';

describe('useDashboardVariableValues', () => {
  it('reads the values given to the provider', () => {
    const values = new Map([['v1', 'energy']]);
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <DashboardVariableValuesProvider values={values}>{children}</DashboardVariableValuesProvider>
    );
    const { result } = renderHook(() => useDashboardVariableValues(), { wrapper });
    expect(result.current).toBe(values);
  });

  it('is an empty map without provider', () => {
    const { result } = renderHook(() => useDashboardVariableValues());
    expect(result.current.size).toEqual(0);
  });
});

describe('useDashboardDateVariableIds', () => {
  it('reads the date variable ids given to the provider', () => {
    const dateVariableIds = new Set(['v1']);
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <DashboardVariableValuesProvider values={new Map()} dateVariableIds={dateVariableIds}>{children}</DashboardVariableValuesProvider>
    );
    const { result } = renderHook(() => useDashboardDateVariableIds(), { wrapper });
    expect(result.current).toBe(dateVariableIds);
  });

  it('is empty without provider, or when the provider is given none', () => {
    expect(renderHook(() => useDashboardDateVariableIds()).result.current.size).toEqual(0);
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <DashboardVariableValuesProvider values={new Map()}>{children}</DashboardVariableValuesProvider>
    );
    expect(renderHook(() => useDashboardDateVariableIds(), { wrapper }).result.current.size).toEqual(0);
  });
});
