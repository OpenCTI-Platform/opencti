import React from 'react';
import { describe, expect, it } from 'vitest';
import { renderHook } from '@testing-library/react';
import { DashboardVariableValuesProvider, useDashboardVariableValues } from './DashboardVariableValuesContext';

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
