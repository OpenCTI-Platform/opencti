import React, { createContext, PropsWithChildren, useContext, useMemo } from 'react';
import useHelper from '../../utils/hooks/useHelper';
import type { DashboardVariable } from './dashboard-types';
import { buildDefaultVariableValues } from './dashboardVariablesResolution';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from './dashboardVariablesFeatureFlag';

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();

// Current value of each dashboard variable, keyed by variable id.
// Without provider (custom views, other hosts) no variable resolves: widgets using one fail closed.
const DashboardVariableValuesContext = createContext<ReadonlyMap<string, string>>(EMPTY_VALUES);

export const useDashboardVariableValues = () => useContext(DashboardVariableValuesContext);

/**
 * Values coming from the manifest defaults. Per-user current values (localStorage + URL)
 * will take over once dashboard variables can be changed from the dashboard.
 */
export const useDashboardDefaultVariableValues = (variables: DashboardVariable[]) => {
  const { isFeatureEnable } = useHelper();
  const isDashboardVariablesEnabled = isFeatureEnable(DASHBOARD_VARIABLES_FEATURE_FLAG);
  // Every manifest save (layout, dates...) gives a new variables array: keying the map on its content
  // keeps the same instance, so widgets do not all re-resolve their data selection for nothing.
  const signature = isDashboardVariablesEnabled ? JSON.stringify([...buildDefaultVariableValues(variables)]) : '[]';
  return useMemo<ReadonlyMap<string, string>>(() => new Map(JSON.parse(signature)), [signature]);
};

export const DashboardVariableValuesProvider = ({ values, children }: PropsWithChildren<{ values: ReadonlyMap<string, string> }>) => (
  <DashboardVariableValuesContext.Provider value={values}>
    {children}
  </DashboardVariableValuesContext.Provider>
);
