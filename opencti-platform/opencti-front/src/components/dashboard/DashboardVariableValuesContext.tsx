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
  return useMemo(
    () => (isDashboardVariablesEnabled ? buildDefaultVariableValues(variables) : EMPTY_VALUES),
    [isDashboardVariablesEnabled, variables],
  );
};

export const DashboardVariableValuesProvider = ({ values, children }: PropsWithChildren<{ values: ReadonlyMap<string, string> }>) => (
  <DashboardVariableValuesContext.Provider value={values}>
    {children}
  </DashboardVariableValuesContext.Provider>
);
