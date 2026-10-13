import React, { createContext, PropsWithChildren, useContext } from 'react';

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();

// Current value of each dashboard variable, keyed by variable id.
// Without provider (custom views, other hosts) no variable resolves: widgets using one fail closed.
const DashboardVariableValuesContext = createContext<ReadonlyMap<string, string>>(EMPTY_VALUES);

export const useDashboardVariableValues = () => useContext(DashboardVariableValuesContext);

export const DashboardVariableValuesProvider = ({ values, children }: PropsWithChildren<{ values: ReadonlyMap<string, string> }>) => (
  <DashboardVariableValuesContext.Provider value={values}>
    {children}
  </DashboardVariableValuesContext.Provider>
);
