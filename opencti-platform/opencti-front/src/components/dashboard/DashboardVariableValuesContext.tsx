import React, { createContext, PropsWithChildren, useContext } from 'react';

const EMPTY_VALUES: ReadonlyMap<string, string> = new Map();
const NO_DATE_VARIABLE_IDS: ReadonlySet<string> = new Set();

// Current value of each dashboard variable, keyed by variable id.
// Without provider (custom views, other hosts) no variable resolves: widgets using one fail closed.
const DashboardVariableValuesContext = createContext<ReadonlyMap<string, string>>(EMPTY_VALUES);

// Ids of the date variables of the dashboard: their value is shifted by one day for the lte and gt operators when it is
// substituted (resolveVariablesInFilterGroup). Kept apart from the values, which many consumers read as a plain map.
const DashboardDateVariableIdsContext = createContext<ReadonlySet<string>>(NO_DATE_VARIABLE_IDS);

export const useDashboardVariableValues = () => useContext(DashboardVariableValuesContext);

export const useDashboardDateVariableIds = () => useContext(DashboardDateVariableIdsContext);

export const DashboardVariableValuesProvider = ({
  values,
  dateVariableIds = NO_DATE_VARIABLE_IDS,
  children,
}: PropsWithChildren<{ values: ReadonlyMap<string, string>; dateVariableIds?: ReadonlySet<string> }>) => (
  <DashboardVariableValuesContext.Provider value={values}>
    <DashboardDateVariableIdsContext.Provider value={dateVariableIds}>
      {children}
    </DashboardDateVariableIdsContext.Provider>
  </DashboardVariableValuesContext.Provider>
);
