import React, { createContext, PropsWithChildren, useContext } from 'react';
import type { DashboardVariable } from './dashboard-types';

const NO_VARIABLES: DashboardVariable[] = [];

// Definitions of the dashboard variables, for the widget filter editors (not to be confused with
// DashboardVariableValuesContext, the current values used to resolve the widget queries).
// `undefined` means "not in a dashboard with variables" (no provider: lists, feeds, triggers, playbooks,
// custom views, fintel templates; or the dashboard gives none: feature off, home dashboard). The filters
// then behave exactly as anywhere else: nothing is offered and a `$var:` looking value stays a literal.
// An empty list still means "in a dashboard": a token of a deleted variable is shown as such.
const DashboardVariablesContext = createContext<DashboardVariable[] | undefined>(undefined);

export const DashboardVariablesProvider = ({ variables, children }: PropsWithChildren<{ variables: DashboardVariable[] | undefined }>) => (
  <DashboardVariablesContext.Provider value={variables}>
    {children}
  </DashboardVariablesContext.Provider>
);

/** The variables of the dashboard, an empty list outside a dashboard with variables. */
export const useDashboardVariableDefinitions = (): DashboardVariable[] => useContext(DashboardVariablesContext) ?? NO_VARIABLES;

/** The variables of the dashboard, `undefined` outside a dashboard with variables (tokens are then not interpreted). */
export const useOptionalDashboardVariableDefinitions = (): DashboardVariable[] | undefined => useContext(DashboardVariablesContext);
