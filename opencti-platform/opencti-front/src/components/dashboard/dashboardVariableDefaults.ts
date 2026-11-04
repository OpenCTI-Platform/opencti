import type { DashboardVariable } from './dashboard-types';
import { buildDefaultVariableValues } from './dashboardVariablesResolution';

/**
 * Ids of the variables whose default value is ignored when the dashboard builds its default values (invalid for the type
 * of the variable, see `buildDefaultVariableValues`): the widgets using them stay unresolved and show no data, which the
 * owner can only fix if it is made visible. A variable without default is not listed, it is just unset.
 */
export const getInvalidDefaultVariableIds = (variables: readonly DashboardVariable[]): Set<string> => {
  const invalidIds = new Set<string>();
  variables.forEach((variable) => {
    if (!variable.defaultValue) return;
    // The same rule as the one applying the defaults, so the warning cannot disagree with what is applied.
    if (!buildDefaultVariableValues([variable]).has(variable.id)) invalidIds.add(variable.id);
  });
  return invalidIds;
};
