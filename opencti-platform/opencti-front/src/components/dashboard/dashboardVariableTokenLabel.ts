import type { DashboardVariable } from './dashboard-types';
import { parseVariableToken } from './dashboardVariablesResolution';

/**
 * How a filter value that is a dashboard variable token is displayed: under the variable name, or as a
 * deleted variable. Never through the filters representatives, which cannot resolve a token.
 * `null` when the value is not a token, or outside a dashboard with variables (`variables` undefined):
 * the value is then displayed as any other, a `$var:` looking literal included.
 */
export const getVariableTokenLabel = (
  value: unknown,
  variables: DashboardVariable[] | undefined,
  t_i18n: (message: string) => string,
): { variableId: string; isDeleted: boolean; label: string } | null => {
  const variableId = variables ? parseVariableToken(value) : null;
  if (variableId === null) return null;
  const variable = variables?.find(({ id }) => id === variableId);
  return { variableId, isDeleted: !variable, label: variable?.name ?? t_i18n('Deleted variable') };
};
