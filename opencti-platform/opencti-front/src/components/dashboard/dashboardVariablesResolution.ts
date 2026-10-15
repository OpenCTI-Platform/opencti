import type { DashboardVariable } from './dashboard-types';

// Mirror of opencti-graphql/src/modules/dashboard/dashboard-variables-resolution.ts.
// Both are locked by opencti-graphql/tests/data/dashboard-variables/resolution-cases.json.

const UUID_PATTERN = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const TOKEN_REGEXP = new RegExp(`^\\$var:(${UUID_PATTERN})$`);

type FilterGroupLike = { filters: unknown[]; filterGroups?: unknown[] };
type SubFilterLike = { key: unknown; values: unknown[] };

const isFilterGroupLike = (value: unknown): value is FilterGroupLike => {
  return typeof value === 'object' && value !== null && Array.isArray((value as FilterGroupLike).filters);
};

const isSubFilterLike = (value: unknown): value is SubFilterLike => {
  return typeof value === 'object' && value !== null && 'key' in value && Array.isArray((value as SubFilterLike).values);
};

export const parseVariableToken = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const match = TOKEN_REGEXP.exec(value);
  return match ? match[1] : null;
};

export const toVariableToken = (variableId: string) => `$var:${variableId}`;

/**
 * Replace every `$var:<uuid>` token of a filter group by the current value of the variable.
 * A token without a (non-empty, non-token) value is kept in place and reported in `unresolved`:
 * the widget must then not run its query (fail closed), never run it without the filter.
 */
export const resolveVariablesInFilterGroup = <T>(
  filterGroup: T,
  values: ReadonlyMap<string, string>,
): { filters: T; unresolved: string[] } => {
  const unresolved: string[] = [];
  const resolveValue = (value: unknown): unknown => {
    const variableId = parseVariableToken(value);
    if (variableId !== null) {
      const current = values.get(variableId);
      // A value that is itself a token is not resolved further (no chaining, no cycle): fail closed.
      if (current === undefined || current === '' || parseVariableToken(current) !== null) {
        if (!unresolved.includes(variableId)) unresolved.push(variableId);
        return value;
      }
      return current;
    }
    if (isFilterGroupLike(value)) return resolveGroup(value);
    if (isSubFilterLike(value)) return { ...value, values: value.values.map(resolveValue) };
    return value;
  };
  const resolveGroup = (group: FilterGroupLike): FilterGroupLike => {
    const result: FilterGroupLike = {
      ...group,
      filters: group.filters.map((filter) => (isSubFilterLike(filter) ? { ...filter, values: filter.values.map(resolveValue) } : filter)),
    };
    if (Array.isArray(group.filterGroups)) {
      result.filterGroups = group.filterGroups.map((subGroup) => (isFilterGroupLike(subGroup) ? resolveGroup(subGroup) : subGroup));
    }
    return result;
  };
  if (!isFilterGroupLike(filterGroup)) {
    return { filters: filterGroup, unresolved };
  }
  return { filters: resolveGroup(filterGroup) as T, unresolved };
};

export const buildDefaultVariableValues = (variables: DashboardVariable[] | undefined) => {
  const values = new Map<string, string>();
  (variables ?? []).forEach((variable) => {
    if (variable.defaultValue) values.set(variable.id, variable.defaultValue);
  });
  return values;
};

/**
 * Whether a value coming from the user's browser (localStorage, `variables` URL param) may be applied to a variable.
 * Same rules as the default value of a variable (`validateDraft` in variables/dashboardVariableDraft.ts):
 * a boolean is `true` or `false`, a numeric a finite number, a date something `Date.parse` understands, any other type
 * a non-blank string; no value may reference another variable. A selection restriction also bounds the value to its pool.
 * A boolean, numeric or date value is taken as is, never trimmed: one with surrounding spaces is refused, since it would
 * otherwise reach the filters of the widgets with its spaces.
 * A value failing it is ignored, so the default of the variable applies.
 */
export const isValidVariableValue = (variable: DashboardVariable, value: string): boolean => {
  const trimmed = value.trim();
  if (trimmed === '' || value.includes(toVariableToken(''))) return false;
  if (variable.restriction.mode === 'selection' && !variable.restriction.values.includes(value)) return false;
  switch (variable.type) {
    case 'boolean':
      return value === 'true' || value === 'false';
    case 'numeric':
      return value === trimmed && Number.isFinite(Number(value));
    case 'date':
      return value === trimmed && !Number.isNaN(Date.parse(value));
    default:
      return true;
  }
};
