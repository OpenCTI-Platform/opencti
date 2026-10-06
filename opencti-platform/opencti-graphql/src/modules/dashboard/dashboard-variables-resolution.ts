// Dashboard variables are referenced in widget filters with a textual token `$var:<uuid>`.
// This module is mirrored in opencti-front (src/components/dashboard/dashboardVariablesResolution.ts);
// both sides are locked by tests/data/dashboard-variables/resolution-cases.json.

const DASHBOARD_VARIABLE_TOKEN_PREFIX = '$var:';

const UUID_PATTERN = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const TOKEN_REGEXP = new RegExp(`^\\$var:(${UUID_PATTERN})$`);
const TOKEN_ANYWHERE_REGEXP = new RegExp(`\\$var:${UUID_PATTERN}`);

type FilterGroupLike = { filters: unknown[]; filterGroups?: unknown[] };
type SubFilterLike = { key: unknown; values: unknown[] };

const isFilterGroupLike = (value: unknown): value is FilterGroupLike => {
  return typeof value === 'object' && value !== null && Array.isArray((value as FilterGroupLike).filters);
};

const isSubFilterLike = (value: unknown): value is SubFilterLike => {
  return typeof value === 'object' && value !== null && 'key' in value && Array.isArray((value as SubFilterLike).values);
};

export const toDashboardVariableToken = (variableId: string) => `${DASHBOARD_VARIABLE_TOKEN_PREFIX}${variableId}`;

export const parseDashboardVariableToken = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const match = TOKEN_REGEXP.exec(value);
  return match ? match[1] : null;
};

export const containsDashboardVariableToken = (serialized: string) => TOKEN_ANYWHERE_REGEXP.test(serialized);

/**
 * Replace every `$var:<uuid>` token of a filter group by the current value of the variable.
 * A token without a (non-empty) value is kept in place and reported in `unresolved`:
 * the caller must then refuse to run the query (fail closed), never drop the filter.
 * The input is never mutated.
 */
export const resolveVariablesInFilterGroup = <T>(
  filterGroup: T,
  values: ReadonlyMap<string, string>,
): { filters: T; unresolved: string[] } => {
  const unresolved: string[] = [];
  const resolveValue = (value: unknown): unknown => {
    const variableId = parseDashboardVariableToken(value);
    if (variableId !== null) {
      const current = values.get(variableId);
      if (current === undefined || current === '') {
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

export const extractDashboardVariableIds = (filterGroup: unknown) => {
  // With no value available, every referenced variable is reported as unresolved.
  return resolveVariablesInFilterGroup(filterGroup, new Map()).unresolved;
};

type ManifestWidgetLike = { dataSelection?: Array<{ filters?: unknown; dynamicFrom?: unknown; dynamicTo?: unknown }> };

/**
 * Map each variable id to the ids of the widgets referencing it in their inline filters.
 * Saved filters are deliberately ignored: a token is forbidden inside a saved filter.
 */
export const computeDashboardVariablesUsage = (widgets: Record<string, ManifestWidgetLike> | undefined) => {
  const usage = new Map<string, string[]>();
  Object.entries(widgets ?? {}).forEach(([widgetId, widget]) => {
    const ids = new Set<string>();
    (widget.dataSelection ?? []).forEach((selection) => {
      [selection.filters, selection.dynamicFrom, selection.dynamicTo]
        .flatMap(extractDashboardVariableIds)
        .forEach((id) => ids.add(id));
    });
    ids.forEach((id) => usage.set(id, [...(usage.get(id) ?? []), widgetId]));
  });
  return usage;
};
