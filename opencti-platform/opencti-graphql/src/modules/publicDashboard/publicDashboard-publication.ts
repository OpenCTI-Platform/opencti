import { FunctionalError } from '../../config/errors';
import type { PublicDashboardTimeRangeInput, PublicDashboardVariableValueInput } from '../../generated/graphql';
import { buildDashboardVariableDefaultValues, isStrictIsoDate, isValidDashboardVariableValue, isValidTimeZone } from '../dashboard/dashboard-variables-resolution';

// The relative dates offered by the time filters of a dashboard (DashboardRelativeDateSelect).
const RELATIVE_DATES: ReadonlySet<string> = new Set(['days-1', 'days-7', 'months-1', 'months-3', 'months-6', 'years-1']);

/**
 * Values frozen in a public dashboard, keyed by variable id: the default of each variable, replaced by the value the
 * author chose when publishing. A provided value is checked against the type of its variable, like a default value,
 * but not against its restriction: the author is an admin of the dashboard and could change the restriction anyway.
 * An empty value keeps the default.
 */
export const buildPublicationVariableValues = (
  variables: unknown,
  provided: readonly PublicDashboardVariableValueInput[] | null | undefined,
) => {
  const values = buildDashboardVariableDefaultValues(variables);
  const types = new Map<string, unknown>();
  if (Array.isArray(variables)) {
    variables.forEach((variable: { id?: unknown; type?: unknown } | null) => {
      if (typeof variable?.id === 'string') types.set(variable.id, variable.type);
    });
  }
  const seen = new Set<string>();
  (provided ?? []).forEach(({ variable_id: variableId, value }) => {
    if (!types.has(variableId)) throw FunctionalError('Unknown dashboard variable', { variableId });
    if (seen.has(variableId)) throw FunctionalError('Duplicated dashboard variable value', { variableId });
    seen.add(variableId);
    if (value.trim() === '') return;
    if (!isValidDashboardVariableValue(types.get(variableId), value)) {
      throw FunctionalError('Invalid dashboard variable value', { variableId });
    }
    values.set(variableId, value);
  });
  return values;
};

/**
 * The dashboard config with the time range chosen when publishing, with the rule of the time filters: a relative date
 * clears the absolute ones. Without range, the config of the dashboard is kept as is.
 */
export const applyPublicationTimeRange = (
  config: Record<string, unknown> | undefined,
  range: PublicDashboardTimeRangeInput | null | undefined,
): Record<string, unknown> => {
  if (!range) return { ...(config ?? {}) };
  const relativeDate = range.relative_date ?? null;
  const startDate = range.start_date ?? null;
  const endDate = range.end_date ?? null;
  const isValidDate = (date: string | null) => date === null || isStrictIsoDate(date);
  if ((relativeDate !== null && !RELATIVE_DATES.has(relativeDate)) || !isValidDate(startDate) || !isValidDate(endDate)) {
    throw FunctionalError('Invalid public dashboard time range');
  }
  if (relativeDate !== null) {
    return { ...config, relativeDate, startDate: null, endDate: null };
  }
  return { ...config, relativeDate: null, startDate, endDate };
};

/**
 * Time zone of the author, used to shift the date variables exactly as they were shown to them.
 * Unsupported or missing: undefined, the resolution then counts in UTC.
 */
export const toPublicationTimeZone = (timeZone: string | null | undefined) => {
  return timeZone && isValidTimeZone(timeZone) ? timeZone : undefined;
};
