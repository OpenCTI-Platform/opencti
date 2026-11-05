import { v4 as uuidv4 } from 'uuid';
import { copyToClipboard } from '../../../../../utils/utils';
import { APP_BASE_PATH } from '../../../../../relay/environment';
import type { FieldOption } from '../../../../../utils/field';
import type { DashboardConfig, DashboardVariable } from '../../../../../components/dashboard/dashboard-types';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import { buildDefaultVariableValues, isValidVariableValue } from '../../../../../components/dashboard/dashboardVariablesResolution';
import { dashboardVariablesStorageKey, parseVariablesParam, readStoredVariableValues } from '../../../../../components/dashboard/dashboardVariablesStorage';

/**
 * Generates a URI key slug from a dashboard name.
 * Strips non-ASCII characters and replaces spaces with hyphens.
 * Falls back to a UUID v4 if the resulting slug is empty (e.g. fully non-Latin name).
 */
export const generatePublicDashboardUriKey = (name: string): string => {
  const slug = name.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase();
  return slug || uuidv4();
};

export const copyPublicDashboardLinkUrl = (t: (text: string) => string, uriKey: string) => {
  copyToClipboard(
    t,
    `${window.location.origin}${APP_BASE_PATH}/public/dashboard/${uriKey.toLowerCase()}`,
  );
};

export interface PublishedTimeRange {
  startDate: string | null;
  endDate: string | null;
  relativeDate: string | null;
}

export interface PublicDashboardCreationFormData {
  name: string;
  enabled: boolean;
  uri_key: string;
  max_markings: FieldOption[];
  dashboard_id: string;
  // Frozen in the public dashboard (dashboard variables feature), keyed by variable id
  variable_values: Record<string, string>;
  time_range: PublishedTimeRange;
}

// A dashboard as the creation form loads it: the manifest holds the definitions, `variables` their usage.
export interface PublishableDashboard {
  id: string;
  manifest?: string | null;
  variables?: readonly { id: string; usedInWidgetIds: readonly string[] }[] | null;
}

export const EMPTY_PUBLISHED_TIME_RANGE: PublishedTimeRange = { startDate: null, endDate: null, relativeDate: null };

export const pickPublishedTimeRange = (config: DashboardConfig | undefined): PublishedTimeRange => ({
  startDate: config?.startDate ?? null,
  endDate: config?.endDate ?? null,
  relativeDate: config?.relativeDate ?? null,
});

export const isSamePublishedTimeRange = (a: PublishedTimeRange, b: PublishedTimeRange) => (
  a.startDate === b.startDate && a.endDate === b.endDate && a.relativeDate === b.relativeDate
);

/**
 * The variables offered when publishing: only those used by a widget, the others having no effect on the published
 * dashboard. In the manifest order.
 */
export const buildPublishedVariables = (
  variables: readonly DashboardVariable[],
  usage: PublishableDashboard['variables'],
): DashboardVariable[] => {
  const used = new Set((usage ?? []).filter(({ usedInWidgetIds }) => usedInWidgetIds.length > 0).map(({ id }) => id));
  return variables.filter((variable) => used.has(variable.id));
};

/**
 * Value of each variable: the one the user sees on the dashboard (stored locally) when still valid, else its default.
 */
export const buildPublishedVariableValues = (variables: DashboardVariable[], stored: Record<string, string>): Record<string, string> => {
  const values = Object.fromEntries(buildDefaultVariableValues(variables));
  variables.forEach((variable) => {
    const value = stored[variable.id];
    if (value !== undefined && isValidVariableValue(variable, value)) values[variable.id] = value;
  });
  return values;
};

/**
 * Whether `pathname` is the page of the dashboard `dashboardId`.
 */
const isDashboardPage = (pathname: string, dashboardId: string) => {
  const segments = pathname.split('/');
  return segments.some((segment, index) => segment === dashboardId && segments[index - 1] === 'dashboards');
};

/**
 * Values the form starts from for the selected dashboard, and starts again from when another one is selected: what
 * the author sees on the dashboard, with the same precedence as the page (URL, then this browser, then the default).
 * The URL only speaks for the dashboard it shows: it is read for the dashboard of the page, never for another one.
 * The time range is the one of the dashboard: it is not kept per user yet.
 */
export const buildPublishedValuesState = (
  dashboard: PublishableDashboard | undefined,
  userId: string,
  search: string = window.location.search,
  pathname: string = window.location.pathname,
): Pick<PublicDashboardCreationFormData, 'variable_values' | 'time_range'> => {
  if (!dashboard) return { variable_values: {}, time_range: EMPTY_PUBLISHED_TIME_RANGE };
  const manifest = deserializeDashboardManifestForFrontend(dashboard.manifest);
  const variables = buildPublishedVariables(manifest.variables ?? [], dashboard.variables);
  const stored = {
    ...readStoredVariableValues(dashboardVariablesStorageKey(userId, dashboard.id)),
    ...(isDashboardPage(pathname, dashboard.id) ? parseVariablesParam(search) : {}),
  };
  return {
    variable_values: buildPublishedVariableValues(variables, stored),
    time_range: pickPublishedTimeRange(manifest.config),
  };
};

/**
 * Same rule as the time filters of a dashboard: `none` empties the field, a relative date clears the absolute ones.
 */
export const applyPublishedTimeRangeChange = (
  range: PublishedTimeRange,
  type: keyof Pick<DashboardConfig, 'startDate' | 'endDate' | 'relativeDate'>,
  value: string | null,
): PublishedTimeRange => {
  const next = { ...range, [type]: value === 'none' ? null : value };
  return type === 'relativeDate' && value !== 'none' ? { ...next, startDate: null, endDate: null } : next;
};

/**
 * Input of the creation mutation. The published values are only sent with the dashboard variables feature:
 * without it, the input is exactly the one of before.
 */
export interface PublicDashboardPublicationInput {
  name: string;
  enabled: boolean;
  uri_key: string;
  dashboard_id: string;
  allowed_markings_ids: string[];
  variable_values?: { variable_id: string; value: string }[];
  time_range?: { relative_date: string | null; start_date: string | null; end_date: string | null };
  time_zone?: string;
}

export const buildPublicationInput = (values: PublicDashboardCreationFormData, isVariablesEnabled: boolean): PublicDashboardPublicationInput => {
  const input = {
    name: values.name,
    enabled: values.enabled,
    uri_key: values.uri_key,
    dashboard_id: values.dashboard_id,
    allowed_markings_ids: values.max_markings.map((marking) => marking.value),
  };
  if (!isVariablesEnabled) return input;
  return {
    ...input,
    variable_values: Object.entries(values.variable_values)
      .filter(([, value]) => value !== '')
      .map(([variableId, value]) => ({ variable_id: variableId, value })),
    time_range: {
      relative_date: values.time_range.relativeDate,
      start_date: values.time_range.startDate,
      end_date: values.time_range.endDate,
    },
    time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
};
