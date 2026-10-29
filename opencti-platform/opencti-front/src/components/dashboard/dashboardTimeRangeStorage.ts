import type { DashboardTimeRange } from './dashboardTimeRange';
import { isStrictIsoDate } from './dashboardVariablesResolution';

// The values of the relative time select (DashboardRelativeDateSelect), `none` aside: it is stored as null.
export const RELATIVE_DATE_VALUES: readonly string[] = ['days-1', 'days-7', 'months-1', 'months-3', 'months-6', 'years-1'];

export const TIME_RANGE_PARAM = 'timeRange';
const ABSOLUTE_RANGE_SEPARATOR = '..';

export const dashboardTimeRangeStorageKey = (userId: string, workspaceId: string) => `dashboard-time-range-${userId}-${workspaceId}`;

const isOptionalIsoDate = (value: unknown) => value === null || (typeof value === 'string' && isStrictIsoDate(value));

// A relative date always comes alone: picking one clears the absolute dates.
export const isValidTimeRange = (value: unknown): value is DashboardTimeRange => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const { startDate, endDate, relativeDate } = value as Record<string, unknown>;
  if (!isOptionalIsoDate(startDate) || !isOptionalIsoDate(endDate)) return false;
  if (relativeDate === null) return true;
  return typeof relativeDate === 'string' && RELATIVE_DATE_VALUES.includes(relativeDate) && startDate === null && endDate === null;
};

export const readStoredTimeRange = (key: string): DashboardTimeRange | null => {
  try {
    const raw = window.localStorage.getItem(key);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    if (!isValidTimeRange(parsed)) return null;
    return { startDate: parsed.startDate, endDate: parsed.endDate, relativeDate: parsed.relativeDate };
  } catch {
    return null;
  }
};

export const writeStoredTimeRange = (key: string, range: DashboardTimeRange | null) => {
  try {
    if (range === null) {
      window.localStorage.removeItem(key);
    } else {
      window.localStorage.setItem(key, JSON.stringify(range));
    }
  } catch {
    // Storage full or denied: the range stays in memory for the session, it is just not persisted.
  }
};

// `days-7` for a relative date, `<start>..<end>` otherwise, each side possibly empty.
export const serializeTimeRangeParam = (range: DashboardTimeRange) => (
  range.relativeDate ?? `${range.startDate ?? ''}${ABSOLUTE_RANGE_SEPARATOR}${range.endDate ?? ''}`
);

export const parseTimeRangeParam = (search: string): DashboardTimeRange | null => {
  const raw = new URLSearchParams(search).get(TIME_RANGE_PARAM);
  if (!raw) return null;
  const separator = raw.indexOf(ABSOLUTE_RANGE_SEPARATOR);
  const range = separator < 0
    ? { startDate: null, endDate: null, relativeDate: raw }
    : {
        startDate: raw.slice(0, separator) || null,
        endDate: raw.slice(separator + ABSOLUTE_RANGE_SEPARATOR.length) || null,
        relativeDate: null,
      };
  return isValidTimeRange(range) ? range : null;
};

export const writeTimeRangeParam = (range: DashboardTimeRange | null) => {
  const url = new URL(window.location.href);
  if (range === null) url.searchParams.delete(TIME_RANGE_PARAM);
  else url.searchParams.set(TIME_RANGE_PARAM, serializeTimeRangeParam(range));
  try {
    window.history.replaceState(window.history.state, '', url);
  } catch {
    // Browsers rate-limit history updates (SecurityError): the URL then lags behind, the state is not affected.
  }
};
