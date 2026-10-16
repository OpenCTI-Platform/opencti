import { addDays } from 'date-fns';
import type { DashboardVariable } from './dashboard-types';

// Mirror of opencti-graphql/src/modules/dashboard/dashboard-variables-resolution.ts.
// Both are locked by opencti-graphql/tests/data/dashboard-variables/resolution-cases.json.

const UUID_PATTERN = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const TOKEN_REGEXP = new RegExp(`^\\$var:(${UUID_PATTERN})$`);

type FilterGroupLike = { filters: unknown[]; filterGroups?: unknown[] };
type SubFilterLike = { key: unknown; values: unknown[]; operator?: unknown };

export interface VariablesResolutionOptions {
  // Ids of the variables of type date: their value is shifted like a fixed date for the lte and gt operators.
  dateVariableIds?: ReadonlySet<string>;
  // IANA time zone in which the day shift of a date variable is counted, the one of the browser by default.
  timeZone?: string;
}

// A fixed date D is stored as D + 1 day 00:00 for these operators (FilterValueInput, FilterOperatorSelect), so that
// "<= D" includes the whole day D and "> D" excludes it. A date variable gets the same shift when it is substituted.
const DAY_SHIFTED_DATE_OPERATORS = ['lte', 'gt'];

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

// Time zones already reported as unusable: the fallback warns once per zone, not for every value it shifts.
const warnedUnusableTimeZones = new Set<string>();

// Formatter of the wall clock time in `timeZone`, or null when the browser cannot use the time zone: an id that `Intl`
// rejects (a browser with limited ICU), or `Etc/Unknown` (a host without configured time zone).
const buildWallClockFormatter = (timeZone: string): Intl.DateTimeFormat | null => {
  if (!timeZone) return null;
  const formatOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hourCycle: 'h23',
  };
  try {
    const formatter = new Intl.DateTimeFormat('en-US', { ...formatOptions, timeZone });
    const resolvedTimeZone = formatter.resolvedOptions().timeZone;
    return resolvedTimeZone && resolvedTimeZone !== 'Etc/Unknown' ? formatter : null;
  } catch {
    return null;
  }
};

// Wall clock time of an instant in the time zone of the formatter, as the timestamp showing the same wall clock in UTC.
const toWallClock = (time: number, formatter: Intl.DateTimeFormat) => {
  const parts: Record<string, number> = {};
  formatter.formatToParts(new Date(time)).forEach(({ type, value }) => {
    parts[type] = Number(value);
  });
  const wallClock = new Date(0);
  // setUTCFullYear, unlike Date.UTC, does not map the years 0 to 99 to 1900 to 1999.
  wallClock.setUTCFullYear(parts.year, parts.month - 1, parts.day);
  wallClock.setUTCHours(parts.hour % 24, parts.minute, parts.second, new Date(time).getUTCMilliseconds());
  return wallClock.getTime();
};

/**
 * One calendar day after `isoString` in `timeZone`, at the same wall clock time: local midnight stays local midnight,
 * so the result is 23 or 25 hours later across a daylight saving change. Counted in the time zone of the browser, it is
 * the date-fns `addDays` of the fixed date input (FilterValueInput).
 * A wall clock time skipped by a daylight saving change (gap) gives the instant after the gap, moved forward by the
 * length of the gap; a wall clock time repeated by a change (overlap) gives its first occurrence. Both follow JavaScript
 * dates, hence date-fns. A value that is not a date is returned unchanged. A time zone the browser cannot use falls back,
 * with a warning, to the date-fns `addDays` of the fixed date input itself (local calendar day of the browser), so that
 * both stay aligned; UTC, the fallback of the back, would shift the day by the offset of the browser.
 */
const addCalendarDayInTimeZone = (isoString: string, timeZone: string): string => {
  const time = new Date(isoString).getTime();
  if (Number.isNaN(time)) return isoString;
  const formatter = buildWallClockFormatter(timeZone);
  if (!formatter) {
    if (!warnedUnusableTimeZones.has(timeZone)) {
      warnedUnusableTimeZones.add(timeZone);
      console.warn(`Dashboard variables: unusable time zone "${timeZone}", date variables are shifted by one local calendar day instead`);
    }
    return addDays(new Date(isoString), 1).toISOString();
  }
  const offsetAt = (instant: number) => toWallClock(instant, formatter) - instant;
  const targetWallClock = toWallClock(time, formatter) + ONE_DAY_MS;
  // Offsets of the zone on both sides of a daylight saving change that may happen around the target.
  const offsetBefore = offsetAt(targetWallClock - ONE_DAY_MS);
  const offsetAfter = offsetAt(targetWallClock + ONE_DAY_MS);
  const beforeCandidate = targetWallClock - offsetBefore;
  const afterCandidate = targetWallClock - offsetAfter;
  // The offset before the change is kept when it is valid at the target (no change, or the first occurrence of an
  // overlap) and in a gap, where no offset is valid; the offset after the change only when the change precedes the target.
  const isAfterChange = offsetAt(beforeCandidate) !== offsetBefore && offsetAt(afterCandidate) === offsetAfter;
  return new Date(isAfterChange ? afterCandidate : beforeCandidate).toISOString();
};

const browserTimeZone = () => Intl.DateTimeFormat().resolvedOptions().timeZone;

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
 * The value of a date variable (`options.dateVariableIds`) in a filter of operator lte or gt is shifted by one calendar
 * day in `options.timeZone` (the one of the browser by default), exactly as a fixed date is when it is picked: switching
 * a filter between a fixed date and a variable keeps its result.
 * A token without a (non-empty, non-token) value is kept in place and reported in `unresolved`:
 * the widget must then not run its query (fail closed), never run it without the filter.
 */
export const resolveVariablesInFilterGroup = <T>(
  filterGroup: T,
  values: ReadonlyMap<string, string>,
  options: VariablesResolutionOptions = {},
): { filters: T; unresolved: string[] } => {
  const unresolved: string[] = [];
  // `operator` is the one of the filter holding the value; a sub filter (regardingOf) has none of its own.
  const resolveValue = (value: unknown, operator?: unknown): unknown => {
    const variableId = parseVariableToken(value);
    if (variableId !== null) {
      const current = values.get(variableId);
      // A value that is itself a token is not resolved further (no chaining, no cycle): fail closed.
      if (current === undefined || current === '' || parseVariableToken(current) !== null) {
        if (!unresolved.includes(variableId)) unresolved.push(variableId);
        return value;
      }
      const isDayShifted = options.dateVariableIds?.has(variableId) && DAY_SHIFTED_DATE_OPERATORS.includes(operator as string);
      return isDayShifted ? addCalendarDayInTimeZone(current, options.timeZone ?? browserTimeZone()) : current;
    }
    if (isFilterGroupLike(value)) return resolveGroup(value);
    if (isSubFilterLike(value)) return resolveFilter(value);
    return value;
  };
  const resolveFilter = (filter: SubFilterLike): SubFilterLike => ({
    ...filter,
    values: filter.values.map((value) => resolveValue(value, filter.operator)),
  });
  const resolveGroup = (group: FilterGroupLike): FilterGroupLike => {
    const result: FilterGroupLike = {
      ...group,
      filters: group.filters.map((filter) => (isSubFilterLike(filter) ? resolveFilter(filter) : filter)),
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

// Strict ISO-8601 date: `YYYY-MM-DD`, or a date-time `YYYY-MM-DDTHH:mm`, `…:ss` or `…:ss.s` (1 to 3 digits) ending with
// a time zone designator, `Z` or `±HH:mm`. Outside this format `Date.parse` depends on the JavaScript engine (V8 parses
// `2024/01/01` or `March 7 2024`, Safari does not), and a date-time without designator is local time in some engines
// and UTC in others. Written identically in the back (dashboard-variables-resolution.ts).
const ISO_DATE_REGEXP = /^(\d{4})-(\d{2})-(\d{2})(?:T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,3})?)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d))?$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * Whether `value` is a strict ISO-8601 date (see ISO_DATE_REGEXP) of an existing calendar day, which every engine parses
 * to the same instant. A day that does not exist (`2024-02-30`) is refused: some engines roll it over, others refuse it.
 */
export const isStrictIsoDate = (value: string): boolean => {
  const match = ISO_DATE_REGEXP.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12) return false;
  const isLeapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = month === 2 && isLeapYear ? 29 : DAYS_IN_MONTH[month - 1];
  return day >= 1 && day <= daysInMonth && !Number.isNaN(Date.parse(value));
};

// The rules of a value that depend on the type of its variable only, not on its selection restriction.
const isValidValueForType = (type: DashboardVariable['type'], value: string): boolean => {
  const trimmed = value.trim();
  if (trimmed === '' || value.includes(toVariableToken(''))) return false;
  switch (type) {
    case 'boolean':
      return value === 'true' || value === 'false';
    case 'numeric':
      return value === trimmed && Number.isFinite(Number(value));
    case 'date':
      return isStrictIsoDate(value);
    default:
      return true;
  }
};

/**
 * Default value of each variable, keyed by variable id. A default invalid for the type of its variable (a manifest
 * import may hold one, e.g. a numeric with surrounding spaces) is ignored: the widgets using it stay unresolved.
 * The selection restriction is not checked here: the default of a selection variable is checked when it is written.
 */
export const buildDefaultVariableValues = (variables: DashboardVariable[] | undefined) => {
  const values = new Map<string, string>();
  (variables ?? []).forEach((variable) => {
    if (variable.defaultValue && isValidValueForType(variable.type, variable.defaultValue)) {
      values.set(variable.id, variable.defaultValue);
    }
  });
  return values;
};

/**
 * Whether a value coming from the user's browser (localStorage, `variables` URL param) may be applied to a variable.
 * Same rules as the default value of a variable (`validateDraft` in variables/dashboardVariableDraft.ts):
 * a boolean is `true` or `false`, a numeric a finite number, a date a strict ISO-8601 date (`isStrictIsoDate`), any other
 * type a non-blank string; no value may reference another variable. A selection restriction also bounds the value to its pool.
 * A boolean, numeric or date value is taken as is, never trimmed: one with surrounding spaces is refused, since it would
 * otherwise reach the filters of the widgets with its spaces.
 * A value failing it is ignored, so the default of the variable applies.
 */
export const isValidVariableValue = (variable: DashboardVariable, value: string): boolean => {
  if (!isValidValueForType(variable.type, value)) return false;
  return variable.restriction.mode !== 'selection' || variable.restriction.values.includes(value);
};
