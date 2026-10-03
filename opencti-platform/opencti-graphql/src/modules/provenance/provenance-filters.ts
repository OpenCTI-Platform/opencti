import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';
import { ATTRIBUTE_LAST_ASSERTED_AT } from './provenance-types';

const DAY_IN_MS = 24 * 60 * 60 * 1000;

const daysAgo = (reference: Date, days: number) => new Date(reference.getTime() - days * DAY_IN_MS).toISOString();

const lastAssertedFilter = (operator: FilterOperator, date: string): Filter => ({
  key: [ATTRIBUTE_LAST_ASSERTED_AT],
  values: [date],
  operator,
  mode: FilterMode.Or,
});

/**
 * freshness_days is floor((now - last_asserted_at) / 1 day): each comparison on it is a range on last_asserted_at.
 */
const freshnessComparison = (operator: FilterOperator, days: number, reference: Date): FilterGroup => {
  const single = (filter: Filter): FilterGroup => ({ mode: FilterMode.And, filters: [filter], filterGroups: [] });
  switch (operator) {
    case FilterOperator.Gte:
      return single(lastAssertedFilter(FilterOperator.Lte, daysAgo(reference, days)));
    case FilterOperator.Gt:
      return single(lastAssertedFilter(FilterOperator.Lte, daysAgo(reference, days + 1)));
    case FilterOperator.Lte:
      return single(lastAssertedFilter(FilterOperator.Gt, daysAgo(reference, days + 1)));
    case FilterOperator.Lt:
      return single(lastAssertedFilter(FilterOperator.Gt, daysAgo(reference, days)));
    case FilterOperator.NotEq:
      return {
        mode: FilterMode.Or,
        filters: [lastAssertedFilter(FilterOperator.Lte, daysAgo(reference, days + 1)), lastAssertedFilter(FilterOperator.Gt, daysAgo(reference, days))],
        filterGroups: [],
      };
    case FilterOperator.Eq:
      return {
        mode: FilterMode.And,
        filters: [lastAssertedFilter(FilterOperator.Gt, daysAgo(reference, days + 1)), lastAssertedFilter(FilterOperator.Lte, daysAgo(reference, days))],
        filterGroups: [],
      };
    default:
      throw FunctionalError('Unsupported operator for the freshness filter', { operator });
  }
};

export const adaptFilterToFreshnessDaysFilterKey = (filter: Filter, reference: Date = new Date()): { newFilterGroup: FilterGroup } => {
  const operator = filter.operator ?? FilterOperator.Eq;
  if (operator === FilterOperator.Nil || operator === FilterOperator.NotNil) {
    return { newFilterGroup: { mode: FilterMode.And, filters: [{ key: [ATTRIBUTE_LAST_ASSERTED_AT], values: [], operator }], filterGroups: [] } };
  }
  const days = filter.values.map((value) => (/^\d+$/.test(String(value).trim()) ? Number(String(value).trim()) : Number.NaN));
  if (days.length === 0 || days.some((day) => !Number.isSafeInteger(day))) {
    throw FunctionalError('The freshness filter expects a number of days', { values: filter.values });
  }
  return {
    newFilterGroup: {
      mode: filter.mode ?? FilterMode.Or,
      filters: [],
      filterGroups: days.map((day) => freshnessComparison(operator, day, reference)),
    },
  };
};

// Fresh first (ascending freshness) is the most recent assertion first.
export const buildFreshnessDaysSorting = (orderMode: 'asc' | 'desc' | null) => ({
  [ATTRIBUTE_LAST_ASSERTED_AT]: { order: orderMode === 'desc' ? 'asc' : 'desc', missing: 0 },
});
