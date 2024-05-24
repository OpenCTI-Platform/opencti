import moment from 'moment';
import type { Filter, FilterGroup } from '../../generated/graphql';
import { isFilterGroupNotEmpty } from './filtering-utils';

type FilterLogic = Pick<Filter, 'mode' | 'operator'>;
type FilterExcerpt = Pick<Filter, 'mode' | 'operator' | 'values'>;

/**
 * The Boolean Logic Engine is responsible for testing some data recursively against a filter group.
 * The model of the data is unknown (specifically, we are not using any stix concept here).
 * The engine job is to compare strings, booleans, numbers and dates with a nested AND/OR logic.
 */

/**
 * Utility function that takes a single value and return an array.
 * The array contains the value only if the value is defined, otherwise array is empty
 */
export const toValidArray = <T = unknown>(v: T) => {
  if (v !== undefined && v !== null) {
    return [v];
  }
  return [];
};

/**
 * Apply the filtering logic on values that are compatible with simple arithmetic operators (string, number, boolean).
 *  - With operator gt, gte, lt or lte, string values are compared alphabetically.
 *  - With boolean values, expect these operators to work as if true is 1 and false 0 (i.e. true > false).
 * @param filter the filter with mode and operator
 * @param adaptedFilterValues filter.values (strings) adapted for the test (e.g. parsing numbers, forcing lower case...)
 * @param stixCandidates the values inside the DATA that we compare to the filter values; they are properly types
 *                       We always assume an array of value(s) ; use toValidArray if the data is a single, nullable value.
 */
export const testGenericFilter = <T extends string | number | boolean>({ mode, operator }: FilterLogic, adaptedFilterValues: T[], stixCandidates: T[]) => {
  // "(not) nil" or "(not) equal to nothing" is resolved the same way
  if (operator === 'nil' || (operator === 'eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length === 0;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length > 0;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (adaptedFilterValues.length === 0) {
    return false;
  }
  if (mode === 'and') {
    // we need to find all of them or none of them
    return (operator === 'eq' && adaptedFilterValues.every((v) => stixCandidates.includes(v)))
      || (operator === 'not_eq' && adaptedFilterValues.every((v) => !stixCandidates.includes(v)))
      || (operator === 'contains' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (operator === 'not_contains' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (operator === 'starts_with' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (operator === 'not_starts_with' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (operator === 'ends_with' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (operator === 'not_ends_with' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (operator === 'search' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string'
        && (v.split(' ').some((word) => c.includes(word)))))) // a stix candidate should contains at least one of the filter values words

      // In real cases, there is only 1 filter value with the next operators (not much sense otherwise)
      || (operator === 'lt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c < v)))
      || (operator === 'lte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c <= v)))
      || (operator === 'gt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c > v)))
      || (operator === 'gte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c >= v)));
  }

  if (mode === 'or') {
    // we need to find one of them or at least one is not found
    return (operator === 'eq' && adaptedFilterValues.some((v) => stixCandidates.includes(v)))
      || (operator === 'not_eq' && adaptedFilterValues.some((v) => !stixCandidates.includes(v)))
      || (operator === 'contains' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (operator === 'not_contains' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (operator === 'starts_with' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (operator === 'not_starts_with' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (operator === 'ends_with' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (operator === 'not_ends_with' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (operator === 'search' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string'
        && (v.split(' ').some((word) => c.includes(word)))))) // a stix candidate should contains at least one of the filter values words

      // In real cases, there is only 1 filter value with the next operators (not much sense otherwise)
      || (operator === 'lt' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c < v)))
      || (operator === 'lte' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c <= v)))
      || (operator === 'gt' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c > v)))
      || (operator === 'gte' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c >= v)));
  }

  return false;
};

/**
 * Implementation of testGenericFilter for string values.
 * String comparison is insensitive to case, and we trim values by default.
 */
export const testStringFilter = (filter: FilterExcerpt, stixCandidates: string[]) => {
  const filterValuesLowerCase = filter.values.map((v) => v.toLowerCase().trim());
  const stixValuesLowerCase = stixCandidates.map((v) => v.toLowerCase().trim());
  return testGenericFilter<string>(filter, filterValuesLowerCase, stixValuesLowerCase);
};

/**
 * Implementation of testGenericFilter for boolean values.
 * Filter values are parsed as booleans
 * The strings "true", "yes" or "1" are interpreted as true ; anything else is false.
 */
export const testBooleanFilter = (filter: FilterExcerpt, stixCandidate: boolean | null | undefined) => {
  const filterValuesAsBooleans = filter.values.map((v) => v.toLowerCase() === 'true' || v.toLowerCase() === 'yes' || v === '1');
  return testGenericFilter<boolean>(filter, filterValuesAsBooleans, toValidArray(stixCandidate));
};

/**
 * Implementation of testGenericFilter for numerical values.
 * Filter values are parsed as floats.
 */
export const testNumericFilter = (filter: FilterExcerpt, stixCandidate: number | null | undefined) => {
  const filterValuesAsNumbers = filter.values.map((v) => parseFloat(v)).filter((n) => !Number.isNaN(n));
  return testGenericFilter<number>(filter, filterValuesAsNumbers, toValidArray(stixCandidate));
};

/**
 * Specific tester using the Moment.js library to compare dates.
 */
export const testDateFilter = ({ mode, operator, values }: FilterExcerpt, stixCandidate: string | null | undefined) => {
  // make sure the dates are valid, otherwise we won't use them.
  const filterValuesAsDates = values.map((v) => moment(new Date(v))).filter((d) => d.isValid());

  if (operator === 'nil' || (operator === 'eq' && filterValuesAsDates.length === 0)) {
    return stixCandidate === null;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && filterValuesAsDates.length === 0)) {
    return stixCandidate !== null;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (stixCandidate === null || stixCandidate === undefined) {
    return false;
  }

  const stixDate = moment(new Date(stixCandidate));
  if (!stixDate.isValid()) {
    // This is actually an error case that should not happen (invalid stix)
    return false;
  }

  if (mode === 'and') {
    // NOTE: equality is very strict (milliseconds)
    return (operator === 'eq' && filterValuesAsDates.every((v) => stixDate.isSame(v)))
      || (operator === 'not_eq' && filterValuesAsDates.every((v) => !stixDate.isSame(v)))
      || (operator === 'lt' && filterValuesAsDates.every((v) => stixDate.isBefore(v)))
      || (operator === 'lte' && filterValuesAsDates.every((v) => stixDate.isSameOrBefore(v)))
      || (operator === 'gt' && filterValuesAsDates.every((v) => stixDate.isAfter(v)))
      || (operator === 'gte' && filterValuesAsDates.every((v) => stixDate.isSameOrAfter(v)));
  }
  if (mode === 'or') {
    // value must compare to at least one of the candidates according to operator
    return (operator === 'eq' && filterValuesAsDates.some((v) => stixDate.isSame(v)))
      || (operator === 'not_eq' && filterValuesAsDates.some((v) => !stixDate.isSame(v)))
      || (operator === 'lt' && filterValuesAsDates.some((v) => stixDate.isBefore(v)))
      || (operator === 'lte' && filterValuesAsDates.some((v) => stixDate.isSameOrBefore(v)))
      || (operator === 'gt' && filterValuesAsDates.some((v) => stixDate.isAfter(v)))
      || (operator === 'gte' && filterValuesAsDates.some((v) => stixDate.isSameOrAfter(v)));
  }

  return false;
};

//----------------------------------------------------------------------------------------------------------------------

// generic representation of a tester function
// its implementations are dependent on the data model, to find the information requested by the filter
export type TesterFunction = (data: any, filter: Filter) => boolean;

/**
 * Recursive function that tests a complex filter group.
 * Thanks to the param getTesterFromFilterKey, this function is agnostic of the data content and how to test it.
 * It only takes care of the recursion mechanism.
 * @param data data to test
 * @param filterGroup complex filter group object with nested groups and filters
 * @param testerByFilterKeyMap function that gives a function to test a filter, according to the filter key
 *                               see unit tests for an example.
 */
export const testFilterGroup = (data: any, filterGroup: FilterGroup, testerByFilterKeyMap: Record<string, TesterFunction>) : boolean => {
  if (!isFilterGroupNotEmpty(filterGroup)) return true; // no filters -> stix always match
  if (filterGroup.mode === 'and') {
    const results: boolean[] = [];
    if (filterGroup.filters.length > 0) {
      // note that we are not compatible with multiple keys yet, so we'll always check the first one only
      results.push(filterGroup.filters.every((filter) => testerByFilterKeyMap[filter.key[0]]?.(data, filter)));
    }
    if (filterGroup.filterGroups.length > 0) {
      results.push(filterGroup.filterGroups.every((fg) => testFilterGroup(data, fg, testerByFilterKeyMap)));
    }
    return results.length > 0 && results.every((isTrue) => isTrue);
  }

  if (filterGroup.mode === 'or') {
    const results: boolean[] = [];
    if (filterGroup.filters.length > 0) {
      results.push(filterGroup.filters.some((filter) => testerByFilterKeyMap[filter.key[0]]?.(data, filter)));
    }
    if (filterGroup.filterGroups.length > 0) {
      results.push(filterGroup.filterGroups.some((fg) => testFilterGroup(data, fg, testerByFilterKeyMap)));
    }
    return results.length > 0 && results.some((isTrue) => isTrue);
  }

  return false;
};
