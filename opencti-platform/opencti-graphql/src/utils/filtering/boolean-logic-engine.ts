import { isValid as fnsIsValid } from 'date-fns';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
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
 * @param changeContext optional context for has_changed evaluation: { filterKey, eventContext }
 */
export const testGenericFilter = <T extends string | number | boolean>(
  { mode = FilterMode.Or, operator = FilterOperator.Eq }: FilterLogic,
  adaptedFilterValues: T[],
  stixCandidates: T[],
  changeContext?: { filterKey: string; eventContext: FilterEventContext },
): boolean => {
  const op = operator ?? 'eq';
  const operationMode = mode ?? 'or';

  // has_changed / not_has_changed operators
  if (op === 'has_changed' || op === 'not_has_changed') {
    const isHasChanged = op === 'has_changed';
    if (!changeContext) return !isHasChanged;
    const { filterKey, eventContext } = changeContext;
    if (eventContext.isCreation) {
      // Creation: "has changed" if the field has a non-null value
      return isHasChanged ? stixCandidates.length > 0 : stixCandidates.length === 0;
    }
    // Update: check if the filter key is in the changed attributes list
    const changed = eventContext.changedAttributes.includes(filterKey);
    return isHasChanged ? changed : !changed;
  }

  // "(not) nil" or "(not) equal to nothing" is resolved the same way
  if (op === 'nil' || (op === 'eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length === 0;
  }
  if (op === 'not_nil' || (op === 'not_eq' && adaptedFilterValues.length === 0)) {
    return stixCandidates.length > 0;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (adaptedFilterValues.length === 0) {
    return false;
  }
  if (operationMode === 'and') {
    // we need to find all of them or none of them
    return (op === 'eq' && adaptedFilterValues.every((v) => stixCandidates.includes(v)))
      || (op === 'not_eq' && adaptedFilterValues.every((v) => !stixCandidates.includes(v)))
      || (op === 'contains' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (op === 'not_contains' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (op === 'starts_with' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (op === 'not_starts_with' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (op === 'ends_with' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (op === 'not_ends_with' && adaptedFilterValues.every((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (op === 'only_eq_to' && adaptedFilterValues.every((v) => stixCandidates.includes(v)) && stixCandidates.every((c) => adaptedFilterValues.includes(c)))
      || (op === 'not_only_eq_to' && !(adaptedFilterValues.every((v) => stixCandidates.includes(v)) && stixCandidates.every((c) => adaptedFilterValues.includes(c))))
      || (op === 'search' && adaptedFilterValues.every((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string'
        && (v.split(' ').some((word) => c.includes(word)))))) // a stix candidate should contain at least one of the filter values words

    // In real cases, there is only 1 filter value with the next operators (not much sense otherwise)
        || (op === 'lt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c < v)))
        || (op === 'lte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c <= v)))
        || (op === 'gt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c > v)))
        || (op === 'gte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c >= v)));
  }

  if (operationMode === 'or') {
    // we need to find one of them or at least one is not found
    return (op === 'eq' && adaptedFilterValues.some((v) => stixCandidates.includes(v)))
      || (op === 'not_eq' && adaptedFilterValues.some((v) => !stixCandidates.includes(v)))
      || (op === 'contains' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (op === 'not_contains' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.includes(v))))
      || (op === 'starts_with' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (op === 'not_starts_with' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.startsWith(v))))
      || (op === 'ends_with' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (op === 'not_ends_with' && adaptedFilterValues.some((v) => !stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string' && c.endsWith(v))))
      || (op === 'only_eq_to' && stixCandidates.length === 1 && adaptedFilterValues.some((v) => stixCandidates[0] === v))
      || (op === 'not_only_eq_to' && !(stixCandidates.length === 1 && adaptedFilterValues.some((v) => stixCandidates[0] === v)))
      || (op === 'search' && adaptedFilterValues.some((v) => stixCandidates.some((c) => typeof c === 'string' && typeof v === 'string'
        && (v.split(' ').some((word) => c.includes(word)))))) // a stix candidate should contain at least one of the filter values words

    // In real cases, there is only 1 filter value with the next operators (not much sense otherwise)
        || (op === 'lt' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c < v)))
        || (op === 'lte' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c <= v)))
        || (op === 'gt' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c > v)))
        || (op === 'gte' && adaptedFilterValues.some((v) => stixCandidates.some((c) => c >= v)));
  }

  return false;
};

/**
 * Implementation of testGenericFilter for string values.
 * String comparison is insensitive to case, and we trim values by default.
 */
export const testStringFilter = (filter: FilterExcerpt, stixCandidates: string[], changeContext?: { filterKey: string; eventContext: FilterEventContext }) => {
  const filterValuesLowerCase = filter.values.map((v) => v.toLowerCase().trim());
  const stixValuesLowerCase = stixCandidates.map((v) => v.toLowerCase().trim());
  return testGenericFilter<string>(filter, filterValuesLowerCase, stixValuesLowerCase, changeContext);
};

/**
 * Implementation of testGenericFilter for boolean values.
 * Filter values are parsed as booleans
 * The strings "true", "yes" or "1" are interpreted as true ; anything else is false.
 */
export const testBooleanFilter = (filter: FilterExcerpt, stixCandidate: boolean | null | undefined, changeContext?: { filterKey: string; eventContext: FilterEventContext }) => {
  const filterValuesAsBooleans = filter.values.map((v) => v.toLowerCase() === 'true' || v.toLowerCase() === 'yes' || v === '1');
  return testGenericFilter<boolean>(filter, filterValuesAsBooleans, toValidArray(stixCandidate), changeContext);
};

/**
 * Implementation of testGenericFilter for numerical values.
 * Filter values are parsed as floats.
 */
export const testNumericFilter = (filter: FilterExcerpt, stixCandidate: number | null | undefined, changeContext?: { filterKey: string; eventContext: FilterEventContext }) => {
  const filterValuesAsNumbers = filter.values.map((v) => parseFloat(v)).filter((n) => !Number.isNaN(n));
  return testGenericFilter<number>(filter, filterValuesAsNumbers, toValidArray(stixCandidate), changeContext);
};

/**
 * Specific tester using the Moment.js library to compare dates.
 */
export const testDateFilter = ({ mode, operator, values }: FilterExcerpt, stixCandidate: string | null | undefined) => {
  // make sure the dates are valid, otherwise we won't use them.
  const filterValuesAsDates = values.map((v) => new Date(v)).filter((d) => fnsIsValid(d) && !Number.isNaN(d.getTime()));

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

  const stixDate = new Date(stixCandidate);
  if (!fnsIsValid(stixDate) || Number.isNaN(stixDate.getTime())) {
    // This is actually an error case that should not happen (invalid stix)
    return false;
  }

  const stixTime = stixDate.getTime();
  if (mode === 'and') {
    // NOTE: equality is very strict (milliseconds)
    return (operator === 'eq' && filterValuesAsDates.every((v) => stixTime === v.getTime()))
      || (operator === 'not_eq' && filterValuesAsDates.every((v) => stixTime !== v.getTime()))
      || (operator === 'lt' && filterValuesAsDates.every((v) => stixTime < v.getTime()))
      || (operator === 'lte' && filterValuesAsDates.every((v) => stixTime <= v.getTime()))
      || (operator === 'gt' && filterValuesAsDates.every((v) => stixTime > v.getTime()))
      || (operator === 'gte' && filterValuesAsDates.every((v) => stixTime >= v.getTime()));
  }
  if (mode === 'or') {
    // value must compare to at least one of the candidates according to operator
    return (operator === 'eq' && filterValuesAsDates.some((v) => stixTime === v.getTime()))
      || (operator === 'not_eq' && filterValuesAsDates.some((v) => stixTime !== v.getTime()))
      || (operator === 'lt' && filterValuesAsDates.some((v) => stixTime < v.getTime()))
      || (operator === 'lte' && filterValuesAsDates.some((v) => stixTime <= v.getTime()))
      || (operator === 'gt' && filterValuesAsDates.some((v) => stixTime > v.getTime()))
      || (operator === 'gte' && filterValuesAsDates.some((v) => stixTime >= v.getTime()));
  }

  return false;
};

// ----------------------------------------------------------------------------------------------------------------------

// generic representation of a tester function
// its implementations are dependent on the data model, to find the information requested by the filter
export type TesterFunction = (data: any, filter: Filter, changeContext?: { filterKey: string; eventContext: FilterEventContext }) => boolean;

/**
 * Optional event context passed through the filtering pipeline.
 * Used to evaluate has_changed/not_has_changed operators.
 */
export interface FilterEventContext {
  changedAttributes: string[]; // Filter keys of attributes that changed (e.g., ['confidence', 'workflow_id'])
  isCreation?: boolean; // When true, has_changed evaluates to true if the field has a non-null value in the created entity
}

/**
 * Recursive function that tests a complex filter group.
 * Thanks to the param getTesterFromFilterKey, this function is agnostic of the data content and how to test it.
 * It only takes care of the recursion mechanism.
 * @param data data to test
 * @param filterGroup complex filter group object with nested groups and filters
 * @param testerByFilterKeyMap function that gives a function to test a filter, according to the filter key
 *                               see unit tests for an example.
 * @param eventContext optional context from the stream event (for has_changed evaluation)
 */
export const testFilterGroup = (data: any, filterGroup: FilterGroup, testerByFilterKeyMap: Record<string, TesterFunction>, eventContext?: FilterEventContext): boolean => {
  if (!isFilterGroupNotEmpty(filterGroup)) return true; // no filters -> stix always match

  const testSingleFilter = (filter: Filter): boolean => {
    const changeContext = eventContext ? { filterKey: filter.key[0], eventContext } : undefined;
    const tester = testerByFilterKeyMap[filter.key[0]];
    if (!tester) return false;
    return tester(data, filter, changeContext);
  };

  if (filterGroup.mode === 'and') {
    const results: boolean[] = [];
    if (filterGroup.filters.length > 0) {
      results.push(filterGroup.filters.every((filter) => testSingleFilter(filter)));
    }
    if (filterGroup.filterGroups.length > 0) {
      results.push(filterGroup.filterGroups.every((fg) => testFilterGroup(data, fg, testerByFilterKeyMap, eventContext)));
    }
    return results.length > 0 && results.every((isTrue) => isTrue);
  }

  if (filterGroup.mode === 'or') {
    const results: boolean[] = [];
    if (filterGroup.filters.length > 0) {
      results.push(filterGroup.filters.some((filter) => testSingleFilter(filter)));
    }
    if (filterGroup.filterGroups.length > 0) {
      results.push(filterGroup.filterGroups.some((fg) => testFilterGroup(data, fg, testerByFilterKeyMap, eventContext)));
    }
    return results.length > 0 && results.some((isTrue) => isTrue);
  }

  return false;
};
