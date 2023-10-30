import moment from 'moment';
import type { Filter } from './stix-filtering';

type FilterLogic = Pick<Filter, 'mode' | 'operator'>;
type FilterExcerpt = Pick<Filter, 'mode' | 'operator' | 'values'>;

/**
 * Take a single value and return an array.
 * The array contains the value only if the value is defined, otherwise array is empty
 */
export const toValidArray = <T = unknown>(v: T) => {
  if (v !== undefined && v !== null) {
    return [v];
  }
  return [];
};

/**
 * Apply the boolean logic of testing the equality of some candidate values to an array of values.
 * It works with string, numeric, and boolean values.
 * Note that with operator gt, gte, lt or lte, string values are compared alphabetically.
 * With boolean values, expect these operators to work as if true is 1 and false 0 (i.e. true > false).
 * @param filter the filter with mode and operator
 * @param adaptedFilterValues filter.values (strings) adapted for the test (e.g. parsing numbers, forcing lower case...)
 * @param stixCandidates the values inside the stix bundle that we compare to the filter values; they are properly types
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
  if (mode === 'AND') {
    // we need to find all of them or none of them
    return (operator === 'eq' && adaptedFilterValues.every((v) => stixCandidates.includes(v)))
      || (operator === 'not_eq' && adaptedFilterValues.every((v) => !stixCandidates.includes(v)))

      // In real cases, there is only 1 filter value with the next operators (not much sense otherwise)
      || (operator === 'lt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c < v)))
      || (operator === 'lte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c <= v)))
      || (operator === 'gt' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c > v)))
      || (operator === 'gte' && adaptedFilterValues.every((v) => stixCandidates.some((c) => c >= v)));
  }

  if (mode === 'OR') {
    // we need to find one of them or at least one is not found
    return (operator === 'eq' && adaptedFilterValues.some((v) => stixCandidates.includes(v)))
      || (operator === 'not_eq' && adaptedFilterValues.some((v) => !stixCandidates.includes(v)))

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
 * String comparison is insensitive to case.
 */
export const testStringFilter = (filter: FilterExcerpt, stixCandidates: string[]) => {
  const filterValuesLowerCase = filter.values.map((v) => v.toLowerCase());
  const stixValuesLowerCase = stixCandidates.map((v) => v.toLowerCase());
  return testGenericFilter<string>(filter, filterValuesLowerCase, stixValuesLowerCase);
};

/**
 * Implementation of testGenericFilter for boolean values.
 * Filter values are parsed as booleans.
 */
export const testBooleanFilter = (filter: FilterExcerpt, stixCandidate: boolean | null | undefined) => {
  const filterValuesAsBooleans = filter.values.map((v) => v.toLowerCase() === 'true' || v === '1');
  return testGenericFilter<boolean>(filter, filterValuesAsBooleans, toValidArray(stixCandidate));
};

/**
 * Implementation of testGenericFilter for numerical values.
 * Filter values are parsed as integers.
 */
export const testNumericFilter = (filter: FilterExcerpt, stixCandidate: number | null | undefined) => {
  const filterValuesAsNumbers = filter.values.map((v) => parseInt(v, 10)).filter((n) => !Number.isNaN(n));
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

  if (mode === 'AND') {
    // NOTE: equality is very strict (milliseconds)
    return (operator === 'eq' && filterValuesAsDates.every((v) => stixDate.isSame(v)))
      || (operator === 'not_eq' && filterValuesAsDates.every((v) => !stixDate.isSame(v)))
      || (operator === 'lt' && filterValuesAsDates.every((v) => stixDate.isBefore(v)))
      || (operator === 'lte' && filterValuesAsDates.every((v) => stixDate.isSameOrBefore(v)))
      || (operator === 'gt' && filterValuesAsDates.every((v) => stixDate.isAfter(v)))
      || (operator === 'gte' && filterValuesAsDates.every((v) => stixDate.isSameOrAfter(v)));
  }
  if (mode === 'OR') {
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
