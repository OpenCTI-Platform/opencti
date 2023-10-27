import moment from 'moment';
import type { Filter } from './stix-filtering';

/**
 * Apply the boolean logic of testing the equality of some candidate values to an array of values.
 * It applies to "eq" and "not_eq" operators as well as "nil" and "not_nil", but not to numeric operator (lt, gt , etc.)
 * @param filter the raw filter
 * @param adaptedFilterValues filter.values adapted to the boolean logic implemented (e.g. parsing values to boolean, forcing lowercase)
 * @param stixCandidates the values inside the stix bundle that we compare to the filter values
 */
export const testEqualityByMode = ({ mode, operator }: Pick<Filter, 'mode' | 'operator'>, adaptedFilterValues: (string | boolean)[], stixCandidates: (string | boolean)[]) => {
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

  const allFound = adaptedFilterValues.every((v) => stixCandidates.includes(v));
  const oneFound = adaptedFilterValues.some((v) => stixCandidates.includes(v));

  if (mode === 'AND') {
    // we need to find all of them or none of them
    return (operator === 'eq' && allFound) || (operator === 'not_eq' && !oneFound);
  }
  if (mode === 'OR') {
    // we need to find one of them or at least one is not found
    return (operator === 'eq' && oneFound) || (operator === 'not_eq' && !allFound);
  }

  return false;
};

/**
 * Take a single value and return an array.
 * The array contains the value only if the value is defined, otherwise array is empty
 * Useful for using testEqualityByMode on a single stix value that might not be present
 */
export const toValidArray = <T = unknown>(v: T) => {
  if (v !== undefined && v !== null) {
    return [v];
  }
  return [];
};

/**
 * Apply a boolean logic on some numeric values to compare (eq, gt, lt... etc)
 * The stix candidate is compared to an array of filter values according to filter mode and operator.
 * The candidate can be null if the value is not present in stix bundle.
 * @param filter the raw filter, we'll parse its values to number
 * @param stixCandidate the value inside the stix bundle that we compare to the filter values, might be null
 * TODO: handle dates if needed in the future; fo now none of the filters used in streams use dates
 */
export const testNumericByMode = ({ mode, operator, values }: Pick<Filter, 'mode' | 'operator' | 'values'>, stixCandidate: number | null) => {
  const filterValuesAsNumbers = values.map((v) => parseInt(v, 10)).filter((n) => !Number.isNaN(n));

  if (operator === 'nil' || (operator === 'eq' && filterValuesAsNumbers.length === 0)) {
    return stixCandidate === null;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && filterValuesAsNumbers.length === 0)) {
    return stixCandidate !== null;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (stixCandidate === null) {
    return false;
  }

  if (mode === 'AND') {
    // value must compare to all candidates according to operator
    return (operator === 'eq' && filterValuesAsNumbers.every((c) => stixCandidate === c))
      || (operator === 'not_eq' && filterValuesAsNumbers.every((c) => stixCandidate !== c))
      || (operator === 'lt' && filterValuesAsNumbers.every((c) => stixCandidate < c))
      || (operator === 'lte' && filterValuesAsNumbers.every((c) => stixCandidate <= c))
      || (operator === 'gt' && filterValuesAsNumbers.every((c) => stixCandidate > c))
      || (operator === 'gte' && filterValuesAsNumbers.every((c) => stixCandidate >= c));
  }
  if (mode === 'OR') {
    // value must compare to at least one of the candidates according to operator
    return (operator === 'eq' && filterValuesAsNumbers.some((c) => stixCandidate === c))
      || (operator === 'not_eq' && filterValuesAsNumbers.some((c) => stixCandidate !== c))
      || (operator === 'lt' && filterValuesAsNumbers.some((c) => stixCandidate < c))
      || (operator === 'lte' && filterValuesAsNumbers.some((c) => stixCandidate <= c))
      || (operator === 'gt' && filterValuesAsNumbers.some((c) => stixCandidate > c))
      || (operator === 'gte' && filterValuesAsNumbers.some((c) => stixCandidate >= c));
  }

  return false;
};

export const testDateByMode = ({ mode, operator, values }: Pick<Filter, 'mode' | 'operator' | 'values'>, stixCandidate: string | null) => {
  const filterValuesAsDates = values.map((v) => moment(new Date(v))).filter((d) => d.isValid());

  if (operator === 'nil' || (operator === 'eq' && filterValuesAsDates.length === 0)) {
    return stixCandidate === null;
  }
  if (operator === 'not_nil' || (operator === 'not_eq' && filterValuesAsDates.length === 0)) {
    return stixCandidate !== null;
  }

  // excluding the cases above, comparing to nothing is not supported and would never match
  if (stixCandidate === null) {
    return false;
  }

  const stixDate = moment(new Date(stixCandidate));

  if (mode === 'AND') {
    // NOTE: equality is very strict (milliseconds)
    return (operator === 'eq' && filterValuesAsDates.every((c) => stixDate.isSame(c)))
      || (operator === 'not_eq' && filterValuesAsDates.every((c) => !stixDate.isSame(c)))
      || (operator === 'lt' && filterValuesAsDates.every((c) => stixDate.isBefore(c)))
      || (operator === 'lte' && filterValuesAsDates.every((c) => stixDate.isSameOrBefore(c)))
      || (operator === 'gt' && filterValuesAsDates.every((c) => stixDate.isAfter(c)))
      || (operator === 'gte' && filterValuesAsDates.every((c) => stixDate.isSameOrAfter(c)));
  }
  if (mode === 'OR') {
    // value must compare to at least one of the candidates according to operator
    return (operator === 'eq' && filterValuesAsDates.some((c) => stixDate.isSame(c)))
      || (operator === 'not_eq' && filterValuesAsDates.some((c) => !stixDate.isSame(c)))
      || (operator === 'lt' && filterValuesAsDates.some((c) => stixDate.isBefore(c)))
      || (operator === 'lte' && filterValuesAsDates.some((c) => stixDate.isSameOrBefore(c)))
      || (operator === 'gt' && filterValuesAsDates.some((c) => stixDate.isAfter(c)))
      || (operator === 'gte' && filterValuesAsDates.some((c) => stixDate.isSameOrAfter(c)));
  }

  return false;
};
