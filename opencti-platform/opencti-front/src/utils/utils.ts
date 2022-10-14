import * as R from 'ramda';

export const isNotEmptyField = <T>(field: T | null | undefined): field is T => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = <T>(field: T | null | undefined): field is null | undefined => !isNotEmptyField(field);
