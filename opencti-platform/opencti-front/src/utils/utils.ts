import * as R from "ramda";

export const isNotEmptyField = <T extends unknown>(field: T | null | undefined): field is T => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = <T extends unknown>(field: T | null | undefined): field is null | undefined => !isNotEmptyField(field);
