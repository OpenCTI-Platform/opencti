import { isNotEmptyField } from '../database/utils';

export const filterEmpty = <T>(data: T | null | undefined): data is T => {
  return isNotEmptyField(data);
};

/**
 * Inverse operation of the built-in Readonly<T> utility type:
 * makes all records of an object mutable.
 */
export type Mutable<T> = { -readonly [P in keyof T]: T[P]; };
