import { UnsupportedError } from '../config/errors';
import type * as S from '../types/stix-2-1-common';
import type * as S2 from '../types/stix-2-0-common';
import { FROM_START, FROM_START_STR, UNTIL_END, UNTIL_END_STR } from '../utils/format';
import { objects } from '../schema/stixRefRelationship';
import { isEmptyField } from './utils';

export const assertType = (type: string, instanceType: string) => {
  if (instanceType !== type) {
    throw UnsupportedError('Incompatible type', { instanceType, type });
  }
};
export const convertToStixDate = (date: Date | string | undefined): S.StixDate | S2.StixDate => {
  if (date === undefined) {
    return undefined;
  }
  // date type from graphql
  if (date instanceof Date) {
    const time = date.getTime();
    if (time === FROM_START || time === UNTIL_END) {
      return undefined;
    }
    return date.toISOString();
  }
  // date string from the database
  if (date === FROM_START_STR || date === UNTIL_END_STR) {
    return undefined;
  }
  return date;
};
export const cleanObject = <T>(data: T): T => {
  const obj: T = { ...data };
  // eslint-disable-next-line no-restricted-syntax
  for (const key in data) {
    // cleanup empty keys except object_refs
    if (key !== objects.stixName && isEmptyField(obj[key])) {
      delete obj[key];
    }
  }
  return obj;
};
