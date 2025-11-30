import * as R from 'ramda';
import { UnsupportedError } from '../config/errors';
import type * as S2 from '../types/stix-2-0-common';
import type * as S from '../types/stix-2-1-common';
import { FROM_START, FROM_START_STR, UNTIL_END, UNTIL_END_STR } from '../utils/format';
import { objects } from '../schema/stixRefRelationship';
import { isEmptyField, isInferredIndex } from './utils';
import type { StoreEntity } from '../types/store';
import { INPUT_OBJECTS } from '../schema/general';

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
export const isValidStix = (data: S.StixObject | S2.StixObject): boolean => {
  // TODO @JRI @SAM
  return !R.isEmpty(data);
};
export const convertObjectReferences = (instance: StoreEntity, isInferred = false) => {
  const objectRefs = instance[INPUT_OBJECTS] ?? [];
  return objectRefs.filter((r) => {
    // If related relation not available, it's just a creation, so inferred false
    if (!r.i_relation) return !isInferred;
    // If related relation is available, select accordingly
    return isInferredIndex(r.i_relation._index) === isInferred;
  }).map((m) => m.standard_id);
};
