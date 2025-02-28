import { v4, v5 } from 'uuid';
import { FROM_START, FROM_START_STR, UNTIL_END, UNTIL_END_STR } from '../utils/format';

export type StixDate = string | undefined;
type StixId = `${string}--${v4 | v5}`;

export const convertToStixDate = (date: Date | string | undefined): StixDate => {
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
