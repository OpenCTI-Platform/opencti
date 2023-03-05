import * as R from 'ramda';
import { MESSAGING$ } from '../relay/environment';

export const isNotEmptyField = <T>(field: T | null | undefined): field is T => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = <T>(
  field: T | null | undefined,
): field is null | undefined => !isNotEmptyField(field);

export const copyToClipboard = (t: (text: string) => string, text: string) => {
  navigator.clipboard.writeText(text);
  MESSAGING$.notifySuccess(t('Copied to clipboard'));
};

export const removeEmptyFields = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  obj: Record<string, any | undefined>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Record<string, any> => {
  const clone = { ...obj };
  Object.keys(clone).forEach((key) => clone[key] == null && delete clone[key]);
  return clone;
};

export const formikFieldToEditInput = <T extends Record<string, unknown>>(
  current: T,
  previous: T,
) => {
  const object = { ...current };
  Object.entries(previous).forEach(([key, value]) => {
    if (object[key] === value) {
      delete object[key];
    }
  });
  return Object.entries(object).map(([key, value]) => ({ key, value }));
};
