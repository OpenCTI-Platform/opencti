import * as R from 'ramda';
import { APP_BASE_PATH, MESSAGING$ } from '../relay/environment';

export const export_max_size = 50000;

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
  Object.keys(clone).forEach((key) => {
    if (typeof clone[key] !== 'string' && isEmptyField(clone[key])) {
      delete clone[key];
    }
  });
  return clone;
};

export const deleteElementByValue = (obj: Record<string, string>, val: string) => {
  for (const key in obj) {
    if (obj[key] === val) {
      // eslint-disable-next-line no-param-reassign
      delete obj[key];
    }
  }
  return obj;
};

export const getFileUri = (id: string) => {
  const encodedFilePath = encodeURIComponent(id);
  return `${APP_BASE_PATH}/storage/view/${encodedFilePath}`;
};

export const generateUniqueItemsArray = <T>(submittedArray: IterableIterator<T> | Array<T>) => Array.from(new Set(submittedArray));

export const getCurrentTab = (location: Location, entity_id: string, entity_type_path: string) => {
  if (location.pathname.includes(`${entity_type_path}/${entity_id}/knowledge`)) return `${entity_type_path}/${entity_id}/knowledge`;
  if (location.pathname.includes(`${entity_type_path}/${entity_id}/content`)) return `${entity_type_path}/${entity_id}/content`;
  return location.pathname;
};

export const getPaddingRight = (location: Location, entity_id: string, entity_type_path: string) => {
  let paddingRight = 0;
  if (entity_id) {
    if (
      location.pathname.includes(
        `${entity_type_path}/${entity_id}/entities`,
      )
      || location.pathname.includes(
        `${entity_type_path}/${entity_id}/observables`,
      )
    ) {
      paddingRight = 250;
    }
    if (
      location.pathname.includes(
        `${entity_type_path}/${entity_id}/content`,
      )
    ) {
      paddingRight = 350;
    }
    if (
      location.pathname.includes(
        `${entity_type_path}/${entity_id}/content/mapping`,
      )
    ) {
      paddingRight = 0;
    }
  }
  return paddingRight;
};
