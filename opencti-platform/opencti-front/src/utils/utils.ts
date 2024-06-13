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

export const getCurrentTab = (locationPath: string, entityId: string, entityTypePath: string) => {
  if (locationPath.includes(`${entityTypePath}/${entityId}/knowledge`)) return `${entityTypePath}/${entityId}/knowledge`;
  if (locationPath.includes(`${entityTypePath}/${entityId}/content`)) return `${entityTypePath}/${entityId}/content`;
  return locationPath;
};

export const getPaddingRight = (locationPath: string, entityId: string, entityTypePath: string, applyKnowledgePadding = true) => {
  let paddingRight = 0;
  if (entityId) {
    if (
      locationPath.includes(
        `${entityTypePath}/${entityId}/entities`,
      )
      || locationPath.includes(
        `${entityTypePath}/${entityId}/observables`,
      )
    ) {
      paddingRight = 250;
    }
    if (
      applyKnowledgePadding && locationPath.includes(
        `${entityTypePath}/${entityId}/knowledge`,
      )
    ) {
      paddingRight = 200;
    }
    if (
      locationPath.includes(
        `${entityTypePath}/${entityId}/content`,
      )
    ) {
      paddingRight = 350;
    }
    if (
      locationPath.includes(
        `${entityTypePath}/${entityId}/content/mapping`,
      )
    ) {
      paddingRight = 0;
    }
  }
  return paddingRight;
};
