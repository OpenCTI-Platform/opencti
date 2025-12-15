import * as R from 'ramda';
import { APP_BASE_PATH, MESSAGING$ } from '../relay/environment';

export const export_max_size = 50000;

export const isNotEmptyField = <T>(field: T | null | undefined): field is T => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = <T>(
  field: T | null | undefined,
): field is null | undefined => !isNotEmptyField(field);

export const isNilField = <T>(field: T | null | undefined) => field === null || field === undefined;

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
      delete obj[key];
    }
  }
  return obj;
};

export const getFileUri = (id: string) => {
  const encodedFilePath = encodeURIComponent(id);
  return `${APP_BASE_PATH}/storage/view/${encodedFilePath}`;
};

export const uniqueArray = <T>(items: IterableIterator<T> | Array<T>) => Array.from(new Set(items));

export const getCurrentTab = (locationPath: string, entityId: string, entityTypePath: string) => {
  if (locationPath.includes(`${entityTypePath}/${entityId}/knowledge`)) return `${entityTypePath}/${entityId}/knowledge`;
  if (locationPath.includes(`${entityTypePath}/${entityId}/content`)) return `${entityTypePath}/${entityId}/content`;
  return locationPath;
};

export const getPaddingRight = (locationPath: string, entityId: string, entityTypePath: string, applyKnowledgePadding = true) => {
  let paddingRight = 0;
  if (entityId) {
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
      || locationPath.includes(
        `${entityTypePath}/${entityId}/content/suggested_mapping`,
      )
    ) {
      paddingRight = 0;
    }
  }
  return paddingRight;
};

export const throttle = (callback: (...a: unknown[]) => unknown, wait: number) => {
  let timeoutId: number;
  return (...args: unknown[]) => {
    window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(() => {
      callback(...args);
    }, wait);
  };
};

export const cleanHtmlTags = (str?: string | null) => {
  return (str ?? '')
    .replace('```html', '')
    .replace('```', '')
    .replace(/<html[^>]*>/g, '') // Removes `<html>` with any attributes
    .replace('</html>', '')
    .replace(/<body[^>]*>/g, '') // Removes `<body>` with any attributes
    .replace('</body>', '')
    .trim();
};
