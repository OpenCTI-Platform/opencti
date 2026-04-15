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

/**
 * Compute the current state value of a <Tabs> component by comparing the
 * location.pathname (`fullpath`) with the `basePath` of the component
 * and extracting the next URL segment in the sequence.
 *
 * @param fullpath - The current full pathname as returned by useLocation().pathname.
 * Should contain no query params nor hash param.
 * @param basePath - The closest path to root where the <Tabs> component is rendered.
 * @returns The current tab value.
 *
 * @example
 * ```
 * getCurrentTab(
 *   '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c/knowledge/or/something/else',
 *   '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
 * ); // returns 'knowledge'
 * ```
 */
export const getCurrentTab = (fullpath: string, basePath: string) => {
  let subpath = fullpath.substring(basePath.length);
  if (subpath.startsWith('/')) {
    subpath = subpath.substring(1);
  }
  const nextSlashPos = subpath.indexOf('/');
  return nextSlashPos >= 0 ? subpath.substring(0, nextSlashPos) : subpath;
};

export const getPaddingRight = (locationPath: string, entityBasePath: string, applyKnowledgePadding = true) => {
  let paddingRight = 0;
  if (
    applyKnowledgePadding && locationPath.includes(
      `${entityBasePath}/knowledge`,
    )
  ) {
    paddingRight = 200;
  }
  if (locationPath.includes(`${entityBasePath}/content`)) {
    paddingRight = 350;
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
