import * as R from 'ramda';
import { last } from 'ramda';
import purify from 'dompurify';
import { Base64 } from 'js-base64';
import { isNotEmptyField } from './utils';

// the relative date values must be: 'now' OR 'now' followed by -/+ then a number then a letter among [smhHdwMy] and eventually a / followed by a letter among [smhHdwMy]
export const RELATIVE_DATE_REGEX = /^now([-+]\d+[smhHdwMy](\/[smhHdwMy])?)?$/;

// the value to display if a field is empty or undefined
export const EMPTY_VALUE = '-';

export function truncate(str: string, limit?: number, truncateSpaces?: boolean): string;
export function truncate(str: undefined, limit?: number, truncateSpaces?: boolean): undefined;
export function truncate(str: null, limit?: number, truncateSpaces?: boolean): null;
export function truncate(str: string | undefined | null, limit?: number, truncateSpaces?: boolean): string | undefined | null;
export function truncate(
  str: string | undefined | null,
  limit?: number,
  truncateSpaces = true,
): string | undefined | null {
  if (str === undefined || str === null || (limit && str.length <= limit)) {
    return str;
  }
  const trimmedStr = str.substring(0, limit);
  if (!truncateSpaces || !trimmedStr.includes(' ')) {
    return `${trimmedStr}...`;
  }
  return `${trimmedStr.substring(
    0,
    Math.min(trimmedStr.length, trimmedStr.lastIndexOf(' ')),
  )}...`;
}

/**
 * Normalize a field value for use in GraphQL edit inputs.
 * - If the value is an array, it is returned as-is.
 * - If the value is nil (null/undefined), returns an empty string.
 * - Otherwise, converts the value to its string representation.
 *
 * @param value The raw field value.
 * @returns The normalized value as a string or array.
 */
export function adaptFieldValue(value: unknown[]): unknown[];
export function adaptFieldValue(value: unknown): string;
export function adaptFieldValue(value: unknown): string | unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (R.isNil(value)) {
    return '';
  }
  return value.toString();
}

/**
 * Split a string by newlines, commas and semicolons,
 * then join all resulting parts with newlines.
 *
 * @param text {string} The input text to split.
 * @returns {string} The text with commas/semicolons replaced by newlines.
 */
export const splitIntoLines = (text: string) => {
  return text
    .split('\n')
    .map((o) => o
      .split(',')
      .map((p) => p.split(';'))
      .flat())
    .flat()
    .join('\n');
};

export const pascalize = (s: string) => s.replace(/(\w)(\w*)/g, (g0: string, g1: string, g2: string) => g1.toUpperCase() + g2.toLowerCase());

export const convertFromStixType = (s: string | undefined | null): string | undefined | null => {
  if (!s) {
    return s;
  }
  let type = pascalize(s);
  if (type.includes('Opencti')) {
    type = type.replaceAll('Opencti', 'OpenCTI');
  }
  if (type.includes('Ipv')) {
    type = type.replaceAll('Ipv', 'IPv');
  }
  if (type === 'File' || type === 'Stixfile') {
    return 'StixFile';
  }
  if (type.startsWith('X-OpenCTI-')) {
    type = type.replaceAll('X-OpenCTI-', '');
  }
  return type;
};

export const convertToStixType = (type: string | undefined | null): string | undefined | null => {
  if (!type) {
    return type;
  }
  if (type === 'StixFile') {
    return 'file';
  }
  if (['Sector', 'Organization', 'Individual', 'System', 'SecurityPlatform'].includes(type)) {
    return 'identity';
  }
  if (['Threat-Actor-Group', 'Threat-Actor-Individual'].includes(type)) {
    return 'threat-actor';
  }
  if (['Region', 'Country', 'City', 'Position', 'Administrative-Area'].includes(type)) {
    return 'location';
  }
  return type.toLowerCase();
};

export const isValidStixBundle = (bundle: string): boolean => {
  try {
    const data = JSON.parse(bundle);
    return !!(data.objects && data.objects.length > 0);
  } catch (_e) {
    return false;
  }
};

export const toB64 = (str: string): string => Base64.encodeURI(str);

export const toBase64 = (str: string): string => Base64.encode(str);

export const fromB64 = (str: string): string => Base64.decode(str);

export const fromBase64 = (str: string): string => Base64.encode(str);

/** Check if two objects have the same values (deep equality) for the given fields. */
const areSameByFields = <T extends Record<string, unknown>>(
  fields: string[],
  a: T,
  b: T,
): boolean =>
  fields.every((f) => JSON.stringify(a[f]) === JSON.stringify(b[f]));

/** Deduplicate an array by keeping only the first occurrence of each unique combination of the given fields. */
export const uniqWithByFields = <T extends Record<string, unknown>>(fields: (keyof T)[]) => (data: T[]): T[] => {
  return data.filter((item, index) =>
    data.findIndex((other) =>
      areSameByFields(fields as string[], item, other),
    ) === index,
  );
};

/**
 * Group consecutive elements that share the same values for the given fields.
 */
export const computeDuplicates = <T extends Record<string, unknown>>(fields: string[], data: T[]): T[][] => {
  if (data.length === 0) return [];
  const result: T[][] = [[data[0]]];
  for (let i = 1; i < data.length; i++) {
    if (areSameByFields(fields, data[i - 1], data[i])) {
      result[result.length - 1].push(data[i]);
    } else {
      result.push([data[i]]);
    }
  }
  return result;
};

export const capitalizeFirstLetter = (str: string): string => str.charAt(0).toUpperCase() + str.slice(1);

export const capitalizeWords = (str: string): string => str.split(' ').map(capitalizeFirstLetter).join(' ');

export const toCamelCase = (str: string): string => {
  return str
    .replace(/[^a-zA-Z0-9 ]/g, '')
    .replace(/(?:^\w|[A-Z]|\b\w)/g, (word, i) => {
      return i === 0 ? word.toLowerCase() : word.toUpperCase();
    })
    .replace(/\s+/g, '');
};

export const emptyFilled = (str: string | undefined | null): string => (isNotEmptyField(str) ? str : EMPTY_VALUE);

/**
 * Split a string by newlines, filter out empty lines, and trim each resulting line.
 *
 * @param str The input string to split.
 * @returns Array of non-empty trimmed lines.
 */
export const splitMultilines = (str: string | undefined | null): string[] => (str ?? '')
  .split(/\r?\n/)
  .filter((v) => !!v)
  .map((s) => s.trim());

export const maskString = (value: string | undefined | null): string => (value ? '•'.repeat(value.length) : '');

/**
 * Add zero-width spaces every 10 characters in a string.
 * It allows PDF generation to automatically go to new line instead
 * of going outside of the file when facing every long names, ids, etc.
 *
 * @param value String to make wrappable.
 * @returns {string} Same string but wrappable.
 */
export const stringWithZeroWidthSpace = (value: string) => {
  return (value.match(/.{1,10}/g) ?? []).join('​');
};

/**
 * Check if a string is in a correct date format
 * (usefull to check if a value in a filter of type date is correct)
 *
 * @param stringDate String
 * @returns {boolean} If the string is in a correct date format.
 */
export const isValidDate = (stringDate: string | undefined | null): boolean => {
  if (!stringDate) return false;
  const dateParsed = Date.parse(stringDate);
  if (!dateParsed) return false;
  const dateInstance = new Date(dateParsed);
  return dateInstance.toISOString() === stringDate;
};

type RelativeUnit = 's' | 'm' | 'H' | 'h' | 'w' | 'd' | 'M' | 'y';

/**
 * Check if an array of string is translatable in a comprehensible date interval phrase
 * ie if the array is composed of 2 strings
 * and the first in a relative date math format before now,
 * and the second is 'now'
 *
 * @param filterValues {string[]} The filter values to check.
 * @returns {boolean} If the array is translatable in a relative date interval phrase
 */
export const isDateIntervalTranslatable = (filterValues: string[]): boolean => {
  return filterValues.length === 2
    && filterValues[1] === 'now'
    && !!filterValues[0].match(RELATIVE_DATE_REGEX)
    && filterValues[0].includes('-')
    && !filterValues[0].includes('/');
};

/**
 * Translate an array into a comprehensible date interval phrase.
 *
 * @param filterValues {string[]} The filter values to translate.
 * @param t_i18n {function} The translation function.
 * @returns {string} Translation in a relative date interval phrase
 */
export const translateDateInterval = (filterValues: string[], t_i18n: (s: string) => string): string => {
  if (!isDateIntervalTranslatable(filterValues)) {
    throw Error('The interval of value is not translatable in a relative date interval phrase.');
  }
  const relativeUnitMapInPlural: Record<RelativeUnit, string> = {
    s: t_i18n('seconds'),
    m: t_i18n('minutes'),
    H: t_i18n('hours'),
    h: t_i18n('hours'),
    w: t_i18n('weeks'),
    d: t_i18n('days'),
    M: t_i18n('months'),
    y: t_i18n('years'),
  };
  const relativeUnitMapInSingular: Record<RelativeUnit, string> = {
    s: t_i18n('second'),
    m: t_i18n('minute'),
    H: t_i18n('hour'),
    h: t_i18n('hour'),
    w: t_i18n('week'),
    d: t_i18n('day'),
    M: t_i18n('month'),
    y: t_i18n('year'),
  };
  const relativeExtraction = last(filterValues[0].split('now-')) ?? '';
  const relativeUnitLetter = last(relativeExtraction) ?? '' as string;
  const relativeNumber = relativeExtraction.split(relativeUnitLetter)[0];
  const relativeUnit = relativeNumber === '1'
    ? relativeUnitMapInSingular[relativeUnitLetter as RelativeUnit]
    : relativeUnitMapInPlural[relativeUnitLetter as RelativeUnit];

  return `${t_i18n('Last')} ${relativeNumber} ${t_i18n(relativeUnit)}`;
};

/**
 * Convert an entity type value in a translatable string
 *
 * @param {string|undefined} value The entity type to translate
 * @returns {string} Translation in a translatable string
 */
export const displayEntityTypeForTranslation = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  return value.toString()[0] === value.toString()[0].toUpperCase()
    ? `entity_${value.toString()}`
    : `relationship_${value.toString()}`;
};

/**
 * Extract urls from a string
 *
 * @returns {*[]}
 * @param text
 */
export const extractUrlsFromText = (text: string) => {
  const extractUrlsregex = /\b(?:https?:\/\/|www\.)\S+\b/gm;
  const matches = Array.from(text.matchAll(extractUrlsregex));
  const parts = [];
  let lastIndex = 0;

  matches.forEach((match) => {
    if ((match.index ?? 0) > lastIndex) {
      parts.push(<span key={`text-${lastIndex}`}>{text.substring(lastIndex, match.index)}</span>);
    }
    const url = match[0];
    const href = url.startsWith('www.') ? `http://${url}` : url;

    parts.push(
      <a key={`url-${match.index}`} href={href} target="_blank" rel="noopener noreferrer">
        {url}
      </a>,
    );
    lastIndex = (match.index ?? 0) + url.length;
  });

  if (lastIndex < text.length) {
    parts.push(<span key={`text-${lastIndex}`}>{text.substring(lastIndex)}</span>);
  }

  return parts;
};

/**
 * Transform a potential unsecure html string into a secure one.
 *
 * @param data String to sanitize.
 * @param escapeHtml If we want to keep html tags without removing them.
 * @returns Sanitized string.
 */
export const sanitize = (data: string, escapeHtml = false): string => {
  const toSanitize = escapeHtml
    ? data.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    : data;
  return purify.sanitize(toSanitize);
};

/**
 * Check if a string is xss safe.
 *
 * @param data Determine is a string is xss safe or not.
 * @returns True if the string is safe.
 */
export const isStringSafe = (data: string): boolean => {
  return data === purify.sanitize(data);
};

/**
 * Extract JSON content from a string that may contain a Markdown code block.
 * If the string contains a ```json or ``` fenced block, returns its inner content (trimmed).
 * Otherwise, returns the whole string trimmed.
 *
 * @param content {string} The raw string potentially wrapping JSON in a code block.
 * @returns {string} The extracted JSON string.
 */
export const extractJsonContent = (content: string): string => {
  const codeBlockMatch = content.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (codeBlockMatch?.[1]) {
    return codeBlockMatch[1].trim();
  }
  return content.trim();
};
