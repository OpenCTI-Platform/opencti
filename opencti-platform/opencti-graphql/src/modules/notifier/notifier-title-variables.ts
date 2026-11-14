import { isForbiddenName } from '../../utils/safeEjs';

// Closed list of template-data roots a `$variable` can start with in a notifier title.
export const TITLE_VARIABLE_ROOTS: readonly string[] = [
  'notification',
  'notification_content',
  'content',
  'data',
  'user',
  'platform_uri',
];

// Name under which resolved values are exposed to the compiled EJS template.
export const TITLE_VARIABLES_DATA_KEY = 'octi_title_variables';

const VARIABLE_REGEX = /\$([A-Za-z_][A-Za-z0-9_]*)((?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*)/y;
const SEGMENT_REGEX = /\.?([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]/y;

const hasOwn = (target: object, key: string) => Object.prototype.hasOwnProperty.call(target, key);

const renderValue = (value: unknown): string => {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value) && value.every((v) => ['string', 'number', 'boolean'].includes(typeof v))) {
    return value.map(String).join(', ');
  }
  return '';
};

/**
 * Resolve a template-data path (without the leading `$`), e.g. `notification_content[0].title`.
 * Own properties only, forbidden names rejected, never throws: anything unresolvable gives ''.
 */
export const resolveTitleVariablePath = (data: Record<string, unknown>, path: string): string => {
  let current: unknown = data;
  SEGMENT_REGEX.lastIndex = 0;
  let position = 0;
  let isFirst = true;
  while (position < path.length) {
    SEGMENT_REGEX.lastIndex = position;
    const match = SEGMENT_REGEX.exec(path);
    // A leading dot is only valid between segments, never before the root.
    if (!match || (isFirst && (match[2] !== undefined || path[position] === '.'))) {
      return '';
    }
    position = SEGMENT_REGEX.lastIndex;
    isFirst = false;
    if (typeof current !== 'object' || current === null) {
      return '';
    }
    if (match[2] !== undefined) {
      const index = Number(match[2]);
      if (!Array.isArray(current) || !Number.isSafeInteger(index) || index >= current.length) {
        return '';
      }
      current = current[index];
    } else {
      const name = match[1];
      if (isForbiddenName(name)) {
        return '';
      }
      const isArrayLength = Array.isArray(current) && name === 'length';
      if (Array.isArray(current) ? !isArrayLength : !hasOwn(current, name)) {
        return '';
      }
      current = (current as Record<string, unknown>)[name];
    }
  }
  return isFirst ? '' : renderValue(current);
};

/**
 * Rewrite every `$path` variable found outside EJS tags into `<%- octi_title_variables[i] %>`.
 * Values are returned separately so they are passed as data and never concatenated into the template.
 */
export const compileTitleVariables = (title: string, data: Record<string, unknown>): { template: string; values: string[] } => {
  const values: string[] = [];
  let template = '';
  let i = 0;
  while (i < title.length) {
    if (title.startsWith('<%%', i)) {
      template += '<%%';
      i += 3;
    } else if (title.startsWith('<%', i)) {
      const end = title.indexOf('%>', i + 2);
      if (end === -1) {
        // Unterminated tag: leave the rest untouched, safeRender will report it.
        template += title.slice(i);
        break;
      }
      template += title.slice(i, end + 2);
      i = end + 2;
    } else if (title[i] === '$') {
      VARIABLE_REGEX.lastIndex = i;
      const match = VARIABLE_REGEX.exec(title);
      if (match && TITLE_VARIABLE_ROOTS.includes(match[1])) {
        template += `<%- ${TITLE_VARIABLES_DATA_KEY}[${values.length}] %>`;
        values.push(resolveTitleVariablePath(data, `${match[1]}${match[2]}`));
        i += match[0].length;
      } else {
        const literal = match ? match[0] : '$';
        template += literal;
        i += literal.length;
      }
    } else {
      template += title[i];
      i += 1;
    }
  }
  return { template, values };
};

// An email subject must stay on a single line: flatten any line terminator (including NEL U+0085), collapse spaces and trim.
export const normalizeEmailSubject = (subject: string): string => subject.replace(/[\s\u0085]+/g, ' ').trim();
