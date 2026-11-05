import { STIX_CYBER_OBSERVABLE_TYPES } from '../../utils/stix2-splitter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-2-1-extensions';
import { StixImportError, type StixObject } from './types';

// pycti `"extensions" in object and id in object["extensions"] and key in object["extensions"][id]`
// (a None or str along the way fails or matches as in Python)
const inExtension = (object: StixObject, extensionId: string, key: string) => contains(object, 'extensions')
  && contains(object.extensions, extensionId) && contains(required(object.extensions, extensionId), key);

// pycti get_attribute_in_extension: the OpenCTI extensions first, then the object itself
export const getAttributeInExtension = (key: string, object: StixObject): any => {
  if (inExtension(object, STIX_EXT_OCTI, key)) {
    return required(required(object.extensions, STIX_EXT_OCTI), key);
  }
  if (inExtension(object, STIX_EXT_OCTI_SCO, key)) {
    return required(required(object.extensions, STIX_EXT_OCTI_SCO), key);
  }
  if (contains(object, key) && key !== 'type') {
    return required(object, key);
  }
  return null;
};

// pycti get_attribute_in_mitre_extension: the MITRE ATT&CK extension only, no fallback
export const getAttributeInMitreExtension = (key: string, object: StixObject): any => {
  if (inExtension(object, STIX_EXT_MITRE, key)) {
    return required(required(object.extensions, STIX_EXT_MITRE), key);
  }
  return null;
};

const OBSERVABLE_TYPES = new Set(STIX_CYBER_OBSERVABLE_TYPES);

// pycti StixCyberObservableTypes.has_value: case insensitive
export const isStixCyberObservableType = (type: unknown) => OBSERVABLE_TYPES.has(asStr(type, 'lower').toLowerCase());

// pycti convert_markdown: <code> tags to backticks (re.sub fails on a value other than a str)
export const convertMarkdown = (text: unknown) => {
  if (text === null || text === undefined) {
    return null;
  }
  if (typeof text !== 'string') {
    throw new StixImportError('TypeError', `expected string or bytes-like object, got '${pythonType(text)}'`);
  }
  return text.replace(/<code>([\s\S]*?)<\/code>/g, '`$1`');
};

// pycti pick_aliases
export const pickAliases = (object: StixObject) => {
  for (const key of ['x_opencti_aliases', 'x_mitre_aliases', 'x_amitt_aliases', 'aliases']) {
    if (key in object) {
      return object[key];
    }
  }
  return null;
};

// pycti is_custom_field_input_value: a custom field holds a scalar, or a list of strings for a
// multi select; an object, or a list holding one or a list, never matches one (x_opencti_files
// and its base64 content, already sent as uploads) and is not sent
const isCustomFieldInputValue = (value: unknown) => {
  if (value === null || value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.every((item) => item === null || typeof item !== 'object');
  }
  return typeof value !== 'object';
};

// pycti extract_custom_field_values: every x_ property that can fill a custom field, top level
// first, then the extensions
export const extractCustomFieldValues = (object: StixObject) => {
  const values: { field_name: string; value: unknown }[] = [];
  const seen = new Set<string>();
  Object.entries(object).forEach(([key, value]) => {
    if (key.startsWith('x_') && value !== null && value !== undefined) {
      // A top-level value takes precedence even if it cannot be sent
      seen.add(key);
      if (isCustomFieldInputValue(value)) {
        values.push({ field_name: key, value });
      }
    }
  });
  const { extensions } = object;
  if (extensions && typeof extensions === 'object' && !Array.isArray(extensions)) {
    Object.values(extensions).forEach((extension) => {
      if (!extension || typeof extension !== 'object' || Array.isArray(extension)) {
        return;
      }
      Object.entries(extension as Record<string, unknown>).forEach(([key, value]) => {
        if (key.startsWith('x_') && !seen.has(key) && isCustomFieldInputValue(value)) {
          values.push({ field_name: key, value });
          seen.add(key);
        }
      });
    });
  }
  return values.length > 0 ? values : null;
};

// region python semantics
// What pycti raises when it reads the input without a guard: the port fails at the same point,
// with the same Python error name (the item outcome), instead of dropping the value.
// Not reproduced (accepted): the input is read with JSON.parse, so a float with an integral value
// (1.0) is read as an int (Python str gives "1.0", the port "1"), integers above 2^53 lose
// their precision (Python keeps them exact), and a dict is iterated in JavaScript key order:
// integer-like keys first, ascending, then the others in insertion order (Python keeps the
// insertion order for all keys), so {"zz": 1, "5": 2} is iterated "5" then "zz".
// A key is looked up as an own key only (never through the prototype), and written as an own
// property (a "__proto__" key is a plain key, as in Python).

// The Python type name of a JSON value, for the error messages
export const pythonType = (value: unknown) => {
  if (value === null || value === undefined) {
    return 'NoneType';
  }
  if (Array.isArray(value)) {
    return 'list';
  }
  if (typeof value === 'string') {
    return 'str';
  }
  if (typeof value === 'boolean') {
    return 'bool';
  }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? 'int' : 'float';
  }
  return 'dict';
};

const isDict = (value: unknown): value is StixObject => value !== null && typeof value === 'object' && !Array.isArray(value);

// pycti `object[key]` with a string key: a missing key fails
export const required = (object: unknown, key: string): any => {
  if (isDict(object)) {
    if (!Object.prototype.hasOwnProperty.call(object, key)) {
      throw new StixImportError('KeyError', `'${key}'`);
    }
    return object[key];
  }
  if (Array.isArray(object)) {
    throw new StixImportError('TypeError', 'list indices must be integers or slices, not str');
  }
  if (typeof object === 'string') {
    throw new StixImportError('TypeError', 'string indices must be integers, not \'str\'');
  }
  throw new StixImportError('TypeError', `'${pythonType(object)}' object is not subscriptable`);
};

// pycti `values[index]` with an integer index
export const at = (values: unknown, index: number): any => {
  if (Array.isArray(values) || typeof values === 'string') {
    const position = index < 0 ? values.length + index : index;
    if (position < 0 || position >= values.length) {
      throw new StixImportError('IndexError', `${Array.isArray(values) ? 'list' : 'string'} index out of range`);
    }
    return values[position];
  }
  if (isDict(values)) {
    // A dict indexed by an integer: JSON keys are strings, the key is missing
    throw new StixImportError('KeyError', String(index));
  }
  throw new StixImportError('TypeError', `'${pythonType(values)}' object is not subscriptable`);
};

// pycti `values[0]`
export const first = (values: unknown) => at(values, 0);

// pycti `for value in values`
export const iterate = (values: unknown): unknown[] => {
  if (Array.isArray(values)) {
    return values;
  }
  if (typeof values === 'string') {
    return [...values];
  }
  if (isDict(values)) {
    return Object.keys(values);
  }
  throw new StixImportError('TypeError', `'${pythonType(values)}' object is not iterable`);
};

// pycti `key in container`
export const contains = (container: unknown, key: unknown) => {
  if (typeof container === 'string') {
    if (typeof key !== 'string') {
      throw new StixImportError('TypeError', `'in <string>' requires string as left operand, not ${pythonType(key)}`);
    }
    return container.includes(key);
  }
  if (Array.isArray(container)) {
    return container.includes(key);
  }
  if (isDict(container)) {
    if (key !== null && typeof key === 'object') {
      throw new StixImportError('TypeError', `unhashable type: '${pythonType(key)}'`);
    }
    return typeof key === 'string' && Object.prototype.hasOwnProperty.call(container, key);
  }
  throw new StixImportError('TypeError', `argument of type '${pythonType(container)}' is not iterable`);
};

// pycti `table.get(key)` on a dict of the code (a registry): own keys only, an unhashable key fails
export const tableGet = <T>(table: Record<string, T> | Map<string, T>, key: unknown): T | undefined => {
  if (key !== null && typeof key === 'object') {
    throw new StixImportError('TypeError', `unhashable type: '${pythonType(key)}'`);
  }
  if (typeof key !== 'string') {
    return undefined;
  }
  if (table instanceof Map) {
    return table.get(key);
  }
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
};

// pycti `container[key] = value` with a string key
export const setItem = (container: unknown, key: string, value: unknown) => {
  if (isDict(container)) {
    if (key === '__proto__') {
      // An assignment would set the prototype: define the own property
      Object.defineProperty(container, key, { value, writable: true, enumerable: true, configurable: true });
    } else {
      // The containers are plain objects, with no accessor but __proto__ on their prototype: an
      // assignment writes the own property as defineProperty does, at a fraction of its cost
      container[key] = value;
    }
    return;
  }
  if (Array.isArray(container)) {
    throw new StixImportError('TypeError', 'list indices must be integers or slices, not str');
  }
  throw new StixImportError('TypeError', `'${pythonType(container)}' object does not support item assignment`);
};

// pycti `dict.get(key)` on what must be a dict
export const dictGet = (dict: unknown, key: string, defaultValue: unknown = null) => {
  if (!isDict(dict)) {
    throw new StixImportError('AttributeError', `'${pythonType(dict)}' object has no attribute 'get'`);
  }
  return Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : defaultValue;
};

// pycti `dict.items()` on what must be a dict
export const dictItems = (dict: unknown): [string, any][] => {
  if (!isDict(dict)) {
    throw new StixImportError('AttributeError', `'${pythonType(dict)}' object has no attribute 'items'`);
  }
  return Object.entries(dict);
};

// pycti `{**value}` on what must be a dict
export const asMapping = (value: unknown): StixObject => {
  if (!isDict(value)) {
    throw new StixImportError('TypeError', `'${pythonType(value)}' object is not a mapping`);
  }
  return value;
};

// pycti `len(value)`
export const pythonLen = (value: unknown) => {
  if (Array.isArray(value) || typeof value === 'string') {
    return value.length;
  }
  if (isDict(value)) {
    return Object.keys(value).length;
  }
  throw new StixImportError('TypeError', `object of type '${pythonType(value)}' has no len()`);
};

// Values of the base64 alphabet (binascii table_a2b_base64), the other characters are skipped
const BASE64_VALUES = new Map([...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'].map((character, index) => [character, index]));

// pycti base64.b64decode(value): Python's non-strict binascii.a2b_base64 (CPython 3.12): characters
// outside the alphabet are discarded, a padding ends the data once it completes a quad, and a
// truncated quad fails with binascii.Error (a ValueError)
export const b64decode = (value: unknown) => {
  if (typeof value !== 'string') {
    throw new StixImportError('TypeError', `argument should be a bytes-like object or ASCII string, not '${pythonType(value)}'`);
  }
  // Canonical base64 (the files of real messages, up to tens of MB): the native decoder gives
  // Python's bytes. Only a canonical string survives the round trip, any other one is decoded below
  const native = Buffer.from(value, 'base64');
  if (native.toString('base64') === value) {
    return native;
  }
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(value)) {
    throw new StixImportError('ValueError', 'string argument should contain only ASCII characters');
  }
  const bytes: number[] = [];
  let quadPosition = 0;
  let leftBits = 0;
  let pads = 0;
  for (const character of value) {
    if (character === '=') {
      if (quadPosition >= 2) {
        pads += 1;
        if (quadPosition + pads >= 4) {
          return Buffer.from(bytes);
        }
      }
      continue;
    }
    const sextet = BASE64_VALUES.get(character);
    if (sextet === undefined) {
      continue;
    }
    pads = 0;
    if (quadPosition === 0) {
      leftBits = sextet;
    } else if (quadPosition === 1) {
      bytes.push(((leftBits << 2) | (sextet >> 4)) & 0xff);
      leftBits = sextet & 0x0f;
    } else if (quadPosition === 2) {
      bytes.push(((leftBits << 4) | (sextet >> 2)) & 0xff);
      leftBits = sextet & 0x03;
    } else {
      bytes.push(((leftBits << 6) | sextet) & 0xff);
    }
    quadPosition = (quadPosition + 1) % 4;
  }
  if (quadPosition === 1) {
    throw new StixImportError('Error', `Invalid base64-encoded string: number of data characters (${Math.floor(bytes.length / 3) * 4 + 1}) cannot be 1 more than a multiple of 4`);
  }
  if (quadPosition !== 0) {
    throw new StixImportError('Error', 'Incorrect padding');
  }
  return Buffer.from(bytes);
};

// pycti `value.<method>()` of a str method (lower, upper, strip, startswith...) on what must be a str
export const asStr = (value: unknown, method: string): string => {
  if (typeof value !== 'string') {
    throw new StixImportError('AttributeError', `'${pythonType(value)}' object has no attribute '${method}'`);
  }
  return value;
};

// pycti `left + right` on what must be two str
export const concat = (left: unknown, right: unknown): string => {
  if (typeof left === 'string' && typeof right === 'string') {
    return left + right;
  }
  if (typeof left === 'string') {
    throw new StixImportError('TypeError', `can only concatenate str (not "${pythonType(right)}") to str`);
  }
  throw new StixImportError('TypeError', `unsupported operand type(s) for +: '${pythonType(left)}' and '${pythonType(right)}'`);
};
// Python repr() of a JSON value
const pythonStringRepr = (text: string) => {
  const quote = text.includes("'") && !text.includes('"') ? '"' : "'";
  let result = '';
  for (const character of text) {
    const code = character.codePointAt(0) as number;
    if (character === '\\' || character === quote) {
      result += `\\${character}`;
    } else if (character === '\n') {
      result += '\\n';
    } else if (character === '\r') {
      result += '\\r';
    } else if (character === '\t') {
      result += '\\t';
    } else if (character !== ' ' && /[\p{C}\p{Z}]/u.test(character)) {
      // Non printable: \xhh, \uhhhh or \Uhhhhhhhh
      if (code < 0x100) {
        result += `\\x${code.toString(16).padStart(2, '0')}`;
      } else if (code < 0x10000) {
        result += `\\u${code.toString(16).padStart(4, '0')}`;
      } else {
        result += `\\U${code.toString(16).padStart(8, '0')}`;
      }
    } else {
      result += character;
    }
  }
  return `${quote}${result}${quote}`;
};

// Python repr() of a float: the shortest digits (as JavaScript), positional when the exponent is
// in [-4, 16), else scientific with a signed exponent of at least two digits
const pythonFloatRepr = (value: number) => {
  if (Number.isInteger(value)) {
    return Math.abs(value) < 1e21 ? String(value) : BigInt(value).toString();
  }
  const [mantissa, exponentText] = value.toExponential().split('e');
  const exponent = Number(exponentText);
  if (exponent >= -4 && exponent < 16) {
    return String(value);
  }
  const sign = exponent < 0 ? '-' : '+';
  return `${mantissa}e${sign}${String(Math.abs(exponent)).padStart(2, '0')}`;
};

const pythonRepr = (value: unknown): string => {
  if (value === null || value === undefined) {
    return 'None';
  }
  if (typeof value === 'boolean') {
    return value ? 'True' : 'False';
  }
  if (typeof value === 'number') {
    return pythonFloatRepr(value);
  }
  if (typeof value === 'string') {
    return pythonStringRepr(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(pythonRepr).join(', ')}]`;
  }
  return `{${Object.entries(value as StixObject).map(([key, item]) => `${pythonStringRepr(key)}: ${pythonRepr(item)}`).join(', ')}}`;
};

// Python str()
export const pythonStr = (value: unknown) => (typeof value === 'string' ? value : pythonRepr(value));

// Python bool(value)
export const pythonTruthy = (value: unknown) => {
  if (Array.isArray(value) || typeof value === 'string') {
    return value.length > 0;
  }
  if (value !== null && typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return Boolean(value);
};

// pycti `value is None` (a key never provided included)
export const isMissing = (value: unknown) => value === null || value === undefined;

// Unicode decimal digits as ASCII (Python's int, float and Decimal accept them all): the decimal
// digits come in runs of 10 ascending code points, from 0
const DECIMAL_DIGIT = /^\p{Nd}$/u;
export const asciiDigits = (value: string) => Array.from(value).map((character) => {
  if ((character >= '0' && character <= '9') || !DECIMAL_DIGIT.test(character)) {
    return character;
  }
  const codePoint = character.codePointAt(0) as number;
  let offset = 0;
  while (DECIMAL_DIGIT.test(String.fromCodePoint(codePoint - offset - 1))) {
    offset += 1;
  }
  return String(offset % 10);
}).join('');

// Python str.isspace() characters
// eslint-disable-next-line no-control-regex
const PYTHON_SPACE_CHARACTER = /^[\t\n\v\f\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u;
export const isPythonSpace = (character: string) => PYTHON_SPACE_CHARACTER.test(character);

// The spaces int() strips: str.isspace() without the ASCII separators \x1c-\x1f (CPython only
// converts the non-ASCII spaces, then skips the ASCII whitespace)
const INT_SPACE = '[\\t\\n\\v\\f\\r \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const PYTHON_INT_LITERAL = new RegExp(`^${INT_SPACE}*([+-]?)(\\p{Nd}+(?:_\\p{Nd}+)*)${INT_SPACE}*$`, 'u');

// Python int(): truncates a number, parses a decimal string (surrounding spaces, sign, digit
// underscores and any Unicode decimal digit allowed), raises a ValueError otherwise
export const pythonInt = (value: unknown) => {
  if (typeof value === 'boolean') {
    return value ? 1 : 0;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  const literal = typeof value === 'string' ? PYTHON_INT_LITERAL.exec(value) : null;
  if (literal !== null) {
    const [, sign, digits] = literal;
    return (sign === '-' ? -1 : 1) * Number.parseInt(asciiDigits(digits.replaceAll('_', '')), 10);
  }
  if (typeof value === 'string') {
    throw new StixImportError('ValueError', 'invalid literal for int() with base 10');
  }
  throw new StixImportError('TypeError', `int() argument must be a string, a bytes-like object or a real number, not '${pythonType(value)}'`);
};

// Python str.title(): a cased character is uppercased after an uncased one (digit, dash...),
// lowercased otherwise ("x509-certificate" gives "X509-Certificate", "IPv4-Addr" gives "Ipv4-Addr")
export const pythonTitle = (text: string) => {
  let previousCased = false;
  let result = '';
  for (const character of text) {
    const cased = character.toLowerCase() !== character.toUpperCase();
    if (cased) {
      result += previousCased ? character.toLowerCase() : character.toUpperCase();
    } else {
      result += character;
    }
    previousCased = cased;
  }
  return result;
};

// Python os.path.basename: what follows the last slash
export const basename = (path: unknown) => {
  if (typeof path !== 'string') {
    throw new StixImportError('TypeError', `expected str, bytes or os.PathLike object, not ${pythonType(path)}`);
  }
  return path.slice(path.lastIndexOf('/') + 1);
};
// endregion
