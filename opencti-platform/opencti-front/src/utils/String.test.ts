import purify from 'dompurify';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { displayEntityTypeForTranslation, translateDateInterval, isStringSafe, sanitize, extractJsonContent, splitIntoLines, uniqWithByFields, computeDuplicates } from './String';

describe('String utils', () => {
  describe('translateDateInterval', () => {
    it('should translate a string interval in relative date phrase if possible', () => {
      const t = (s: string) => s;
      expect(() => translateDateInterval(['test'], t)).toThrowError();
      expect(() => translateDateInterval(['test', 'now'], t)).toThrowError();
      expect(() => translateDateInterval(['now', 'now'], t)).toThrowError();
      expect(() => translateDateInterval(['now-1d', 'now+1d'], t)).toThrowError();
      expect(() => translateDateInterval(['now-1d/d', 'now'], t)).toThrowError();
      expect(translateDateInterval(['now-1d', 'now'], t)).toEqual('Last 1 day');
      expect(translateDateInterval(['now-2H', 'now'], t)).toEqual('Last 2 hours');
      expect(translateDateInterval(['now-10y', 'now'], t)).toEqual('Last 10 years');
    });
  });

  describe('displayEntityTypeForTranslation', () => {
    it('should translate an entity type in a translatable string', () => {
      expect(displayEntityTypeForTranslation(undefined)).toEqual(undefined);
      expect(displayEntityTypeForTranslation('Malware')).toEqual('entity_Malware');
      expect(displayEntityTypeForTranslation('targets')).toEqual('relationship_targets');
    });
  });

  describe('Function: isStringSafe()', () => {
    afterEach(() => {
      vi.clearAllMocks();
      vi.resetAllMocks();
    });

    it('should return true if safe', () => {
      // If purify does not change the input.
      vi.spyOn(purify, 'sanitize').mockImplementation((d) => `${d}`);
      expect(isStringSafe('string without issues')).toEqual(true);
    });

    it('should return false if not safe', () => {
      // If purify changes the input.
      vi.spyOn(purify, 'sanitize').mockImplementation((d) => `${d} transformed`);
      expect(isStringSafe('string with issues')).toEqual(false);
    });
  });

  describe('Function: sanitize()', () => {
    it('should return same string if safe', () => {
      const testA = '';
      const testB = 'string without any html';
      const testC = '<p>simple <strong>safe</strong> html</p>';

      expect(sanitize(testA)).toEqual(testA);
      expect(isStringSafe(sanitize(testA))).toEqual(true);
      expect(sanitize(testB)).toEqual(testB);
      expect(isStringSafe(sanitize(testB))).toEqual(true);
      expect(sanitize(testC)).toEqual(testC);
      expect(isStringSafe(sanitize(testC))).toEqual(true);
    });

    it('should return sanitized string if not safe (without escape)', () => {
      const testA = '<img src=x onerror=alert(1)//>';
      const testB = '<svg><g/onload=alert(2)//<p>';
      const testC = '<p>abc<iframe//src=jAva&Tab;script:alert(3)>def</p>';

      expect(sanitize(testA)).toEqual('<img src="x">');
      expect(isStringSafe(testA)).toEqual(false);
      expect(isStringSafe(sanitize(testA))).toEqual(true);
      expect(sanitize(testB)).toEqual('<svg><g></g></svg>');
      expect(isStringSafe(testB)).toEqual(false);
      expect(isStringSafe(sanitize(testB))).toEqual(true);
      expect(sanitize(testC)).toEqual('<p>abc</p>');
      expect(isStringSafe(testC)).toEqual(false);
      expect(isStringSafe(sanitize(testC))).toEqual(true);
    });

    it('should return sanitized string if not safe (with escape)', () => {
      const testA = '<img src=x onerror=alert(1)//>';
      const testB = '<svg><g/onload=alert(2)//<p>';
      const testC = '<p>abc<iframe//src=jAva&Tab;script:alert(3)>def</p>';

      expect(sanitize(testA, true)).toEqual('&lt;img src=x onerror=alert(1)//&gt;');
      expect(isStringSafe(testA)).toEqual(false);
      expect(isStringSafe(sanitize(testA, true))).toEqual(true);
      expect(sanitize(testB, true)).toEqual('&lt;svg&gt;&lt;g/onload=alert(2)//&lt;p&gt;');
      expect(isStringSafe(testB)).toEqual(false);
      expect(isStringSafe(sanitize(testB, true))).toEqual(true);
      expect(sanitize(testC, true)).toEqual('&lt;p&gt;abc&lt;iframe//src=jAva&amp;Tab;script:alert(3)&gt;def&lt;/p&gt;');
      expect(isStringSafe(testC)).toEqual(false);
      expect(isStringSafe(sanitize(testC, true))).toEqual(true);
    });
  });

  describe('extractJsonContent', () => {
    it('should extract JSON from a ```json code block', () => {
      const input = '```json\n{"key": "value"}\n```';
      expect(extractJsonContent(input)).toBe('{"key": "value"}');
    });

    it('should extract JSON from a ``` code block without language tag', () => {
      const input = '```\n{"a": 1}\n```';
      expect(extractJsonContent(input)).toBe('{"a": 1}');
    });

    it('should return trimmed content when there is no code block', () => {
      expect(extractJsonContent('  {"plain": true}  ')).toBe('{"plain": true}');
    });

    it('should handle extra whitespace inside code block', () => {
      const input = '```json\n  \n  {"spaced": true}  \n  \n```';
      expect(extractJsonContent(input)).toBe('{"spaced": true}');
    });

    it('should extract only the first code block', () => {
      const input = 'text ```json\n{"first": 1}\n``` more ```json\n{"second": 2}\n```';
      expect(extractJsonContent(input)).toBe('{"first": 1}');
    });

    it('should handle multiline JSON inside code block', () => {
      const input = '```json\n{\n  "a": 1,\n  "b": 2\n}\n```';
      expect(extractJsonContent(input)).toBe('{\n  "a": 1,\n  "b": 2\n}');
    });

    it('should return trimmed string for empty input', () => {
      expect(extractJsonContent('')).toBe('');
      expect(extractJsonContent('   ')).toBe('');
    });
  });

  describe('splitIntoLines', () => {
    it('should split text by newlines', () => {
      expect(splitIntoLines('a\nb\nc')).toBe('a\nb\nc');
    });

    it('should split text by commas', () => {
      expect(splitIntoLines('a,b,c')).toBe('a\nb\nc');
    });

    it('should split text by semicolons', () => {
      expect(splitIntoLines('a;b;c')).toBe('a\nb\nc');
    });

    it('should split text with mixed separators', () => {
      expect(splitIntoLines('a,b;c\nd,e')).toBe('a\nb\nc\nd\ne');
    });

    it('should handle a single value without separators', () => {
      expect(splitIntoLines('hello')).toBe('hello');
    });

    it('should handle empty string', () => {
      expect(splitIntoLines('')).toBe('');
    });

    it('should handle consecutive separators', () => {
      expect(splitIntoLines('a,,b')).toBe('a\n\nb');
    });
  });

  describe('uniqWithByFields', () => {
    it('should remove duplicates based on a single field', () => {
      const data = [{ id: '1', name: 'a' }, { id: '2', name: 'b' }, { id: '1', name: 'c' }];
      const result = uniqWithByFields<typeof data[0]>(['id'])(data);
      expect(result).toEqual([{ id: '1', name: 'a' }, { id: '2', name: 'b' }]);
    });

    it('should remove duplicates based on multiple fields', () => {
      const data = [
        { x: 1, y: 2, z: 'a' },
        { x: 1, y: 2, z: 'b' },
        { x: 1, y: 3, z: 'c' },
      ];
      const result = uniqWithByFields<typeof data[0]>(['x', 'y'])(data);
      expect(result).toEqual([
        { x: 1, y: 2, z: 'a' },
        { x: 1, y: 3, z: 'c' },
      ]);
    });

    it('should return empty array for empty input', () => {
      expect(uniqWithByFields(['id'])([])).toEqual([]);
    });

    it('should handle deep equality for object fields', () => {
      const data = [
        { id: '1', meta: { a: 1 } },
        { id: '2', meta: { a: 1 } },
        { id: '3', meta: { a: 2 } },
      ];
      const result = uniqWithByFields<typeof data[0]>(['meta'])(data);
      expect(result).toEqual([
        { id: '1', meta: { a: 1 } },
        { id: '3', meta: { a: 2 } },
      ]);
    });
  });

  describe('computeDuplicates', () => {
    it('should group consecutive elements with same field values', () => {
      const data = [
        { id: '1', name: 'a' },
        { id: '1', name: 'b' },
        { id: '2', name: 'c' },
        { id: '2', name: 'd' },
        { id: '1', name: 'e' },
      ];
      const result = computeDuplicates(['id'], data);
      expect(result).toEqual([
        [{ id: '1', name: 'a' }, { id: '1', name: 'b' }],
        [{ id: '2', name: 'c' }, { id: '2', name: 'd' }],
        [{ id: '1', name: 'e' }],
      ]);
    });

    it('should return empty array for empty input', () => {
      expect(computeDuplicates(['id'], [])).toEqual([]);
    });

    it('should return single group if all elements match', () => {
      const data = [{ x: 1, y: 'a' }, { x: 1, y: 'b' }];
      expect(computeDuplicates(['x'], data)).toEqual([[{ x: 1, y: 'a' }, { x: 1, y: 'b' }]]);
    });

    it('should return one group per element if none are consecutive duplicates', () => {
      const data = [{ id: '1' }, { id: '2' }, { id: '3' }];
      expect(computeDuplicates(['id'], data)).toEqual([[{ id: '1' }], [{ id: '2' }], [{ id: '3' }]]);
    });

    it('should group by multiple fields', () => {
      const data = [
        { a: 1, b: 2, c: 'x' },
        { a: 1, b: 2, c: 'y' },
        { a: 1, b: 3, c: 'z' },
      ];
      const result = computeDuplicates(['a', 'b'], data);
      expect(result).toEqual([
        [{ a: 1, b: 2, c: 'x' }, { a: 1, b: 2, c: 'y' }],
        [{ a: 1, b: 3, c: 'z' }],
      ]);
    });
  });
});
