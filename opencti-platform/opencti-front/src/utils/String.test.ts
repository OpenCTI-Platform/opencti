import purify from 'dompurify';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { displayEntityTypeForTranslation, translateDateInterval, isStringSafe, sanitize } from './String';

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
});
