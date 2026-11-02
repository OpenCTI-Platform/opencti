import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64decode } from '../../../src/intake/stix-import/utils';
import { StixImportError } from '../../../src/intake/stix-import/types';

// b64decode takes the native decoder for canonical base64 and Python's non-strict decoding for any
// other string: both paths must give pycti's bytes (base64.b64decode, values from CPython 3.12)
describe('b64decode: pycti base64.b64decode', () => {
  it('should decode canonical base64 of any length as the bytes encoded', () => {
    for (let length = 0; length < 300; length += 1) {
      const bytes = randomBytes(length);
      expect(b64decode(bytes.toString('base64')).equals(bytes)).toBe(true);
    }
  });
  it('should decode a non-canonical string as Python does', () => {
    const expected: Record<string, string> = { 'YR==': '61', 'Y Q==': '61', 'YQ==YQ==': '61', 'YWJ=': '6162' };
    Object.entries(expected).forEach(([value, hex]) => expect(b64decode(value).toString('hex'), value).toEqual(hex));
  });
  // Inputs the native decoder decodes without error but to other bytes than Python: only the round
  // trip check sends them to the Python decoder
  it('should decode as Python a string the native decoder reads differently', () => {
    const expected: Record<string, string> = { 'YWJj=YWJj': '616263616263', 'YW=Jj': '616263', 'YQ=a=': '6106', 'YWJjZA=x=': '616263640c' };
    Object.entries(expected).forEach(([value, hex]) => {
      expect(Buffer.from(value, 'base64').toString('hex'), value).not.toEqual(hex);
      expect(b64decode(value).toString('hex'), value).toEqual(hex);
    });
  });
  it('should refuse a non-ASCII string and a non-string as Python does', () => {
    expect(() => b64decode('YWJjé')).toThrow(expect.objectContaining({ name: 'ValueError', message: 'string argument should contain only ASCII characters' }));
    expect(() => b64decode(12)).toThrow(expect.objectContaining({ name: 'TypeError', message: "argument should be a bytes-like object or ASCII string, not 'int'" }));
    expect(() => b64decode(null)).toThrow(expect.objectContaining({ name: 'TypeError', message: "argument should be a bytes-like object or ASCII string, not 'NoneType'" }));
  });
  // binascii.Error (a ValueError), messages from CPython 3.12
  it('should fail as Python does on a truncated quad', () => {
    const quadOfOne = 'Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4';
    const expected: Record<string, string> = { YQ: 'Incorrect padding', '-_8=': quadOfOne, 'a===': quadOfOne };
    Object.entries(expected).forEach(([value, message]) => {
      expect(() => b64decode(value), value).toThrow(StixImportError);
      expect(() => b64decode(value), value).toThrow(expect.objectContaining({ name: 'Error', message }));
    });
  });
});
