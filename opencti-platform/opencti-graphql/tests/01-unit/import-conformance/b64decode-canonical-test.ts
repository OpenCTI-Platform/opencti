import { describe, expect, it } from 'vitest';
import { b64decode, pythonType } from '../../../src/intake/stix-import/utils';
import { StixImportError } from '../../../src/intake/stix-import/types';

// Oracle for the canonical-base64 check of b64decode (no re-encoding): b64decode as of b48f3c0250
// (round trip native.toString('base64') === value), copied below, must give the same bytes or the
// same error on every input.

// ---- reference: b64decode before the rewrite ----
const BASE64_VALUES_OLD = new Map([...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'].map((character, index) => [character, index]));

const b64decodeOld = (value: unknown) => {
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
    const sextet = BASE64_VALUES_OLD.get(character);
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

const outcome = (decode: (value: unknown) => Buffer, value: unknown) => {
  try {
    return decode(value).toString('hex');
  } catch (error: any) {
    return `${error instanceof StixImportError}:${error.name}:${error.message}`;
  }
};

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

const expectSame = (value: string) => expect(outcome(b64decode, value), JSON.stringify(value)).toBe(outcome(b64decodeOld, value));
// the inputs among `values` decoded differently (one expect for many inputs)
const differing = (values: Iterable<string>) => [...values].filter((value) => outcome(b64decode, value) !== outcome(b64decodeOld, value));

describe('b64decode oracle: canonical check without round trip', () => {
  it('should decode as the round-trip version on 300,000 mutated and random strings (bench-b64check)', () => {
    const rnd = lcg(5);
    const values: string[] = [];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ \n.\téőｗĭ';
    for (let k = 0; k < 300000; k += 1) {
      let s = '';
      if (rnd() < 0.6) {
        const bytes = Buffer.alloc(Math.floor(rnd() * 14));
        for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(rnd() * 256);
        s = bytes.toString('base64');
        const edits = Math.floor(rnd() * 3);
        for (let e = 0; e < edits && s.length; e += 1) {
          const p = Math.floor(rnd() * s.length);
          const op = rnd();
          const c = alphabet[Math.floor(rnd() * alphabet.length)];
          if (op < 0.4) s = s.slice(0, p) + c + s.slice(p + 1);
          else if (op < 0.7) s = s.slice(0, p) + c + s.slice(p);
          else s = s.slice(0, p) + s.slice(p + 1);
        }
      } else {
        const l = Math.floor(rnd() * 12);
        for (let i = 0; i < l; i += 1) s += alphabet[Math.floor(rnd() * alphabet.length)];
      }
      values.push(s);
    }
    expect(differing(values)).toEqual([]);
  });

  it('should decode as the round-trip version with any UTF-16 code unit at any position of every padding shape', () => {
    // the native decoder reads the low byte of a code unit past 0xff ('ｗ' as 'W'), skips
    // 0x80-0xff, reads '-' and '_' as url-safe: every code unit, at every position
    const templates = ['YWJj', 'YWI=', 'YQ=='];
    function* substituted() {
      for (const template of templates) {
        for (let position = 0; position < template.length; position += 1) {
          for (let code = 0; code < 0x10000; code += 1) {
            yield template.slice(0, position) + String.fromCharCode(code) + template.slice(position + 1);
          }
        }
      }
    }
    expect(differing(substituted())).toEqual([]);
  });

  it('should take the native bytes for canonical base64 of every length and refuse what the round trip refused', () => {
    const rnd = lcg(9);
    for (let length = 0; length < 200; length += 1) {
      const bytes = Buffer.alloc(length);
      for (let i = 0; i < length; i += 1) bytes[i] = Math.floor(rnd() * 256);
      const value = bytes.toString('base64');
      expect(b64decode(value).equals(bytes)).toBe(true);
      expectSame(value);
      expectSame(`${value}=`);
      expectSame(`${value}====`);
      expectSame(` ${value}`);
      expectSame(value.replace(/\+/g, '-').replace(/\//g, '_'));
    }
    // unused bits set in the last data character (YR== and YWK= decode as YQ== and YWI=)
    ['YR==', 'YWK=', 'YWJ=', 'Y===', '', '====', 'YQ=a', 'YQ==YQ==', 'YW=Jj', 'YQ=a=', 'YWJjZA=x='].forEach(expectSame);
    // a large file, canonical: the native buffer itself
    const big = Buffer.alloc(3_000_001, 7);
    expect(b64decode(big.toString('base64')).equals(big)).toBe(true);
  });
});
