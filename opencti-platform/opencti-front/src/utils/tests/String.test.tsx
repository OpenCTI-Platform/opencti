import { describe, it, expect } from 'vitest';
import { translateDateInterval } from '../String';

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
});
