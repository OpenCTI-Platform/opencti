import { describe, expect, it, vi } from 'vitest';
import { bytesFormat, computeLevel, numberFormat, setNumberOfElements, simpleNumberFormat } from './Number';

describe('Function: numberFormat', () => {
  it('should format a number with the appropriate SI symbol', () => {
    expect(numberFormat(1500)).toEqual({ number: 1.5, symbol: 'K', original: 1500 });
  });

  it('should leave small numbers untouched with an empty symbol', () => {
    expect(numberFormat(42)).toEqual({ number: 42, symbol: '', original: 42 });
  });

  it('should respect the requested precision', () => {
    expect(numberFormat(1_234_567, 1)).toEqual({ number: 1.2, symbol: 'M', original: 1_234_567 });
  });
});

describe('Function: simpleNumberFormat', () => {
  it('should return the formatted number and symbol as a single string', () => {
    expect(simpleNumberFormat(2_500_000)).toBe('2.5 M');
  });

  it('should use the requested number of digits', () => {
    expect(simpleNumberFormat(1_234, 0)).toBe('1 K');
  });

  it('should return only the number when symbol is empty', () => {
    expect(simpleNumberFormat(42)).toBe('42');
  });
});

describe('Function: bytesFormat', () => {
  it('should format a byte count using binary prefixes', () => {
    expect(bytesFormat(1024)).toEqual({ number: 1, symbol: 'KB', original: 1024 });
    expect(bytesFormat(1_572_864)).toEqual({ number: 1.5, symbol: 'MB', original: 1_572_864 });
    expect(bytesFormat(1024 ** 3)).toEqual({ number: 1, symbol: 'GB', original: 1024 ** 3 });
  });

  it('should return zero bytes for a zero input', () => {
    expect(bytesFormat(0)).toEqual({ number: 0, symbol: ' Bytes', original: 0 });
  });
});

describe('Function: setNumberOfElements', () => {
  it('should invoke callback with formatted count when globalCount changes', () => {
    const callback = vi.fn();
    const prevProps = { data: { items: { pageInfo: { globalCount: 10 } } } };
    const props = { data: { items: { pageInfo: { globalCount: 1500 } } } };
    setNumberOfElements(prevProps, props, 'items', callback);
    expect(callback).toHaveBeenCalledWith({ number: 1.5, symbol: 'K', original: 1500 });
  });

  it('should not invoke callback when globalCount is unchanged', () => {
    const callback = vi.fn();
    const prevProps = { data: { items: { pageInfo: { globalCount: 42 } } } };
    const props = { data: { items: { pageInfo: { globalCount: 42 } } } };
    setNumberOfElements(prevProps, props, 'items', callback);
    expect(callback).not.toHaveBeenCalled();
  });
});

describe('Function: computeLevel', () => {
  it('should map a value to a discrete level within the allowed range', () => {
    expect(computeLevel(50, 0, 100)).toBe(4);
  });

  it('should return minAllowed when value is null or undefined', () => {
    expect(computeLevel(null, 0, 100)).toBe(0);
    expect(computeLevel(undefined, 0, 100, 3, 9)).toBe(3);
  });

  it('should correctly map zero as a valid value instead of treating it as falsy', () => {
    expect(computeLevel(0, 0, 100)).toBe(0);
    expect(computeLevel(0, -50, 50, 0, 9)).toBe(4);
  });
});
