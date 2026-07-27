export interface NumberFormat {
  number: number;
  symbol: string;
  original: number;
}

export interface BytesFormat {
  number: number;
  symbol: string;
  original: number;
}

// Strips unnecessary trailing zeros from a decimal number (e.g. "1.50" → "1.5", "2.00" → "2")
const TRAILING_ZEROS_REGEX = /\.0+$|(\.\d*[1-9])0+$/;

/**
 * Returns a pseudo-random floating point number in the half-open interval [min, max).
 */
export const random = (
  min: number,
  max: number,
): number => Math.random() * (max - min) + min;

/**
 * Formats a number into a compact representation using SI prefixes (K, M, G, T, P, E).
 * Returns the scaled number, its symbol and the original value.
 */
export const numberFormat = (
  number: number,
  digits = 2,
): NumberFormat => {
  const si = [
    { value: 1, symbol: '' },
    { value: 1e3, symbol: 'K' },
    { value: 1e6, symbol: 'M' },
    { value: 1e9, symbol: 'G' },
    { value: 1e12, symbol: 'T' },
    { value: 1e15, symbol: 'P' },
    { value: 1e18, symbol: 'E' },
  ];
  let i;
  for (i = si.length - 1; i > 0; i -= 1) {
    if (number >= si[i].value) {
      break;
    }
  }
  return {
    number: Number.parseFloat((number / si[i].value).toFixed(digits).replace(TRAILING_ZEROS_REGEX, '$1')),
    symbol: si[i].symbol,
    original: number,
  };
};

/**
 * Convenience wrapper around `numberFormat` that returns the formatted value
 * as a single string (e.g. "1.23 K").
 */
export const simpleNumberFormat = (number: number, digits = 2): string => {
  const formatted = numberFormat(number, digits);
  return formatted.symbol
    ? `${formatted.number} ${formatted.symbol}`
    : `${formatted.number}`;
};

/**
 * Formats a byte count into a human-readable string using base-1024 units
 * (Bytes, KB, MB, GB, TB). Returns the scaled value, its unit and the original.
 */
export const bytesFormat = (number: number, digits = 2): BytesFormat => {
  const sizes = [' Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (number === 0) {
    return {
      number: 0,
      symbol: ' Bytes',
      original: number,
    };
  }

  const i = Math.floor(Math.log(number) / Math.log(1024));
  return {
    number: Number.parseFloat((number / 1024 ** i).toFixed(digits).replace(TRAILING_ZEROS_REGEX, '$1')),
    symbol: sizes[i],
    original: number,
  };
};

type PageInfoContainer = Record<string, { pageInfo?: { globalCount?: number } } | undefined>;

export const setNumberOfElements = <P extends Record<string, PageInfoContainer | undefined>>(
  prevProps: P,
  props: P,
  key: string,
  callback: (n: NumberFormat) => void,
  propKey: keyof P = 'data' as keyof P,
): void => {
  const currentNumberOfElements = props[propKey]?.[key]?.pageInfo?.globalCount ?? 0;
  const prevNumberOfElements = prevProps[propKey]?.[key]?.pageInfo?.globalCount ?? 0;
  if (currentNumberOfElements !== prevNumberOfElements) {
    callback(numberFormat(currentNumberOfElements));
  }
};

/**
 * Maps a numeric `value` from the range [min, max] to a discrete integer level
 * in the range [minAllowed, maxAllowed] (defaults to 0..9).
 */
export const computeLevel = (
  value: number | null | undefined,
  min: number,
  max: number,
  minAllowed = 0,
  maxAllowed = 9,
): number => {
  if (value === null || value === undefined) return minAllowed;
  return Math.trunc(
    ((maxAllowed - minAllowed) * (value - min)) / (max - min) + minAllowed,
  );
};
