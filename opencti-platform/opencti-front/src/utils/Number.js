import { pathOr } from 'ramda';

export const random = (min, max) => Math.random() * (max - min) + min;

export const numberFormat = (number, digits = 2) => {
  const si = [
    { value: 1, symbol: '' },
    { value: 1e3, symbol: 'K' },
    { value: 1e6, symbol: 'M' },
    { value: 1e9, symbol: 'G' },
    { value: 1e12, symbol: 'T' },
    { value: 1e15, symbol: 'P' },
    { value: 1e18, symbol: 'E' },
  ];
  const rx = /\.0+$|(\.\d*[1-9])0+$/;
  let i;
  for (i = si.length - 1; i > 0; i -= 1) {
    if (number >= si[i].value) {
      break;
    }
  }
  return {
    number: (number / si[i].value).toFixed(digits).replace(rx, '$1'),
    symbol: si[i].symbol,
    original: number,
  };
};

export const simpleNumberFormat = (number, digits = 2) => {
  const formatted = numberFormat(number, digits);
  return `${formatted.number} ${formatted.symbol}`;
};

export const bytesFormat = (number, digits = 2) => {
  const rx = /\.0+$|(\.\d*[1-9])0+$/;
  const sizes = [' Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (number === 0) {
    return {
      // eslint-disable-next-line no-restricted-properties
      number: 0,
      symbol: ' Bytes',
      original: number,
    };
  }
  // eslint-disable-next-line radix
  const i = parseInt(Math.floor(Math.log(number) / Math.log(1024)));
  return {
    // eslint-disable-next-line no-restricted-properties
    number: (number / 1024 ** i).toFixed(digits).replace(rx, '$1'),
    symbol: sizes[i],
    original: number,
  };
};

/**
 * @typedef Weight
 * @type {object}
 * @property {number} weight_kg
 * @property {Date|string|null} date_seen
 */
/**
 * @typedef Height
 * @type {object}
 * @property {number} height_cm
 * @property {Date|string|null} date_seen
 */
/**
 * @typedef UnitValidationOptions
 * @type {object}
 * @property {string[]} validKeys
 * @property {'weight'|'length'} measureType
 */
/** @typedef Measurement @type {Height | Weight} */
/**
 * Takes any string or object and attempts to return a measurement object.
 * Parses a string with a numeric value and supported unit into a measurement object.
 * If either the object or string are invalid, returns a string with an error message.
 * @param {Measurement | string} data
 * @param {UnitValidationOptions} options
 * @returns {Measurement | string | null}
 */
export const validateMeasurement = (data, { validKeys, measureType }) => {
  if (data === undefined || data == null) return null;
  if (typeof data === 'string') {
    // Handle case where data is 'Unknown' if unset in database
    if (data.toLowerCase() === 'unknown') return data;
    // Separate value from unit and validate
    const measuRE = /(?<value>\d+\.?\d*) ?(?<unit>.*)/;
    const unitParts = { ...measuRE.exec(data)?.groups };
    const { value } = unitParts;
    if (Number.isNaN(parseInt(value, 10))) {
      // Measurement value is not a valid numeric value
      return data;
    }
    return measureType === 'weight'
      ? {
        weight_kg: Number(value),
      }
      : {
        height_cm: Number(value),
      };
  }
  // Validate measurement object
  const weightKeys = ['weight_kg', 'weight_lb'];
  const heightKeys = ['height_cm', 'height_in'];
  const keyList = validKeys || (measureType === 'weight' ? weightKeys : heightKeys);
  const dataHasValidKey = keyList.map((key) => Object.keys(data).includes(key))
    .reduce((prev, curr) => prev || curr);
  return dataHasValidKey
    ? data
    : `Measurement data did not have a property matching any of ${keyList}`;
};

export const setNumberOfElements = (
  prevProps,
  props,
  key,
  callback,
  propKey = 'data',
) => {
  const currentNumberOfElements = pathOr(
    0,
    [key, 'pageInfo', 'globalCount'],
    props[propKey],
  );
  const prevNumberOfElements = pathOr(
    0,
    [key, 'pageInfo', 'globalCount'],
    prevProps[propKey],
  );
  if (currentNumberOfElements !== prevNumberOfElements) {
    callback(numberFormat(currentNumberOfElements));
  }
};

export const computeLevel = (value, min, max, minAllowed = 0, maxAllowed = 9) => Math.trunc(
  ((maxAllowed - minAllowed) * (value - min)) / (max - min) + minAllowed,
);
