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
    number: Number.parseFloat((number / si[i].value).toFixed(digits).replace(rx, '$1')),
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

      number: 0,
      symbol: ' Bytes',
      original: number,
    };
  }

  const i = parseInt(Math.floor(Math.log(number) / Math.log(1024)));
  return {

    number: (number / 1024 ** i).toFixed(digits).replace(rx, '$1'),
    symbol: sizes[i],
    original: number,
  };
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
