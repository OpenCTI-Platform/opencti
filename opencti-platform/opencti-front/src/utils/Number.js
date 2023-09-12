import { pathOr } from 'ramda';
import { UnitSystems, getLengthUnit, getUnitForSymbol, getWeightUnit } from './UnitSystems';

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

/** Returns the converted value if the conversion function can be found. Otherwise,
 * returns the given value.
 *
 * @param {number | object} value The value to be converted
 * @param {string} toUnit The desired unit to convert the value to
 * @param {string} fromUnit The current unit representing the given value
 * @param {object} unitMap An object whose first level of keys are supported from-units
 * and whose second level of keys are supported to-units and whose values are conversion
 * functions
 * @returns {{string: number}} an object that might contain one or two unit-value
 * mappings for the given converted value.
 */
const convertValue = (value, toUnit, fromUnit, unitMap) => {
  const supportedUnits = ['centimeter', 'meter', 'inch', 'foot', 'kilogram', 'pound'];
  let numericValue;
  if (typeof value === 'object') {
    supportedUnits.forEach((unitKey) => {
      if (value[unitKey]) {
        numericValue = Number(value[unitKey]);
      }
    });
  } else {
    numericValue = Number(value);
  }
  if (value === undefined || value == null) return null;
  const conversionFunc = unitMap?.[fromUnit]?.[toUnit];
  return conversionFunc ? conversionFunc(numericValue) : numericValue;
};

const CM_IN_METER = 100;
const CM_IN_INCH = 2.54;
const INCH_IN_FOOT = 12;

/* Length conversion utility functions */
/** @param {number} cm */
export const cmToMeter = (cm) => ({ meter: cm / CM_IN_METER });
/** @param {number} cm */
export const cmToCm = (cm) => ({ centimeter: cm });
/** @param {number} meter @param {=number} cm */
export const meterToCm = (meter, cm = 0) => ({ centimeter: meter * CM_IN_METER + cm });
/** @param {number} meter */
export const meterToMeter = (meter) => ({ meter });
/** @param {number} cm */
export const cmToInch = (cm) => ({ inch: cm / CM_IN_INCH });
/** @param {number} inch */
export const inchToCm = (inch) => ({ centimeter: inch * CM_IN_INCH });
/** @param {number} inch */
export const inchToMeter = (inch) => cmToMeter(inchToCm(inch).centimeter);
/** @param {number} meter */
export const meterToInch = (meter) => cmToInch(meterToCm(meter).centimeter);
/** @param {number} inch */
export const inchToFoot = (inch) => ({ foot: Math.floor(inch / INCH_IN_FOOT), inch: (inch % INCH_IN_FOOT) });
/** @param {number} inch */
export const inchToInch = (inch) => ({ inch });
/** @param {number} foot @param {=number} inch */
export const footToInch = (foot, inch = 0) => ({ inch: foot * INCH_IN_FOOT + inch });
/** @param {number} cm */
export const cmToFoot = (cm) => inchToFoot(cmToInch(cm).inch);
/** @param {number} meter */
export const meterToFoot = (meter) => cmToFoot(meterToCm(meter).centimeter);

/** @typedef PrimaryLengthUnit @type {'centimeter' | 'inch'} */
/** @typedef LengthUnit @type {'centimeter' | 'foot' | PrimaryLengthUnit} */
/** Returns a value of meters or inches converted to the desired unit.
 *
 * @param {number | object} length Length value in either meters or inches
 * @param {LengthUnit} toUnit
 * @param {PrimaryLengthUnit} fromUnit
 * @returns {{centimeter: number} | {meter: number} | {inch: number} | {foot: number, inch: number}}
 */
export const convertLength = (length, toUnit = getLengthUnit(UnitSystems.Metric), fromUnit = getLengthUnit(UnitSystems.Metric)) => {
  const unitMap = {
    meter: {
      centimeter: meterToCm,
      meter: meterToMeter,
      inch: meterToInch,
      foot: meterToFoot,
    },
    inch: {
      centimeter: inchToCm,
      meter: inchToMeter,
      inch: inchToInch,
      foot: inchToFoot,
    },
    centimeter: {
      centimeter: cmToCm,
      meter: cmToMeter,
      inch: cmToInch,
      foot: cmToFoot,
    },
  };
  return convertValue(length, toUnit, fromUnit, unitMap);
};

const KG_IN_LB = 0.45359237;

/* Weight conversion utility functions */
/** @param {number} kg */
export const kgToLb = (kg) => ({ pound: kg / KG_IN_LB });
/** @param {number} kg */
export const kgToKg = (kg) => ({ kilogram: kg });
/** @param {number} lb */
export const lbToKg = (lb) => ({ kilogram: lb * KG_IN_LB });
/** @param {number} lb */
export const lbToLb = (lb) => ({ pound: lb });

/** @typedef WeightUnit @type {'kilogram' | 'pound'} */
/** Returns a value of kilograms or pounds converted to the desired unit.
 *
 * @param {number | object} weight Weight value in either kilograms or pounds
 * @param {WeightUnit} toUnit
 * @param {WeightUnit} fromUnit
 * @returns {{kilogram: number} | {pound: number}}
 */
export const convertWeight = (weight, toUnit = getWeightUnit(UnitSystems.Metric), fromUnit = getWeightUnit(UnitSystems.Metric)) => {
  const unitMap = {
    kilogram: {
      kilogram: kgToKg,
      pound: kgToLb,
    },
    pound: {
      kilogram: lbToKg,
      pound: lbToLb,
    },
  };
  return convertValue(weight, toUnit, fromUnit, unitMap);
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
 * @property {string} defaultUnit
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
export const validateMeasurement = (data, { validKeys, measureType, defaultUnit }) => {
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
    const unit = getUnitForSymbol(unitParts.unit, defaultUnit);
    return measureType === 'weight'
      ? {
        weight_kg: convertWeight(value, getWeightUnit(UnitSystems.Metric), unit),
      }
      : {
        height_cm: convertLength(value, getLengthUnit(UnitSystems.Metric), unit),
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
