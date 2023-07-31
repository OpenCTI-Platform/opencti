import { DEFAULT_LANG, LANGUAGES } from './BrowserLanguage';

/**
 * @type UnitSystems
 * @property {'US'} US - US metric system.
 * @property {'Metric'} Metric - International system of units (SI).
 * @property {'auto'} Auto - Default metric system determined by locale ('en-us' => 'US')
 */
export enum UnitSystems {
  US = 'US',
  Metric = 'Metric',
  Auto = 'auto',
}

export type UnitsRecord = {
  [UnitSystem in UnitSystems]: {
    length: {
      primary: string,
      secondary: string,
    },
    weight: string,
  }
};

/**
 * Supported unit systems and associated units.
 */
export const Units: UnitsRecord = {
  [UnitSystems.US]: {
    length: {
      primary: 'inch',
      secondary: 'foot',
    },
    weight: 'pound',
  },
  [UnitSystems.Metric]: {
    length: {
      primary: 'centimeter',
      secondary: 'meter',
    },
    weight: 'kilogram',
  },
  [UnitSystems.Auto]: {
    length: {
      primary: 'inch',
      secondary: 'foot',
    },
    weight: 'pound',
  },
};

/**
 * Validates a given unit system name and ensures that a unit system is returned in case
 * an invalid name is given or the unit system is set to default. The best unit system is
 * selected by using the provided language selection.
 *
 * @param selectedSystem
 * @param selectedLanguage
 * @returns an appropriate string representing the name of a supported unit system
 */
export const validateUnitSystem = (selectedSystem: UnitSystems | null, selectedLanguage = DEFAULT_LANG) => {
  const unitSystem = selectedSystem || UnitSystems.Auto;
  if (unitSystem === UnitSystems.Auto || UnitSystems[unitSystem] === undefined) {
    const languageLocale = selectedLanguage && selectedLanguage !== LANGUAGES.AUTO
      ? selectedLanguage
      : DEFAULT_LANG;
    return languageLocale === LANGUAGES.ENGLISH
      ? UnitSystems.US
      : UnitSystems.Metric;
  }
  return unitSystem;
};

/**
 * Returns the primary or secondary length unit for the given unit system.
 * If the given unit system is not recognized, returns null.
 *
 * See the Units object for supported unit systems and units.
 *
 * @param unitSystem The key name
 * @param secondary If true, will return the secondary length value
 */
export const getLengthUnit = (unitSystem: UnitSystems, secondary = false): string | null => {
  if (!unitSystem || !Object.prototype.hasOwnProperty.call(Units, unitSystem)) return null;
  if (secondary) return Units[unitSystem].length.secondary;
  return Units[unitSystem].length.primary;
};

/**
 * @param locale
 * @param secondary
 */
export const getLengthUnitForLocale = (locale: string = DEFAULT_LANG, secondary = false): string | null => {
  const unitSystem = validateUnitSystem(null, locale);
  return getLengthUnit(unitSystem, secondary);
};

/**
 * Returns the primary or secondary weight unit for the given unit system.
 * If the given unit system is not recognized, returns null.
 *
 * See the Units object for supported unit systems and units.
 *
 * @param unitSystem The key name
 */
export const getWeightUnit = (unitSystem: UnitSystems): string | null => (
  (unitSystem && Object.prototype.hasOwnProperty.call(Units, unitSystem)) ? Units[unitSystem].weight : null
);

/**
 * @param locale
 */
export const getWeightUnitForLocale = (locale: string = DEFAULT_LANG): string | null => {
  const unitSystem = validateUnitSystem(null, locale);
  return getWeightUnit(unitSystem);
};

/**
 * Returns the unit represented by the given symbol or unit string.
 * @param symbol
 * @param defaultUnit - Used if the correct unit could not be determined
 */
export const getUnitForSymbol = (symbol: string, defaultUnit: string): string | null => {
  if (['inch', 'inches', 'in', '"'].includes(symbol)) return getLengthUnit(UnitSystems.US);
  if (['foot', 'feet', 'ft', "'"].includes(symbol)) return getLengthUnit(UnitSystems.US, true);
  if (['meter', 'meters', 'm'].includes(symbol)) return getLengthUnit(UnitSystems.Metric);
  if (['centimeter', 'centimeters', 'cm'].includes(symbol)) return getLengthUnit(UnitSystems.Metric, true);
  if (['kilogram', 'kilograms', 'kg'].includes(symbol)) return getWeightUnit(UnitSystems.Metric);
  if (['pound', 'pounds', 'lb', 'lbs'].includes(symbol)) return getWeightUnit(UnitSystems.US);
  return defaultUnit || null;
};
