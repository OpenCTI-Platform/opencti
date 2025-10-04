import { FormatNumberOptions, useIntl } from 'react-intl';
import convert, { Length, Mass, Unit } from 'convert';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data,
} from '@private/components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import { MeasureInput } from '@private/components/threats/threat_actors_individual/__generated__/ThreatActorIndividualCreationMutation.graphql';
import useAuth from './useAuth';
import { DEFAULT_LANG, LANGUAGES } from '../BrowserLanguage';
import { isEmptyField } from '../utils';
import { UnitSystem } from '../../private/__generated__/RootMe_data.graphql';

export const BASE_LENGTH_TYPE: Length = 'm';
export const BASE_WEIGHT_TYPE: Mass = 'kg';

type SupportedUnitType = 'Imperial' | 'Metric';

type UnitType = {
  length: Length,
  weight: Mass,
};

export const Units: { [k in SupportedUnitType]: UnitType } = {
  Imperial: {
    length: '\'',
    weight: 'lb',
  },
  Metric: {
    length: BASE_LENGTH_TYPE,
    weight: BASE_WEIGHT_TYPE,
  },
};

const computeUserUnit = (selectedSystem?: UnitSystem | null, selectedLanguage = DEFAULT_LANG): SupportedUnitType => {
  const unitSystem = selectedSystem || 'auto';
  if (unitSystem === 'auto' || unitSystem === '%future added value') {
    const languageLocale = selectedLanguage && selectedLanguage !== LANGUAGES.AUTO ? selectedLanguage : DEFAULT_LANG;
    return languageLocale === LANGUAGES.ENGLISH ? 'Imperial' : 'Metric';
  }
  return unitSystem;
};

const heightsConverterLoad = (userMetricType: SupportedUnitType) => {
  return (heights: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['height']) : ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['height'] => {
    return (heights ?? []).map((data) => {
      const { measure, date_seen, index } = data;
      const numericMeasure = parseFloat(String(measure));
      const lengthPrimaryUnit = Units[userMetricType].length;
      const converted = convert<number, Unit>(numericMeasure, 'm').to(lengthPrimaryUnit).toFixed(2); // Meter is the pivot format
      return { measure: Number(converted), date_seen, index };
    });
  };
};
const heightToPivotFormat = (userMetricType: SupportedUnitType) => {
  return (measure: number | string | null | undefined) => {
    const lengthPrimaryUnit = Units[userMetricType].length;
    const numericMeasure = parseFloat(String(measure));
    return Number(convert<number, Unit>(numericMeasure, lengthPrimaryUnit).to('m').toFixed(8)); // Meter is the pivot format
  };
};
const heightsConverterSave = (userMetricType: SupportedUnitType) => {
  const pivotConverter = heightToPivotFormat(userMetricType);
  return (heights: MeasureInput[]) : MeasureInput[] => {
    return (heights ?? []).map(({ measure, date_seen }) => {
      return { measure: pivotConverter(measure), date_seen };
    });
  };
};

const weightsConverterLoad = (userMetricType: SupportedUnitType) => {
  return (weights: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['weight']) : ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['weight'] => {
    return (weights ?? []).map(({ measure, date_seen, index }) => {
      const numericMeasure = parseFloat(String(measure));
      const weightPrimaryUnit = Units[userMetricType].weight;
      const converted = convert<number, Unit>(numericMeasure, 'kg').to(weightPrimaryUnit).toFixed(2); // Meter is the pivot format
      return { measure: Number(converted), date_seen, index };
    });
  };
};
const weightToPivotFormat = (userMetricType: SupportedUnitType) => {
  return (measure: number | string | null | undefined) => {
    const weightPrimaryUnit = Units[userMetricType].weight;
    const numericMeasure = parseFloat(String(measure));
    return Number(convert<number, Unit>(numericMeasure, weightPrimaryUnit).to('kg').toFixed(8)); // Kg is the pivot format
  };
};
const weightsConverterSave = (userMetricType: SupportedUnitType) => {
  const pivotConverter = weightToPivotFormat(userMetricType);
  return (weights: MeasureInput[]) : MeasureInput[] => {
    return (weights ?? []).map(({ measure, date_seen }) => {
      return { measure: pivotConverter(measure), date_seen };
    });
  };
};

const useUserMetric = () => {
  const { me } = useAuth();
  const intl = useIntl();
  const unitSystem = computeUserUnit(me.unit_system, intl.locale);
  const lengthPrimaryUnit = Units[unitSystem].length;
  const weightPrimaryUnit = Units[unitSystem].weight;
  const heightsConverterSaveFn = heightsConverterSave(unitSystem);
  const heightsConverterLoadFn = heightsConverterLoad(unitSystem);
  const weightsSaveConverterFn = weightsConverterSave(unitSystem);
  const weightsConverterLoadFn = weightsConverterLoad(unitSystem);
  const heightToPivotFormatFn = heightToPivotFormat(unitSystem);
  const weightToPivotFormatFn = weightToPivotFormat(unitSystem);
  const formatLength = (number: number) => {
    if (isEmptyField(number)) return '';
    const converted = convert(number, BASE_LENGTH_TYPE).to(lengthPrimaryUnit);
    const formatOpts: FormatNumberOptions = { maximumFractionDigits: 2, unitDisplay: 'long' };
    return intl.formatNumber(Number(converted), formatOpts);
  };
  const formatWeight = (number: number) => {
    if (isEmptyField(number)) return '';
    const converted = convert(number, BASE_WEIGHT_TYPE).to(weightPrimaryUnit);
    const formatOpts: FormatNumberOptions = { maximumFractionDigits: 2, unitDisplay: 'long' };
    return intl.formatNumber(Number(converted), formatOpts);
  };
  return {
    len: formatLength,
    wgt: formatWeight,
    weightPrimaryUnit,
    lengthPrimaryUnit,
    heightToPivotFormat: heightToPivotFormatFn,
    weightToPivotFormat: weightToPivotFormatFn,
    heightsConverterSave: heightsConverterSaveFn,
    heightsConverterLoad: heightsConverterLoadFn,
    weightsConverterSave: weightsSaveConverterFn,
    weightsConverterLoad: weightsConverterLoadFn,
  };
};

export default useUserMetric;
