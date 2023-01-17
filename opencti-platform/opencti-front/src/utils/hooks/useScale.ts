import {
  ConfidenceScaleConfiguration,
  Tick,
} from '../../private/components/settings/sub_types/EntitySettingConfidenceScale';
import useEntitySettings from './useEntitySettings';

export enum SCALE_KEYS {
  // If you add a new scale key, don't forget to add your attribute in EntitySettingConnection Fragment
  confidence = 'confidence_scale',
}

const useScale = (entity_type: string, scaleKey: SCALE_KEYS): ConfidenceScaleConfiguration | null => {
  const entitySetting = useEntitySettings(entity_type)
    .find((node) => node[scaleKey] !== null);

  if (!entitySetting || !entitySetting[scaleKey]) {
    return null;
  }
  const { localConfig } = JSON.parse(entitySetting[scaleKey] as string);
  return localConfig as ConfidenceScaleConfiguration;
};

export const buildConfidenceLevel = (confidenceValue: number | null, confidenceScale: ConfidenceScaleConfiguration | null) => {
  if (!confidenceValue || !confidenceScale) {
    return {
      level: {
        value: confidenceValue,
        label: 'None',
        color: '#607d8b',
      },
      marks: [],
    };
  }
  let label;
  let color;
  const { min, max } = confidenceScale;
  const { ticks } = confidenceScale;

  const confidenceTick = (ticks.filter((value) => !!value) as Array<Tick>)
    .sort((a: Tick, b: Tick) => b.value - a.value)
    .find((tick: Tick) => confidenceValue >= tick?.value);

  if (confidenceTick) {
    label = confidenceTick.label;
    color = confidenceTick.color;
  } else if (confidenceValue >= max.value) {
    label = max.label;
    color = max.color;
  } else {
    label = min.label;
    color = min.color;
  }

  const sortedTicks = (ticks.filter((value) => !!value) as Array<Tick>)
    .sort((a: Tick, b: Tick) => b.value - a.value);

  return {
    level: {
      value: confidenceValue,
      label,
      color,
    },
    marks: [min, ...sortedTicks, max],
  };
};

export const useLevel = (entityType: string, scaleKey: SCALE_KEYS, value: number | null) => {
  const scale = useScale(entityType, scaleKey);
  if (scaleKey === SCALE_KEYS.confidence) {
    return buildConfidenceLevel(value, scale);
  }
  return {
    level: {
      value,
      label: 'None',
      color: '#607d8b',
    },
    marks: [],
  };
};

export default useScale;
