import useEntitySettings from './useEntitySettings';
import { Scale, ScaleConfig, Tick } from '../../private/components/settings/sub_types/scaleConfiguration/scale';

const defaultScale: ScaleConfig = {
  better_side: 'min',
  min: {
    value: 0,
    color: '#f44336',
    label: 'Low',
  },
  max: {
    value: 100,
    color: '#6e44ad',
    label: 'Out of Range',
  },
  ticks: [
    { value: 30, color: '#ff9800', label: 'Med' },
    { value: 70, color: '#4caf50', label: 'High' },
  ],
};

const noneLevel = {
  label: 'None',
  color: '#607d8b',
};

const notSpecifiedLevel = {
  label: 'Not Specified',
  color: '#607d8b',
};

const useScale = (
  entityType: string | null,
  attributeName: string,
): ScaleConfig | null => {
  if (!entityType) {
    // return default configuration scale if entity type is not defined (ex: relationships)
    return defaultScale;
  }
  const entitySetting = useEntitySettings(entityType).find(
    (node) => node.scaleAttributes !== null,
  );
  const scaleAttribute = entitySetting?.scaleAttributes.find(
    (a) => a.name === attributeName,
  );
  if (!scaleAttribute || !scaleAttribute.scale) {
    return defaultScale;
  }
  const scale = JSON.parse(scaleAttribute.scale) as Scale;
  return scale.local_config;
};

export const buildScaleLevel = (
  value: number | null,
  scale: ScaleConfig | null | undefined,
) => {
  if (value === null || !scale) {
    return {
      level: {
        value,
        label: notSpecifiedLevel.label,
        color: notSpecifiedLevel.color,
      },
      marks: [],
      scale,
    };
  }
  let level: Tick;
  const { min, max } = scale;
  const sortedTicks = (
    scale.ticks.filter((tick) => !!tick) as Array<Tick>
  ).sort((a: Tick, b: Tick) => b.value - a.value);
  const tickLevel = sortedTicks.find((tick: Tick) => value >= tick?.value);
  if (value > max.value) {
    level = max;
  } else if (tickLevel) {
    level = tickLevel;
  } else if (value < min.value) {
    level = { value, ...noneLevel };
  } else {
    level = min;
  }
  return {
    level,
    marks: [
      min,
      ...sortedTicks.sort((a: Tick, b: Tick) => a.value - b.value),
    ],
    scale,
  };
};

export const useLevel = (
  entityType: string | null,
  attributeName: string,
  value: number | null,
) => {
  const scale = useScale(entityType, attributeName);
  if (scale) {
    return buildScaleLevel(value, scale);
  }
  return {
    level: {
      value,
      label: notSpecifiedLevel.label,
      color: notSpecifiedLevel.color,
    },
    marks: [],
    scale: null,
  };
};

export default useScale;
