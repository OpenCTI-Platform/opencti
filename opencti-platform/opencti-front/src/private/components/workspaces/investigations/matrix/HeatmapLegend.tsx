import React from 'react';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { HEAT_STOPS, heatFill } from './heatScale';

const SWATCH_WIDTH = 24;
const SWATCH_HEIGHT = 12;

interface HeatmapLegendProps {
  max: number;
  // Translated caption shown before the scale.
  title?: string;
  // Untranslated key naming the scale for assistive technologies; receives {count}.
  scaleLabel?: string;
}

// One image for assistive technologies: its name carries the whole scale, so the swatches stay silent.
const HeatmapLegend = ({ max, title, scaleLabel = 'Technique usage scale, 1 to {count}' }: HeatmapLegendProps) => {
  const { t_i18n } = useFormatter();
  return (
    <div
      role="img"
      aria-label={t_i18n(scaleLabel, { values: { count: max } })}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}
    >
      <Text variant="content-caption">{title ?? t_i18n('Technique usage (low → high)')}</Text>
      <Text variant="content-caption">1</Text>
      <span style={{ display: 'inline-flex' }}>
        {HEAT_STOPS.map((stop, index) => (
          <span
            key={stop}
            data-heat-stop={index}
            style={{ width: SWATCH_WIDTH, height: SWATCH_HEIGHT, backgroundColor: heatFill(index) }}
          />
        ))}
      </span>
      <Text variant="content-caption">{max}</Text>
    </div>
  );
};

export default HeatmapLegend;
