import React from 'react';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { pulseTrendBarHeights } from './threatPulseUtils';

const CHART_HEIGHT = 32;

interface ThreatPulseTrendChartProps {
  // Contributing platforms per week, the oldest week first.
  series: readonly number[];
  label: string;
}

/**
 * The weekly series XTM Hub publishes, one bar per week, the latest one emphasized. Two weeks draw two bars side by
 * side, never a line between them; a single week or an empty series draws nothing.
 */
const ThreatPulseTrendChart = ({ series, label }: ThreatPulseTrendChartProps) => {
  const theme = useTheme();
  if (series.length < 2 || series.every((value) => value === 0)) {
    return null;
  }
  const latest = series.length - 1;
  const twoPoints = series.length === 2;
  const barColor = (index: number) => {
    if (series[index] === 0) return alpha(theme.palette.text.primary, 0.12);
    return index === latest ? theme.palette.primary.main : alpha(theme.palette.primary.main, 0.45);
  };
  return (
    <Box
      role="img"
      aria-label={label}
      data-testid="threat-pulse-sparkline"
      data-variant={twoPoints ? 'two-points' : 'weekly'}
      sx={{ display: 'flex', alignItems: 'flex-end', gap: twoPoints ? 0.75 : 0.5, height: CHART_HEIGHT, flexShrink: 0 }}
    >
      {pulseTrendBarHeights(series, CHART_HEIGHT).map((height, index) => (
        <Box
          key={`week-${index}`}
          data-testid="threat-pulse-sparkline-bar"
          sx={{ width: twoPoints ? 14 : 8, height, borderRadius: 0.5, backgroundColor: barColor(index) }}
        />
      ))}
    </Box>
  );
};

export default ThreatPulseTrendChart;
