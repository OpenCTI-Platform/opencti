import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import { heatMapOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

const darkColors = [
  '#001e3c',
  '#023362',
  '#02407a',
  '#045198',
  '#0561b4',
  '#0b75d9',
  '#2986e7',
  '#3a95f3',
  '#4da3ff',
  '#76bbff',
  '#9eccff',
];

const lightColors = [
  '#f3f6f9',
  '#76bbff',
  '#4da3ff',
  '#3a95f3',
  '#2986e7',
  '#0b75d9',
  '#0561b4',
  '#02407a',
  '#023362',
  '#001e3c',
  '#021428',
];

interface WidgetMultiHeatMapProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[];
  minValue: number;
  maxValue: number;
  isStacked?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiHeatMap = ({
  data,
  minValue,
  maxValue,
  isStacked = false,
  onMounted,
}: WidgetMultiHeatMapProps) => {
  const theme = useTheme<Theme>();
  const axisFormatter = useTimeSeriesAxisFormatter();

  const options: ApexOptions = useMemo(() => {
    // The values are counts. Up to ten ranges of whole numbers, one after the other, color every value from 1 up to
    // the hottest cell: they share a width, and the last one ends at the hottest cell. 0 keeps its own color.
    // Without a value above 0 (or without values, whose bounds are infinite), only the color of 0 is used.
    const lowestValue = Math.max(1, minValue);
    const valuesCount = maxValue >= lowestValue ? maxValue - lowestValue + 1 : 0;
    const rangeWidth = Math.max(1, Math.ceil(valuesCount / 10));
    const colorRanges = Array.from({ length: Math.ceil(valuesCount / rangeWidth) }, (_, i) => ({
      from: lowestValue + i * rangeWidth,
      to: Math.min(lowestValue + (i + 1) * rangeWidth - 1, maxValue),
      color: theme.palette.mode === 'dark' ? darkColors[i + 1] : lightColors[i + 1],
    }));
    colorRanges.push({
      from: 0,
      to: 0,
      color:
      theme.palette.mode === 'dark' ? darkColors[0] : lightColors[0],
    });

    return heatMapOptions(
      theme,
      true,
      axisFormatter,
      undefined,
      undefined,
      isStacked,
      colorRanges,
    ) as ApexOptions;
  }, [theme, isStacked, maxValue, minValue, axisFormatter]);

  return (
    <Chart
      options={options}
      series={data}
      type="heatmap"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetMultiHeatMap;
