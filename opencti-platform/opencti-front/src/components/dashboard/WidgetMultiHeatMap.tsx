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
    // Ten color ranges of a width of at least 1 cover the whole spread of the values, up to the hottest cell.
    // A value on the bound of two ranges takes the upper one: the last range is the one the highest value
    // starts or falls in, none lies entirely above it.
    // Without a value above 0 (or without values, whose bounds are infinite), only the color of 0 is used.
    const spread = Math.max(0, maxValue - minValue) || 0;
    const rangeWidth = Math.max(1, Math.ceil(spread / 10));
    const rangesCount = maxValue > 0 ? Math.min(10, Math.floor(spread / rangeWidth) + 1) : 0;
    const colorRanges = Array(rangesCount)
      .fill(0)
      .map((_, i) => ({
        from:
        minValue + (i + 1) * rangeWidth - rangeWidth === 0
          ? 1
          : minValue + (i + 1) * rangeWidth - rangeWidth,
        to: minValue + (i + 1) * rangeWidth,
        color:
        theme.palette.mode === 'dark'
          ? darkColors[i + 1]
          : lightColors[i + 1],
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
