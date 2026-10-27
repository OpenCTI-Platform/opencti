import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
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
  interval?: string | null;
  isAnimated?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiHeatMap = ({
  data,
  minValue,
  maxValue,
  isStacked = false,
  interval,
  isAnimated = true,
  onMounted,
}: WidgetMultiHeatMapProps) => {
  const theme = useTheme<Theme>();
  const axisFormatter = useTimeSeriesAxisFormatter(interval);

  const options: ApexOptions = useMemo(() => {
    // Width of each color range, not to be confused with the time interval of the series
    const rangeWidth = Math.trunc((maxValue - minValue) / 9);
    const colorRanges = Array(10)
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

    const chartOptions = heatMapOptions(
      theme,
      true,
      axisFormatter,
      undefined,
      undefined,
      isStacked,
      colorRanges,
    ) as ApexOptions;
    if (isAnimated) {
      return chartOptions;
    }
    return { ...chartOptions, chart: { ...chartOptions.chart, animations: { enabled: false } } };
  }, [theme, isStacked, maxValue, minValue, axisFormatter, isAnimated]);

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
