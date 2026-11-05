import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions, withChartAnimations } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetVerticalBarsProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  isStacked?: boolean;
  hasLegend?: boolean;
  isAnimated?: boolean;
  // Off: the chart is drawn with its animations, but its updates are not animated
  isUpdateAnimated?: boolean;
  hasHoverFilter?: boolean;
  tickAmount?: number;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetVerticalBars = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  isAnimated = true,
  isUpdateAnimated = true,
  hasHoverFilter = true,
  tickAmount,
  onMounted,
}: WidgetVerticalBarsProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const options: ApexOptions = useMemo(() => {
    // All intervals are rendered on a 'category' x-axis (isTimeSeries = false) with
    // tickAmount = 'dataPoints'. A 'datetime' axis (previously used for day/week) aligns its
    // ticks to calendar boundaries and does not guarantee a tick on the last data point, which
    // dropped the label of the most recent bar. A category axis labels every bar, including the
    // most recent one, and the time-series buckets are already gap-filled and evenly spaced by
    // the backend, so discrete categories render correctly. A numeric tickAmount trades that
    // guarantee for fewer labels: the last bar may not be labelled.
    const chartOptions = verticalBarsChartOptions(
      theme,
      formatter,
      simpleNumberFormat,
      false,
      false,
      isStacked,
      hasLegend,
      tickAmount ?? 'dataPoints',
      hasHoverFilter,
    ) as ApexOptions;
    return withChartAnimations(chartOptions, isAnimated, isUpdateAnimated) as ApexOptions;
  }, [theme, formatter, isStacked, hasLegend, isAnimated, hasHoverFilter, tickAmount, isUpdateAnimated]);

  return (
    <Chart
      options={options}
      series={series}
      type="bar"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetVerticalBars;
