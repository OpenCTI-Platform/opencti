import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions, getSeriesMaxValue, withChartAnimations, withCompactLegend, withIntegerYAxis } from '../../utils/Charts';
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
  // The legend in rows of about 20 pixels, for many series in a small chart
  isLegendCompact?: boolean;
  // A chart of counts: its y axis is labelled with integers only
  hasIntegerTicks?: boolean;
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
  isLegendCompact = false,
  hasIntegerTicks = false,
  hasHoverFilter = true,
  tickAmount,
  onMounted,
}: WidgetVerticalBarsProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const maxValue = useMemo(() => (hasIntegerTicks ? getSeriesMaxValue(series, isStacked) : 0), [hasIntegerTicks, series, isStacked]);
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
    const countOptions = hasIntegerTicks ? withIntegerYAxis(chartOptions, maxValue) : chartOptions;
    const legendOptions = isLegendCompact ? withCompactLegend(countOptions) : countOptions;
    return withChartAnimations(legendOptions, isAnimated, isUpdateAnimated) as ApexOptions;
  }, [theme, formatter, isStacked, hasLegend, isAnimated, hasHoverFilter, tickAmount, isUpdateAnimated, isLegendCompact, hasIntegerTicks, maxValue]);

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
