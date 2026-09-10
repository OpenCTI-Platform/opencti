import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetVerticalBarsProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  isStacked?: boolean;
  hasLegend?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetVerticalBars = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
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
    // the backend, so discrete categories render correctly.
    return verticalBarsChartOptions(
      theme,
      formatter,
      simpleNumberFormat,
      false,
      false,
      isStacked,
      hasLegend,
      'dataPoints',
    ) as ApexOptions;
  }, [theme, interval, formatter, isStacked, hasLegend]);

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
