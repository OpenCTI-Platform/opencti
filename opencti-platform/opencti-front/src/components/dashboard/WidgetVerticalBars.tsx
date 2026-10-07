import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';

interface WidgetVerticalBarsProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  isStacked?: boolean;
  hasLegend?: boolean;
  isAnimated?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetVerticalBars = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  isAnimated = true,
  onMounted,
}: WidgetVerticalBarsProps) => {
  const theme = useTheme<Theme>();
  const { fsd, mtdy, yd } = useFormatter();

  const options: ApexOptions = useMemo(() => {
    let formatter = fsd;
    if (interval === 'month' || interval === 'quarter') {
      formatter = mtdy;
    }
    if (interval === 'year') {
      formatter = yd;
    }

    // All intervals are rendered on a 'category' x-axis (isTimeSeries = false) with
    // tickAmount = 'dataPoints'. A 'datetime' axis (previously used for day/week) aligns its
    // ticks to calendar boundaries and does not guarantee a tick on the last data point, which
    // dropped the label of the most recent bar. A category axis labels every bar, including the
    // most recent one, and the time-series buckets are already gap-filled and evenly spaced by
    // the backend, so discrete categories render correctly.
    const chartOptions = verticalBarsChartOptions(
      theme,
      formatter,
      simpleNumberFormat,
      false,
      false,
      isStacked,
      hasLegend,
      'dataPoints',
    ) as ApexOptions;
    if (isAnimated) {
      return chartOptions;
    }
    return { ...chartOptions, chart: { ...chartOptions.chart, animations: { enabled: false } } };
  }, [theme, interval, isStacked, hasLegend, isAnimated]);

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
