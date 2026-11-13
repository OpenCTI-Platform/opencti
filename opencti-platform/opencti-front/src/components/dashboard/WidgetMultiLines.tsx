import { useTheme } from '@mui/material/styles';
import { useMemo } from 'react';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import type { Theme } from '../Theme';
import { lineChartOptions, getSeriesMaxValue, withChartAnimations, withCompactLegend, withIntegerYAxis } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetMultiLinesProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  hasLegend?: boolean;
  isAnimated?: boolean;
  // Off: the chart is drawn with its animations, but its updates are not animated
  isUpdateAnimated?: boolean;
  // The legend in rows of about 20 pixels, for many series in a small chart
  isLegendCompact?: boolean;
  // A chart of counts: its y axis is labelled with integers only
  hasIntegerTicks?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiLines = ({
  series,
  interval,
  hasLegend = false,
  isAnimated = true,
  isUpdateAnimated = true,
  isLegendCompact = false,
  hasIntegerTicks = false,
  onMounted,
}: WidgetMultiLinesProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const maxValue = useMemo(() => (hasIntegerTicks ? getSeriesMaxValue(series) : 0), [hasIntegerTicks, series]);
  const options: ApexOptions = useMemo(() => {
    const chartOptions = lineChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      false,
      hasLegend,
    ) as ApexOptions;
    const countOptions = hasIntegerTicks ? withIntegerYAxis(chartOptions, maxValue) : chartOptions;
    const legendOptions = isLegendCompact ? withCompactLegend(countOptions) : countOptions;
    return withChartAnimations(legendOptions, isAnimated, isUpdateAnimated) as ApexOptions;
  }, [theme, formatter, hasLegend, isAnimated, isUpdateAnimated, isLegendCompact, hasIntegerTicks, maxValue]);

  return (
    <Chart
      options={options}
      series={series}
      type="line"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetMultiLines;
