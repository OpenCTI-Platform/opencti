import { useTheme } from '@mui/material/styles';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { areaChartOptions, getSeriesMaxValue, withChartAnimations, withCompactLegend, withIntegerYAxis } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetMultiAreasProps {
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
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiAreas = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  isAnimated = true,
  isUpdateAnimated = true,
  isLegendCompact = false,
  hasIntegerTicks = false,
  onMounted,
}: WidgetMultiAreasProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const maxValue = useMemo(() => (hasIntegerTicks ? getSeriesMaxValue(series, isStacked) : 0), [hasIntegerTicks, series, isStacked]);
  const options: ApexOptions = useMemo(() => {
    const chartOptions = areaChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      isStacked,
      hasLegend,
    ) as ApexOptions;
    const countOptions = hasIntegerTicks ? withIntegerYAxis(chartOptions, maxValue) : chartOptions;
    const legendOptions = isLegendCompact ? withCompactLegend(countOptions) : countOptions;
    return withChartAnimations(legendOptions, isAnimated, isUpdateAnimated) as ApexOptions;
  }, [theme, formatter, isStacked, hasLegend, isAnimated, isUpdateAnimated, isLegendCompact, hasIntegerTicks, maxValue]);

  return (
    <Chart
      options={options}
      series={series}
      type="area"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetMultiAreas;
