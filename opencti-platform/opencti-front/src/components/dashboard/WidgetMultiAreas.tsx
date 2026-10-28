import { useTheme } from '@mui/styles';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { areaChartOptions, withChartAnimations } from '../../utils/Charts';
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
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiAreas = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  isAnimated = true,
  isUpdateAnimated = true,
  onMounted,
}: WidgetMultiAreasProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

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
    return withChartAnimations(chartOptions, isAnimated, isUpdateAnimated) as ApexOptions;
  }, [theme, formatter, isStacked, hasLegend, isAnimated, isUpdateAnimated]);

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
