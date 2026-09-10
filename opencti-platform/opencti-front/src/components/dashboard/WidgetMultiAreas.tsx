import { useTheme } from '@mui/styles';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { areaChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetMultiAreasProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  isStacked?: boolean;
  hasLegend?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiAreas = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  onMounted,
}: WidgetMultiAreasProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const options: ApexOptions = useMemo(() => {
    return areaChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      isStacked,
      hasLegend,
    ) as ApexOptions;
  }, [theme, interval, formatter, isStacked, hasLegend]);

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
