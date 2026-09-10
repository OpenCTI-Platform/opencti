import { useTheme } from '@mui/styles';
import { useMemo } from 'react';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import type { Theme } from '../Theme';
import { lineChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import useTimeSeriesAxisFormatter from '../../utils/hooks/useTimeSeriesAxisFormatter';

interface WidgetMultiLinesProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  hasLegend?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiLines = ({
  series,
  interval,
  hasLegend = false,
  onMounted,
}: WidgetMultiLinesProps) => {
  const theme = useTheme<Theme>();
  const formatter = useTimeSeriesAxisFormatter(interval);

  const options: ApexOptions = useMemo(() => {
    return lineChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      false,
      hasLegend,
    ) as ApexOptions;
  }, [theme, interval, formatter, hasLegend]);

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
