import { useTheme } from '@mui/styles';
import { useMemo } from 'react';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { lineChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetMultiLinesProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  hasLegend?: boolean;
  strokeWidth?: number;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const WidgetMultiLines = ({
  series,
  interval,
  hasLegend = false,
  strokeWidth,
  onMounted,
}: WidgetMultiLinesProps) => {
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

    const baseOptions = lineChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      false,
      hasLegend,
    ) as ApexOptions;

    if (strokeWidth === undefined) {
      return baseOptions;
    }

    return {
      ...baseOptions,
      stroke: {
        ...baseOptions.stroke,
        width: strokeWidth,
      },
    };
  }, [interval, hasLegend, strokeWidth, theme, fsd, mtdy, yd]);

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
