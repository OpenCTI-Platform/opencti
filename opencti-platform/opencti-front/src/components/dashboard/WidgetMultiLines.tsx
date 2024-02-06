import { useTheme } from '@mui/styles';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React from 'react';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { lineChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetMultiLinesProps {
  series: ApexAxisChartSeries
  interval: string
  hasLegend?: boolean
  withExport?: boolean
  readonly?: boolean
}

const WidgetMultiLines = ({
  series,
  interval,
  hasLegend = false,
  withExport = false,
  readonly = false,
}: WidgetMultiLinesProps) => {
  const theme = useTheme<Theme>();
  const { fsd, mtdy, yd } = useFormatter();

  let formatter = fsd;
  if (interval === 'month' || interval === 'quarter') {
    formatter = mtdy;
  }
  if (interval === 'year') {
    formatter = yd;
  }

  return (
    <Chart
      options={lineChartOptions(
        theme,
        !interval || ['day', 'week'].includes(interval),
        formatter,
        simpleNumberFormat,
        interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
        false,
        hasLegend,
      ) as ApexOptions}
      series={series}
      type="line"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetMultiLines;
