import { useTheme } from '@mui/styles';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { lineChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetMultiLinesProps {
  series: ApexAxisChartSeries
  interval?: string | null
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
  const { fsd, mtdy, yd, ywiy } = useFormatter();

  const options: ApexOptions = useMemo(() => {
    let formatter = fsd;
    if (interval === 'month' || interval === 'quarter') {
      formatter = mtdy;
    }
    if (interval === 'year') {
      formatter = yd;
    }
    if (interval === 'week') {
      formatter = ywiy;
    }
    if (interval === 'day') {
      formatter = ywiy;
    }

    return lineChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      false,
      hasLegend,
    ) as ApexOptions;
  }, [interval]);

  return (
    <Chart
      options={options}
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
