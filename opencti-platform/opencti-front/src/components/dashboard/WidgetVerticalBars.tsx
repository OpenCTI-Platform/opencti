import Chart from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';

interface WidgetVerticalBarsProps {
  series: ApexAxisChartSeries
  interval?: string | null
  isStacked?: boolean
  hasLegend?: boolean
  withExport?: boolean
  readonly?: boolean
}

const WidgetVerticalBars = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  withExport = false,
  readonly = false,
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

    return verticalBarsChartOptions(
      theme,
      formatter,
      simpleNumberFormat,
      false,
      !interval || ['day', 'week'].includes(interval),
      isStacked,
      hasLegend,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
    ) as ApexOptions;
  }, [interval, isStacked, hasLegend]);

  return (
    <Chart
      options={options}
      series={series}
      type="bar"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetVerticalBars;
