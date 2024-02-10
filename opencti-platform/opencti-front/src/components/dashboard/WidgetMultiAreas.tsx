import { useTheme } from '@mui/styles';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React from 'react';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { areaChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetMultiAreasProps {
  series: ApexAxisChartSeries
  interval?: string
  isStacked?: boolean
  hasLegend?: boolean
  withExport?: boolean
  readonly?: boolean
}

const WidgetMultiAreas = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  withExport = false,
  readonly = false,
}: WidgetMultiAreasProps) => {
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
      options={areaChartOptions(
        theme,
        !interval || ['day', 'week'].includes(interval),
        formatter,
        simpleNumberFormat,
        interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
        isStacked,
        hasLegend,
      ) as ApexOptions}
      series={series}
      type="area"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetMultiAreas;
