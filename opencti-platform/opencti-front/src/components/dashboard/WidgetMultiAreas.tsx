import { useTheme } from '@mui/styles';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { areaChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetMultiAreasProps {
  series: ApexAxisChartSeries
  interval?: string | null
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

  const options: ApexOptions = useMemo(() => {
    let formatter = fsd;
    if (interval === 'month' || interval === 'quarter') {
      formatter = mtdy;
    }
    if (interval === 'year') {
      formatter = yd;
    }

    return areaChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      isStacked,
      hasLegend,
    ) as ApexOptions;
  }, []);

  return (
    <Chart
      options={options}
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
