import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { radarChartOptions } from '../../utils/Charts';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import useDistributionGraphData from '../../utils/hooks/useDistributionGraphData';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetRadarProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  label: string
  groupBy: string
  withExport?: boolean
  readonly?: boolean
}

const WidgetRadar = ({
  data,
  label,
  groupBy,
  withExport = false,
  readonly = false,
}: WidgetRadarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { buildWidgetLabelsOption } = useDistributionGraphData();

  const chartData = [{
    name: label || t_i18n('Number of relationships'),
    data: data.map((n) => n.value),
  }];

  const labels = buildWidgetLabelsOption(data, groupBy);
  return (
    <Chart
      options={radarChartOptions(theme, labels, simpleNumberFormat, [], true, false) as ApexOptions}
      series={chartData}
      type="radar"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetRadar;
