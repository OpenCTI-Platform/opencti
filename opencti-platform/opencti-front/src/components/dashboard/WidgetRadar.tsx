import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { radarChartOptions } from '../../utils/Charts';
import { defaultValue } from '../../utils/Graph';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';

interface WidgetRadarProps {
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

  const chartData = [{
    name: label || t_i18n('Number of relationships'),
    data: data.map((n) => n.value),
  }];

  // eslint-disable-next-line no-nested-ternary,implicit-arrow-linebreak
  const labels = data.map((n) => (groupBy.endsWith('_id')
    ? defaultValue(n.entity)
    : groupBy === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`
      ? t_i18n(`entity_${n.label}`)
      : n.label));

  return (
    <Chart
      options={radarChartOptions(theme, labels, [], true, false) as ApexOptions}
      series={chartData}
      type="radar"
      width="100%"
      height="120%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetRadar;
