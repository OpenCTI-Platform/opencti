import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { useFormatter } from '../i18n';
import { treeMapOptions } from '../../utils/Charts';
import { defaultValue } from '../../utils/Graph';

interface WidgetTreeProps {
  data: any[]
  groupBy: string
  withExport?: boolean
  readonly?: boolean
  isDistributed?: boolean
}

const WidgetTree = ({
  data,
  groupBy,
  withExport = false,
  readonly = false,
  isDistributed = false,
}: WidgetTreeProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();

  const chartData = data.map((n) => ({
    // eslint-disable-next-line no-nested-ternary
    x: groupBy.endsWith('_id')
      ? defaultValue(n.entity)
      : groupBy === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`
        ? t_i18n(`entity_${n.label}`)
        : n.label,
    y: n.value,
  }));
  const series = [{ data: chartData }];

  return (
    <Chart
      options={treeMapOptions(
        theme,
        'bottom',
        isDistributed,
      ) as ApexOptions}
      series={series}
      type="treemap"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetTree;
