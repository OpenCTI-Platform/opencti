import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { useFormatter } from '../i18n';
import { treeMapOptions } from '../../utils/Charts';
import { getMainRepresentative, isFieldForIdentifier } from '../../utils/defaultRepresentatives';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetTreeProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

  const chartData = data.map((n) => {
    const item = { x: n.label, y: n.value };
    if (isFieldForIdentifier(groupBy)) {
      item.x = getMainRepresentative(n.entity);
    } else if (groupBy === 'entity_type' && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`) {
      item.x = t_i18n(`entity_${n.label}`);
    }
    return item;
  });

  const series = [{ data: chartData }];

  return (
    <Chart
      options={treeMapOptions(
        theme,
        simpleNumberFormat,
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
