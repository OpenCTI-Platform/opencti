import Chart from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
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

  const chartData = useMemo(() => [{
    name: label || t_i18n('Number of relationships'),
    data: data.map((n) => n.value),
  }], [data, label]);

  const options: ApexOptions = useMemo(() => {
    const labels = buildWidgetLabelsOption(data, groupBy);
    return radarChartOptions(
      theme,
      labels,
      simpleNumberFormat,
      [],
      true,
    ) as ApexOptions;
  }, [data, groupBy]);

  return (
    <Chart
      options={options}
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
