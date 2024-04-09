import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { polarAreaChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';
import useDistributionGraphData, { DistributionQueryData } from '../../utils/hooks/useDistributionGraphData';

interface WidgetPolarAreaProps {
  data: DistributionQueryData
  groupBy: string
  withExport?: boolean
  readonly?: boolean
}

const WidgetPolarArea = ({
  data,
  groupBy,
  withExport,
  readonly,
}: WidgetPolarAreaProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption, buildWidgetColorsOptions } = useDistributionGraphData();

  const chartData = data.flatMap((n) => (n ? (n.value ?? 0) : []));
  const labels = buildWidgetLabelsOption(data, groupBy);
  const colors = buildWidgetColorsOptions(data, groupBy);

  return (
    <Chart
      options={polarAreaChartOptions(
        theme,
        labels,
        undefined,
        'bottom',
        colors,
      ) as ApexOptions}
      series={chartData}
      type="polarArea"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetPolarArea;
