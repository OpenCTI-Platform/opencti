import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import { donutChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';
import useDistributionGraphData from '../../utils/hooks/useDistributionGraphData';

interface WidgetDonutProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  groupBy: string
  withExport?: boolean
  readonly?: boolean
}

const WidgetDonut = ({
  data,
  groupBy,
  withExport = false,
  readonly = false,
}: WidgetDonutProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption } = useDistributionGraphData();

  const chartData = data.map((n) => n.value);
  const labels = buildWidgetLabelsOption(data, groupBy);
  let chartColors = [];
  if (data.at(0)?.entity?.color) {
    chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.color === '#ffffff'
      ? '#000000'
      : n.entity?.color));
  }
  if (data.at(0)?.entity?.x_opencti_color) {
    chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.x_opencti_color === '#ffffff'
      ? '#000000'
      : n.entity?.x_opencti_color));
  }
  if (data.at(0)?.entity?.template?.color) {
    chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.template.color === '#ffffff'
      ? '#000000'
      : n.entity?.template.color));
  }

  return (
    <Chart
      options={donutChartOptions(
        theme,
        labels,
        'bottom',
        false,
        chartColors,
      ) as ApexOptions}
      series={chartData}
      type="donut"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetDonut;
