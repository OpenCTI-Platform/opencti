import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { polarAreaChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';

interface WidgetPolarAreaProps {
  data: {
    label: string,
    value: number,
    color: string
  }[]
  withExport?: boolean
  readonly?: boolean
}

const WidgetPolarArea = ({
  data,
  withExport,
  readonly,
}: WidgetPolarAreaProps) => {
  const theme = useTheme<Theme>();

  const chartData = data.map((n) => n.value);
  const labels = data.map((n) => n.label);

  console.log(data);

  return (
    <Chart
      options={polarAreaChartOptions(theme, labels) as ApexOptions}
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
