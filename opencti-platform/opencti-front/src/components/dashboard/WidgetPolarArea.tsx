import Chart from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
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

  const chartData = useMemo(() => data.flatMap((n) => (n ? (n.value ?? 0) : [])), [data]);

  const options: ApexOptions = useMemo(() => {
    const labels = buildWidgetLabelsOption(data, groupBy);
    const colors = buildWidgetColorsOptions(data, groupBy);

    return polarAreaChartOptions(
      theme,
      labels,
      undefined,
      'bottom',
      colors,
    ) as ApexOptions;
  }, [data, groupBy]);

  return (
    <Chart
      options={options}
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
