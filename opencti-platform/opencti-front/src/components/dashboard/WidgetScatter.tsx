import React, { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import { scatterChartOptions, ScatterChartOptionsArgs } from '../../utils/apexCharts/scatterOptions';
import type { Theme } from '../Theme';

interface WidgetScatterProps {
  series: ApexAxisChartSeries
  options?: Omit<ScatterChartOptionsArgs, 'theme'>
}

const WidgetScatter = ({
  series,
  options,
}: WidgetScatterProps) => {
  const theme = useTheme<Theme>();

  const apexOptions = useMemo(() => {
    return scatterChartOptions({
      ...options,
      theme,
    });
  }, []);

  return (
    <Chart
      options={apexOptions}
      series={series}
      type="scatter"
      width="100%"
      height="100%"
    />
  );
};

export default WidgetScatter;
