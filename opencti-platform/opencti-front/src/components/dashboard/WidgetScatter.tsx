import React, { useMemo } from 'react';
import { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import { scatterChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';

interface WidgetScatterProps {
  series: ApexAxisChartSeries
}

const WidgetScatter = ({ series }: WidgetScatterProps) => {
  const theme = useTheme<Theme>();

  const options: ApexOptions = useMemo(() => {
    return scatterChartOptions(theme) as unknown as ApexOptions;
  }, []);

  return (
    <Chart
      options={options}
      series={series}
      type="scatter"
      width="100%"
      height="100%"
    />
  );
};

export default WidgetScatter;
