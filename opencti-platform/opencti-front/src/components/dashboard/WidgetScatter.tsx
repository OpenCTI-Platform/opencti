import React, { useMemo } from 'react';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import { scatterChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';

const WidgetScatter = () => {
  const theme = useTheme<Theme>();

  const { series, ...options }: ApexOptions = useMemo(() => {
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
