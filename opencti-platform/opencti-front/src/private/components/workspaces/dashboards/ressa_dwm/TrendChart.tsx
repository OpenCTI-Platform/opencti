import React, { useMemo } from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import Chart from '@components/common/charts/Chart';
import { lineChartOptions } from '../../../../../utils/Charts';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';

interface TrendChartProps {
  series: { name: string; data: number[]; color: string }[];
}

const TrendChart: React.FC<TrendChartProps> = ({ series }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const months = [
    t_i18n('Jan'),
    t_i18n('Feb'),
    t_i18n('Mar'),
    t_i18n('Apr'),
    t_i18n('May'),
    t_i18n('Jun'),
    t_i18n('Jul'),
    t_i18n('Aug'),
    t_i18n('Sep'),
    t_i18n('Oct'),
    t_i18n('Nov'),
    t_i18n('Dec'),
  ];

  const chartSeries = series.map((s) => ({
    name: s.name,
    data: s.data,
  }));

  const options: ApexOptions = useMemo(() => {
    const baseOptions = lineChartOptions(
      theme,
      false,
      undefined,
      (value: number) => value.toString(),
      undefined,
      false,
      true,
    ) as ApexOptions;

    return {
      ...baseOptions,
      colors: series.map((s) => s.color),
      xaxis: {
        ...baseOptions.xaxis,
        categories: months,
      },
      yaxis: {
        ...baseOptions.yaxis,
        min: 0,
        max: 1000,
        tickAmount: 5,
      },
      legend: {
        ...baseOptions.legend,
        position: 'top',
        horizontalAlign: 'left',
      },
      chart: {
        ...baseOptions.chart,
        toolbar: {
          show: false,
        },
      },
    };
  }, [theme, series, months]);

  return (
    <Box sx={{ height: 300 }}>
      <Chart
        options={options}
        series={chartSeries}
        type="line"
        width="100%"
        height="100%"
      />
    </Box>
  );
};

export default TrendChart;

