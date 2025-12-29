import React, { useMemo } from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import Chart from '@components/common/charts/Chart';
import { donutChartOptions } from '../../../../../utils/Charts';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';

interface DonutChartProps {
  data: { label: string; value: number; color: string }[];
  total: number;
}

const DonutChart: React.FC<DonutChartProps> = ({ data, total }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const chartData = useMemo(() => data.map((item) => item.value), [data]);
  const labels = useMemo(() => data.map((item) => item.label), [data]);
  const colors = useMemo(() => data.map((item) => item.color), [data]);

  const options: ApexOptions = useMemo(() => {
    const baseOptions = donutChartOptions(
      theme,
      labels,
      'right',
      false,
      colors,
      true, // displayLegend: true - legend چارت را فعال می‌کنیم
      false, // displayLabels: false - درصد‌ها را از روی نمودار برمی‌داریم
      true,
      true,
      70,
      false,
    ) as ApexOptions;

    // محاسبه درصد برای هر آیتم
    const percentages = chartData.map((value) => ((value / total) * 100).toFixed(1));

    return {
      ...baseOptions,
      labels: labels, // اضافه کردن labels برای نمایش در legend
      chart: {
        ...baseOptions.chart,
        events: {
          ...baseOptions.chart?.events,
          mounted: (chartContext: any) => {
            // اطمینان از نمایش همیشگی labels
            if (chartContext && chartContext.w) {
              const apexChart = chartContext.w.globals;
              if (apexChart) {
                // Force update برای نمایش labels
                setTimeout(() => {
                  chartContext.updateSeries(chartData, true);
                }, 100);
              }
            }
          },
        },
      },
      legend: {
        ...baseOptions.legend,
        position: 'right',
        horizontalAlign: 'center',
        floating: false,
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontColor: theme.palette.text?.primary,
        labels: {
          colors: theme.palette.text?.primary,
        },
        itemMargin: {
          horizontal: 10,
          vertical: 5,
        },
        formatter: (seriesName: string, opts: { seriesIndex: number }) => {
          const percentage = percentages[opts.seriesIndex];
          return `${seriesName} ${percentage}%`;
        },
      },
      dataLabels: {
        ...baseOptions.dataLabels,
        enabled: false, // درصد‌ها را از روی نمودار برمی‌داریم
      },
      tooltip: {
        ...baseOptions.tooltip,
        enabled: true,
      },
      plotOptions: {
        ...baseOptions.plotOptions,
        pie: {
          ...baseOptions.plotOptions?.pie,
          donut: {
            ...baseOptions.plotOptions?.pie?.donut,
            labels: {
              show: true,
              name: {
                show: true,
                fontSize: '14px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 400,
                color: theme.palette.text?.secondary || '#757575',
                offsetY: -10,
                formatter: () => t_i18n('Total'),
              },
              value: {
                show: true,
                fontSize: '24px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 600,
                color: theme.palette.text?.primary || '#212121',
                offsetY: 10,
                formatter: () => total.toLocaleString(),
              },
              total: {
                show: true,
                showAlways: true,
                label: t_i18n('Total'),
                fontSize: '14px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 400,
                color: theme.palette.text?.secondary || '#757575',
                formatter: () => total.toLocaleString(),
              },
            },
          },
        },
      },
    };
  }, [theme, labels, colors, total, chartData, t_i18n]);

  return (
    <Box sx={{ height: 300 }}>
      <Chart
        options={options}
        series={chartData}
        type="donut"
        width="100%"
        height="100%"
      />
    </Box>
  );
};

export default DonutChart;

