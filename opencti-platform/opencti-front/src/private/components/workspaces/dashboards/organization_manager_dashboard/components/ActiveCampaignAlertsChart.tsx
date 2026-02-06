import React, { useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

const SECTORS = [
  'Universities',
  'Energy',
  'Banks',
  'Ministry of Defense',
  'Broadcasting',
  'Ministry of Health',
  'Ministry of Intelligence',
];

const SERIES_COLORS = ['#42a5f5', '#ffb74d', '#ff8a65', '#d32f2f']; // Low, Medium, High, Critical

const ActiveCampaignAlertsChart: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = SECTORS.map((s) => t_i18n(s));
  const series = [
    { name: t_i18n('Low'), data: [12, 19, 8, 15, 22, 11, 18] },
    { name: t_i18n('Medium'), data: [45, 59, 42, 38, 51, 48, 44] },
    { name: t_i18n('High'), data: [28, 15, 35, 30, 18, 25, 22] },
    { name: t_i18n('Critical'), data: [15, 7, 15, 17, 9, 16, 16] },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = verticalBarsChartOptions(
      theme,
      (v: string) => v,
      (v: number) => v.toString(),
      false,
      false,
      false,
      true,
      undefined,
    ) as ApexOptions;
    return {
      ...base,
      chart: { ...base.chart, stacked: false },
      xaxis: { ...base.xaxis, categories },
      colors: SERIES_COLORS,
      legend: {
        ...base.legend,
        show: true,
        position: 'top',
        horizontalAlign: 'left',
      },
    };
  }, [theme, categories]);

  return (
    <Card
      variant="outlined"
      sx={{
        height: '100%',
        backgroundColor: 'background.paper',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 3, position: 'relative' }}>
        <IconButton
          size="small"
          sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreVert fontSize="small" />
        </IconButton>
        <Typography variant="h6" sx={{ fontWeight: 600, marginBottom: 1, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}>
          {t_i18n('Number of Active Campaign Alerts')}
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', marginBottom: 2, fontSize: '0.875rem', lineHeight: 1.5 }}>
          {t_i18n('Real-time notifications for active hacktivist activities or intelligence operations in different sectors')}
        </Typography>
        <Box sx={{ height: 320, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="bar"
            width="100%"
            height={320}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

export default ActiveCampaignAlertsChart;
