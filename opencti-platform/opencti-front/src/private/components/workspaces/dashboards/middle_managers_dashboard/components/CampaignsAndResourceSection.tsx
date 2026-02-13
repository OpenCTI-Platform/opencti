import React, { useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  Grid,
  IconButton,
  Typography,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { lineChartOptions, verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

// =====================================================
// 1. Current Campaigns (Multi-Line with markers)
// =====================================================

const MONTHS = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

const CAMPAIGNS = [
  { name: 'Pay2Key', color: '#4caf50', category: 'Operational' },
  { name: 'Anonymous', color: '#9c27b0', category: 'Political' },
  { name: 'APT34 (OilRig)', color: '#b71c1c', category: 'Intelligence' },
  { name: 'Gonjeshk Darandeh', color: '#ff9800', category: 'Political' },
  { name: 'Tapandegan', color: '#f44336', category: 'High' },
  { name: 'Qiyam', color: '#fdd835', category: 'Financial' },
];

const CurrentCampaignsCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  const series = [
    { name: 'Pay2Key', data: [2, 3, 5, 4, 3, 2, 1, 2, 1, 1, 0, 1] },
    { name: 'Anonymous', data: [1, 2, 1, 3, 2, 4, 3, 2, 3, 2, 1, 2] },
    { name: 'APT34 (OilRig)', data: [3, 2, 4, 3, 5, 4, 3, 5, 4, 3, 4, 5] },
    { name: 'Gonjeshk Darandeh', data: [1, 1, 2, 4, 5, 7, 5, 3, 4, 2, 3, 6] },
    { name: 'Tapandegan', data: [4, 5, 3, 6, 7, 5, 4, 3, 2, 1, 2, 3] },
    { name: 'Qiyam', data: [0, 1, 1, 2, 1, 3, 2, 4, 3, 5, 4, 6] },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = lineChartOptions(
      theme,
      false,
      null,
      (v: number) => `${v}`,
      undefined,
      false,
      true,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: CAMPAIGNS.map((c) => c.color),
      grid: {
        ...base.grid,
        borderColor:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .06)'
            : 'rgba(0, 0, 0, .06)',
        strokeDashArray: 4,
        padding: { left: 0, right: 0, top: -10, bottom: 0 },
      },
      xaxis: {
        ...base.xaxis,
        categories,
        labels: {
          ...base.xaxis?.labels,
          style: {
            fontSize: '10px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
      },
      yaxis: {
        ...base.yaxis,
        min: 0,
        max: 8,
        tickAmount: 4,
        labels: {
          style: { fontSize: '10px' },
        },
        axisBorder: { show: false },
      },
      stroke: { curve: 'straight', width: 2 },
      markers: {
        size: 5,
        strokeWidth: 0,
        hover: { sizeOffset: 2 },
      },
      legend: { show: false },
      tooltip: {
        ...base.tooltip,
        enabled: true,
        shared: false,
        intersect: true,
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
      <CardContent
        sx={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          padding: 3,
          position: 'relative',
          '&:last-child': { paddingBottom: 2 },
        }}
      >
        <IconButton
          size="small"
          sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreVert fontSize="small" />
        </IconButton>

        <Typography
          variant="h6"
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}
        >
          {t_i18n('Current Campaigns')}
        </Typography>

        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            fontSize: '0.8rem',
            lineHeight: 1.5,
            marginTop: 0.5,
            marginBottom: 1.5,
          }}
        >
          {t_i18n('Shows APT activities and ransomware spread across ministries using a line chart')}
        </Typography>

        {/* Custom Legend with category chips */}
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 1,
            marginBottom: 2,
          }}
        >
          {CAMPAIGNS.map((campaign) => (
            <Box key={campaign.name} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box
                sx={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  backgroundColor: campaign.color,
                }}
              />
              <Typography variant="caption" sx={{ fontSize: '0.7rem', color: 'text.primary', fontWeight: 500 }}>
                {campaign.name}
              </Typography>
              <Chip
                label={t_i18n(campaign.category)}
                size="small"
                sx={{
                  height: 16,
                  fontSize: '0.55rem',
                  fontWeight: 600,
                  backgroundColor: `${campaign.color}18`,
                  color: campaign.color,
                  borderRadius: 0.5,
                }}
              />
            </Box>
          ))}
        </Box>

        {/* Line Chart */}
        <Box sx={{ flex: 1, minHeight: 300, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="line"
            width="100%"
            height={300}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. Resource Allocation Chart (Dual Bar Charts)
// =====================================================

const YEARS = [
  '2013', '2014', '2015', '2016', '2017', '2018',
  '2019', '2020', '2021', '2022', '2023', '2024', '2025',
];

const ResourceAllocationCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  // Top chart: Budget
  const budgetSeries = [
    {
      name: t_i18n('Budget'),
      data: [0.5, 0.6, 0.8, 0.7, 1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.2],
    },
  ];

  const budgetOptions: ApexOptions = useMemo(() => {
    const base = verticalBarsChartOptions(
      theme,
      (v: string) => v,
      (v: number) => `${v}M`,
      false,
      false,
      false,
      false,
      undefined,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: ['#7e57c2'],
      plotOptions: {
        bar: { columnWidth: '50%', borderRadius: 2 },
      },
      grid: {
        ...base.grid,
        borderColor:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .06)'
            : 'rgba(0, 0, 0, .06)',
        strokeDashArray: 4,
        padding: { left: 0, right: 0, top: -10, bottom: 0 },
      },
      xaxis: {
        ...base.xaxis,
        categories: YEARS,
        labels: {
          style: {
            fontSize: '8px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
        title: {
          text: t_i18n('Year'),
          style: { fontSize: '9px', color: theme.palette.text.secondary },
        },
      },
      yaxis: {
        ...base.yaxis,
        title: {
          text: t_i18n('Budget (million)'),
          style: { fontSize: '9px', color: theme.palette.text.secondary },
        },
        labels: { style: { fontSize: '9px' } },
        axisBorder: { show: false },
      },
      legend: { show: false },
      tooltip: { ...base.tooltip, enabled: true },
    };
  }, [theme]);

  // Bottom chart: Counts
  const countSeries = [
    {
      name: t_i18n('Incidents'),
      data: [8, 10, 12, 15, 20, 25, 30, 35, 40, 45, 48, 50, 52],
    },
    {
      name: t_i18n('Campaigns'),
      data: [5, 7, 8, 10, 12, 15, 18, 22, 28, 35, 42, 48, 50],
    },
    {
      name: t_i18n('Hacktivist Groups'),
      data: [2, 3, 4, 5, 8, 10, 12, 15, 18, 22, 30, 35, 40],
    },
  ];

  const countOptions: ApexOptions = useMemo(() => {
    const base = verticalBarsChartOptions(
      theme,
      (v: string) => v,
      (v: number) => `${v}`,
      false,
      false,
      false,
      false,
      undefined,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: ['#3949ab', '#5c6bc0', '#9fa8da'],
      plotOptions: {
        bar: { columnWidth: '60%', borderRadius: 2 },
      },
      grid: {
        ...base.grid,
        borderColor:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .06)'
            : 'rgba(0, 0, 0, .06)',
        strokeDashArray: 4,
        padding: { left: 0, right: 0, top: -10, bottom: 0 },
      },
      xaxis: {
        ...base.xaxis,
        categories: YEARS,
        labels: {
          style: {
            fontSize: '8px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
        title: {
          text: t_i18n('Year'),
          style: { fontSize: '9px', color: theme.palette.text.secondary },
        },
      },
      yaxis: {
        ...base.yaxis,
        title: {
          text: t_i18n('Attacks, Campaigns & Groups'),
          style: { fontSize: '9px', color: theme.palette.text.secondary },
        },
        labels: { style: { fontSize: '9px' } },
        axisBorder: { show: false },
      },
      legend: { show: false },
      tooltip: { ...base.tooltip, enabled: true },
    };
  }, [theme]);

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
      <CardContent
        sx={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          padding: 3,
          position: 'relative',
          '&:last-child': { paddingBottom: 2 },
        }}
      >
        <IconButton
          size="small"
          sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreVert fontSize="small" />
        </IconButton>

        <Typography
          variant="h6"
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}
        >
          {t_i18n('Resource Allocation Chart')}
        </Typography>

        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            fontSize: '0.8rem',
            lineHeight: 1.5,
            marginTop: 0.5,
            marginBottom: 1,
          }}
        >
          {t_i18n('Ratio of reduced threats to budget or allocated staff time')}
        </Typography>

        {/* Legend */}
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 1.5,
            marginBottom: 1,
            justifyContent: 'center',
          }}
        >
          {[
            { label: 'Hacktivist Groups', color: '#9fa8da' },
            { label: 'Budget', color: '#7e57c2' },
            { label: 'Campaigns', color: '#5c6bc0' },
            { label: 'Incidents', color: '#3949ab' },
          ].map((item) => (
            <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  backgroundColor: item.color,
                }}
              />
              <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>
                {t_i18n(item.label)}
              </Typography>
            </Box>
          ))}
        </Box>

        {/* Budget Chart (top) */}
        <Box sx={{ width: '100%', minHeight: 160 }}>
          <Chart
            options={budgetOptions}
            series={budgetSeries}
            type="bar"
            width="100%"
            height={160}
          />
        </Box>

        {/* Counts Chart (bottom) */}
        <Box sx={{ width: '100%', minHeight: 160 }}>
          <Chart
            options={countOptions}
            series={countSeries}
            type="bar"
            width="100%"
            height={160}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const CampaignsAndResourceSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12} md={6}>
        <CurrentCampaignsCard />
      </Grid>
      <Grid item xs={12} md={6}>
        <ResourceAllocationCard />
      </Grid>
    </Grid>
  );
};

export default CampaignsAndResourceSection;
