import React, { useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  IconButton,
  Typography,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { ArrowUp24Regular as ArrowUpIcon } from '@fluentui/react-icons';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

// =====================================================
// 1. High Confidence Active Campaigns (Radar Chart)
// =====================================================

const RADAR_SECTORS = [
  'Energy',
  'Media',
  'Health',
  'Political-Governance',
  'Communications',
  'Academic',
  'Financial',
];

const HighConfidenceCampaignsRadarCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = RADAR_SECTORS.map((s) => t_i18n(s));

  const series = [
    {
      name: t_i18n('Campaigns'),
      data: [20, 8, 5, 12, 6, 4, 15],
    },
  ];

  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'radar',
      background: 'transparent',
      toolbar: { show: false },
      foreColor: theme.palette.text.secondary,
    },
    theme: { mode: theme.palette.mode },
    colors: [theme.palette.primary.main],
    xaxis: {
      categories,
      labels: {
        style: {
          fontSize: '11px',
          fontFamily: '"IBM Plex Sans", sans-serif',
          colors: Array(RADAR_SECTORS.length).fill(theme.palette.text.primary),
        },
      },
    },
    yaxis: {
      show: true,
      tickAmount: 4,
      labels: {
        style: {
          fontSize: '10px',
        },
      },
    },
    stroke: {
      width: 2,
      colors: [theme.palette.primary.main],
    },
    fill: {
      opacity: 0.15,
      colors: [theme.palette.primary.main],
    },
    markers: {
      size: 4,
      colors: [theme.palette.primary.main],
      strokeWidth: 0,
    },
    plotOptions: {
      radar: {
        polygons: {
          strokeColors:
            theme.palette.mode === 'dark'
              ? 'rgba(255, 255, 255, .1)'
              : 'rgba(0, 0, 0, .1)',
          connectorColors:
            theme.palette.mode === 'dark'
              ? 'rgba(255, 255, 255, .1)'
              : 'rgba(0, 0, 0, .1)',
          fill: {
            colors:
              theme.palette.mode === 'dark'
                ? ['transparent', 'rgba(255,255,255,0.02)']
                : ['transparent', 'rgba(0,0,0,0.02)'],
          },
        },
      },
    },
    legend: { show: false },
    tooltip: {
      theme: theme.palette.mode,
      y: { formatter: (val: number) => `${val}` },
    },
    dataLabels: { enabled: false },
  }), [theme, categories]);

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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingInlineEnd: 4 }}
        >
          {t_i18n('High Confidence Active Campaigns')}
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
          {t_i18n('Number of campaigns with confidence >= high')}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 2 }}>
          <Typography
            variant="h3"
            sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2.5rem', lineHeight: 1 }}
          >
            32
          </Typography>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.3,
              backgroundColor: 'success.lighter',
              color: 'success.main',
              padding: '2px 8px',
              borderRadius: 1,
            }}
          >
            <ArrowUpIcon style={{ fontSize: 16 }} />
            <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem' }}>
              5 {t_i18n('last month')}
            </Typography>
          </Box>
        </Box>

        {/* Radar Chart */}
        <Box sx={{ flex: 1, minHeight: 320, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="radar"
            width="100%"
            height={320}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. Performance Indicators (MTTD & MTTR by Sector)
// =====================================================

const PERF_SECTORS = [
  'Technology',
  'Defense',
  'Political-Governance',
  'Energy',
  'Financial',
];

const PerformanceIndicatorsCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = PERF_SECTORS.map((s) => t_i18n(s));

  const series = [
    {
      name: 'MTTD',
      data: [1.5, 2.0, 2.5, 1.8, 1.2],
    },
    {
      name: 'MTTR',
      data: [1.0, 1.5, 2.0, 1.3, 0.8],
    },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = verticalBarsChartOptions(
      theme,
      (v: string) => v,
      (v: number) => `${v}`,
      false,
      false,
      false,
      true,
      undefined,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: ['#3949ab', '#90caf9'],
      plotOptions: {
        bar: {
          columnWidth: '55%',
          borderRadius: 3,
        },
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
        max: 3,
        tickAmount: 3,
        title: {
          text: t_i18n('Days'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
        labels: {
          formatter: (v: number) => `${v}`,
          style: { fontSize: '10px' },
        },
        axisBorder: { show: false },
      },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'center',
        fontSize: '12px',
        markers: { size: 6, shape: 'circle' },
        itemMargin: { horizontal: 12, vertical: 4 },
      },
      tooltip: {
        ...base.tooltip,
        enabled: true,
        y: { formatter: (val: number) => `${val} ${t_i18n('days')}` },
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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingInlineEnd: 4 }}
        >
          {t_i18n('Performance Indicators')}
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
          {t_i18n('MTTD and MTTR indicators by sector')}
        </Typography>

        {/* Summary Values */}
        <Box sx={{ display: 'flex', gap: 4, marginBottom: 2, justifyContent: 'center' }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.75rem' }}>
              MTTD
            </Typography>
            <Typography
              variant="h4"
              sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2rem', lineHeight: 1.2 }}
            >
              1 <Typography component="span" sx={{ fontSize: '1rem', fontWeight: 500, color: 'text.secondary' }}>{t_i18n('day')}</Typography>
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.75rem' }}>
              MTTR
            </Typography>
            <Typography
              variant="h4"
              sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2rem', lineHeight: 1.2 }}
            >
              1.5 <Typography component="span" sx={{ fontSize: '1rem', fontWeight: 500, color: 'text.secondary' }}>{t_i18n('days')}</Typography>
            </Typography>
          </Box>
        </Box>

        {/* Bar Chart */}
        <Box sx={{ flex: 1, minHeight: 300, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="bar"
            width="100%"
            height={300}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const CampaignsAndPerformanceSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr' }}>
      <Grid item xs={12} md={6}>
        <HighConfidenceCampaignsRadarCard />
      </Grid>
      <Grid item xs={12} md={6}>
        <PerformanceIndicatorsCard />
      </Grid>
    </Grid>
  );
};

export default CampaignsAndPerformanceSection;
