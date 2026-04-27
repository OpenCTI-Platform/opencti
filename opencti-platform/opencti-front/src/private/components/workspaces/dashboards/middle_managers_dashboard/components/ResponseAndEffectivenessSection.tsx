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
import { lineChartOptions, verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

// =====================================================
// 1. Incident Response Time Index (Multi-Line Chart)
// =====================================================

const MONTHS = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

const TIME_METRICS = [
  { name: 'Detection Time', color: '#1a237e' },
  { name: 'Notification Time', color: '#5c6bc0' },
  { name: 'Containment Time', color: '#b0bec5' },
];

const IncidentResponseTimeCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  const series = [
    {
      name: t_i18n('Detection Time'),
      data: [4, 5, 3, 6, 5, 4, 7, 6, 8, 5, 9, 10],
    },
    {
      name: t_i18n('Notification Time'),
      data: [3, 4, 2, 5, 4, 3, 5, 5, 6, 4, 7, 8],
    },
    {
      name: t_i18n('Containment Time'),
      data: [2, 3, 2, 3, 3, 2, 4, 3, 4, 3, 5, 6],
    },
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
      colors: TIME_METRICS.map((m) => m.color),
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
        max: 15,
        tickAmount: 5,
        title: {
          text: t_i18n('Days'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
        labels: {
          style: { fontSize: '10px' },
        },
        axisBorder: { show: false },
      },
      stroke: { curve: 'smooth', width: 2 },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'center',
        fontSize: '11px',
        markers: { size: 6, shape: 'circle' },
        itemMargin: { horizontal: 10, vertical: 4 },
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
          {t_i18n('Incident Response Time Index')}
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
          {t_i18n('Average time for detection and notification by CTI team or response to reduce incident impact by response teams')}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 2 }}>
          <Typography
            variant="h3"
            sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2.5rem', lineHeight: 1 }}
          >
            3
          </Typography>
          <Typography
            variant="body1"
            sx={{ fontWeight: 500, color: 'text.secondary', alignSelf: 'flex-end', marginBottom: 0.5 }}
          >
            {t_i18n('days')}
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
              +0.8
            </Typography>
          </Box>
        </Box>

        {/* Line Chart */}
        <Box sx={{ flex: 1, minHeight: 280, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="line"
            width="100%"
            height={280}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. Geographical Effectiveness Chart (Grouped Bar)
// =====================================================

const GEO_SECTORS = [
  'Universities',
  'Energy',
  'Banks',
  'Broadcasting',
  'Ministry of Defense',
  'Ministry of Health',
  'Ministry of Intelligence',
];

const INCIDENT_TYPES = [
  { name: 'Data Breach', color: '#1a237e' },
  { name: 'Ransomware Attack', color: '#283593' },
  { name: 'Phishing Attack', color: '#3949ab' },
  { name: 'Server Intrusion', color: '#5c6bc0' },
  { name: 'System Downtime', color: '#7986cb' },
  { name: 'Threat to Data Publication', color: '#9fa8da' },
];

const GeographicalEffectivenessCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = GEO_SECTORS.map((s) => t_i18n(s));

  const series = [
    { name: t_i18n('Data Breach'), data: [30, 70, 55, 35, 25, 20, 40] },
    { name: t_i18n('Ransomware Attack'), data: [25, 60, 45, 30, 20, 15, 35] },
    { name: t_i18n('Phishing Attack'), data: [20, 50, 40, 25, 18, 12, 30] },
    { name: t_i18n('Server Intrusion'), data: [15, 45, 35, 22, 15, 10, 25] },
    { name: t_i18n('System Downtime'), data: [12, 35, 28, 18, 12, 8, 20] },
    { name: t_i18n('Threat to Data Publication'), data: [8, 25, 20, 12, 8, 5, 15] },
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
        stacked: false,
      },
      colors: INCIDENT_TYPES.map((t) => t.color),
      plotOptions: {
        bar: {
          columnWidth: '75%',
          borderRadius: 1,
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
          rotate: -30,
          rotateAlways: true,
          style: {
            fontSize: '9px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
      },
      yaxis: {
        ...base.yaxis,
        min: 0,
        max: 100,
        tickAmount: 5,
        labels: {
          style: { fontSize: '10px' },
        },
        axisBorder: { show: false },
      },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'center',
        fontSize: '10px',
        markers: { size: 5, shape: 'circle' },
        itemMargin: { horizontal: 6, vertical: 4 },
      },
      tooltip: { ...base.tooltip, enabled: true },
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
          {t_i18n('Geographical Effectiveness Chart')}
        </Typography>

        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            fontSize: '0.8rem',
            lineHeight: 1.5,
            marginTop: 0.5,
            marginBottom: 2,
          }}
        >
          {t_i18n('Maps threats to specific entities within sectors showing active campaigns to help prioritize defensive and response tasks')}
        </Typography>

        {/* Bar Chart */}
        <Box sx={{ flex: 1, minHeight: 350, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="bar"
            width="100%"
            height={350}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const ResponseAndEffectivenessSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12} md={6}>
        <IncidentResponseTimeCard />
      </Grid>
      <Grid item xs={12} md={6}>
        <GeographicalEffectivenessCard />
      </Grid>
    </Grid>
  );
};

export default ResponseAndEffectivenessSection;
