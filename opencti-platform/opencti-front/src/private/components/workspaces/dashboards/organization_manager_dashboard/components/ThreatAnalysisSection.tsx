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
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { lineChartOptions, verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

// --- Cross-Sector Impact Severity Card (Grouped Bar Chart) ---

const SECTORS = [
  'Universities',
  'Energy',
  'Banks',
  'Broadcasting',
  'Municipalities',
  'Ministry of Defense',
  'Ministry of Health',
  'Ministry of Intelligence',
];

const INCIDENT_TYPES = [
  { name: 'Data Breach', color: '#1a237e' },
  { name: 'Phishing Attack', color: '#283593' },
  { name: 'Ransomware Attack', color: '#3949ab' },
  { name: 'Server Intrusion', color: '#5c6bc0' },
  { name: 'System Downtime', color: '#7986cb' },
  { name: 'Threat to Data Publication', color: '#9fa8da' },
];

const CrossSectorImpactCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = SECTORS.map((s) => t_i18n(s));

  const series = [
    { name: t_i18n('Data Breach'), data: [85, 60, 70, 50, 30, 40, 20, 35] },
    { name: t_i18n('Phishing Attack'), data: [75, 55, 65, 45, 25, 35, 15, 30] },
    { name: t_i18n('Ransomware Attack'), data: [65, 50, 55, 40, 20, 30, 10, 25] },
    { name: t_i18n('Server Intrusion'), data: [55, 45, 50, 35, 18, 25, 12, 20] },
    { name: t_i18n('System Downtime'), data: [45, 35, 40, 30, 15, 20, 8, 18] },
    { name: t_i18n('Threat to Data Publication'), data: [35, 25, 30, 20, 10, 15, 5, 12] },
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
          rotate: -45,
          rotateAlways: true,
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
        max: 100,
        tickAmount: 5,
        labels: {
          style: {
            fontSize: '10px',
            fontFamily: '"IBM Plex Sans", sans-serif',
          },
        },
        axisBorder: { show: false },
      },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'center',
        fontSize: '11px',
        markers: {
          size: 6,
          shape: 'circle',
        },
        itemMargin: { horizontal: 8, vertical: 4 },
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
          {t_i18n('Cross-Sector Impact Severity')}
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
          {t_i18n('Average severity score of incidents across ministries, banks, universities, municipalities and provinces')}
        </Typography>

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

// --- Threat Trend Velocity Card (Multi-Line Chart) ---

const CAMPAIGNS = [
  { name: 'Pay2Key', color: '#4caf50' },
  { name: 'Anonymous', color: '#9c27b0' },
  { name: 'APT34 (OilRig)', color: '#b71c1c' },
  { name: 'Gonjeshk Darandeh', color: '#ff9800' },
  { name: 'Tapandegan', color: '#f44336' },
  { name: 'Qiyam', color: '#fdd835' },
];

const YEARS = ['2017', '2018', '2019', '2020', '2021', '2022', '2023', '2024', '2025'];

const ThreatTrendVelocityCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = YEARS;

  const series = [
    { name: 'Pay2Key', data: [5, 8, 12, 10, 14, 11, 8, 6, 4] },
    { name: 'Anonymous', data: [3, 5, 9, 13, 10, 8, 12, 11, 7] },
    { name: 'APT34 (OilRig)', data: [8, 6, 10, 8, 12, 15, 9, 7, 5] },
    { name: 'Gonjeshk Darandeh', data: [2, 4, 6, 5, 8, 10, 14, 18, 25] },
    { name: 'Tapandegan', data: [10, 12, 8, 15, 20, 18, 25, 28, 22] },
    { name: 'Qiyam', data: [1, 3, 2, 4, 6, 5, 8, 7, 10] },
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
        max: 30,
        tickAmount: 6,
        labels: {
          style: {
            fontSize: '10px',
            fontFamily: '"IBM Plex Sans", sans-serif',
          },
        },
        axisBorder: { show: false },
      },
      stroke: {
        curve: 'straight',
        width: 2,
      },
      markers: {
        size: 5,
        strokeWidth: 0,
        hover: { sizeOffset: 2 },
      },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'center',
        fontSize: '11px',
        markers: {
          size: 6,
          shape: 'circle',
        },
        itemMargin: { horizontal: 8, vertical: 4 },
      },
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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingInlineEnd: 4 }}
        >
          {t_i18n('Threat Trend Velocity')}
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
          {t_i18n('Year-over-year change in campaigns identified by state-sponsored APTs and hacktivist groups per campaign')}
        </Typography>

        <Box sx={{ flex: 1, minHeight: 350, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="line"
            width="100%"
            height={350}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// --- Main Section ---

const ThreatAnalysisSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12} md={6}>
        <CrossSectorImpactCard />
      </Grid>
      <Grid item xs={12} md={6}>
        <ThreatTrendVelocityCard />
      </Grid>
    </Grid>
  );
};

export default ThreatAnalysisSection;
