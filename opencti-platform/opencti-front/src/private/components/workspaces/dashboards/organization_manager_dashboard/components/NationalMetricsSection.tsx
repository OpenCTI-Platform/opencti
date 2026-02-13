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
import {
  ArrowUp24Regular as ArrowUpIcon,
  ArrowDown24Regular as ArrowDownIcon,
  ChevronLeft24Regular as ChevronLeftIcon,
} from '@fluentui/react-icons';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { lineChartOptions, verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

const MONTHS = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

// --- National Risk Score Card ---

const NationalRiskScoreCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  // Bar chart data - last bar is highlighted (current month)
  const barData = [65, 70, 55, 80, 90, 60, 75, 85, 95, 70, 80, 76];
  const barColors = barData.map((_, i) => (i === barData.length - 1 ? '#e91e8c' : theme.palette.primary.main));

  const series = [
    {
      name: t_i18n('Risk Score'),
      data: barData,
    },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = verticalBarsChartOptions(
      theme,
      (v: string) => v,
      (v: number) => `${v}`,
      true,
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
      colors: barColors,
      grid: {
        ...base.grid,
        show: false,
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
        labels: { show: false },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      plotOptions: {
        bar: {
          distributed: true,
          columnWidth: '60%',
          borderRadius: 2,
        },
      },
      legend: { show: false },
      tooltip: { ...base.tooltip, enabled: true },
    };
  }, [theme, categories, barColors]);

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
        {/* Menu icon */}
        <IconButton
          size="small"
          sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreVert fontSize="small" />
        </IconButton>

        {/* Title */}
        <Typography
          variant="h6"
          sx={{
            fontWeight: 600,
            color: 'text.primary',
            fontSize: '1rem',
            paddingRight: 4,
          }}
        >
          {t_i18n('National Risk Score')}
        </Typography>

        {/* Description */}
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
          {t_i18n('Weighted sum of active campaigns, critical incidents, vulnerabilities under exploitation, and sector coverage')}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 1 }}>
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              color: 'text.primary',
              fontSize: '2.5rem',
              lineHeight: 1,
            }}
          >
            76%
          </Typography>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.3,
              backgroundColor: 'error.lighter',
              color: 'error.main',
              padding: '2px 8px',
              borderRadius: 1,
            }}
          >
            <ArrowDownIcon style={{ fontSize: 16 }} />
            <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem' }}>
              10%
            </Typography>
          </Box>
        </Box>

        {/* More Details link */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 0.5,
            color: 'text.secondary',
            cursor: 'pointer',
            marginBottom: 1,
            '&:hover': { color: 'primary.main' },
          }}
        >
          <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
            {t_i18n('More details')}
          </Typography>
          <ChevronLeftIcon style={{ fontSize: 16 }} />
        </Box>

        {/* Chart */}
        <Box sx={{ flex: 1, minHeight: 160, width: '100%', marginTop: 'auto' }}>
          <Chart
            options={options}
            series={series}
            type="bar"
            width="100%"
            height={160}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// --- MTTD Card ---

const MttdCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  const series = [
    {
      name: t_i18n('MTTD (days)'),
      data: [180, 200, 190, 210, 220, 250, 230, 200, 260, 230, 210, 230],
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
      false,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: [theme.palette.primary.main],
      grid: {
        ...base.grid,
        show: true,
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
        labels: { show: true, style: { fontSize: '10px' } },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      stroke: { curve: 'smooth', width: 2 },
      legend: { show: false },
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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}
        >
          {t_i18n('National Mean Time to Detect (MTTD)')}
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
          {t_i18n('Aggregated from timelines, cyber incidents and detection reports, threat hunting and forensics')}
        </Typography>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 2 }}>
          <Typography
            variant="h3"
            sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2.5rem', lineHeight: 1 }}
          >
            230
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
              16%
            </Typography>
          </Box>
        </Box>

        <Box sx={{ flex: 1, minHeight: 160, width: '100%', marginTop: 'auto' }}>
          <Chart
            options={options}
            series={series}
            type="line"
            width="100%"
            height={160}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// --- MTCR Card ---

const MtcrCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  const series = [
    {
      name: t_i18n('MTCR (days)'),
      data: [3.0, 3.2, 2.8, 3.5, 3.0, 3.8, 3.5, 3.2, 3.5, 3.0, 3.3, 3.5],
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
      false,
    ) as ApexOptions;
    return {
      ...base,
      chart: {
        ...base.chart,
        background: 'transparent',
        toolbar: { show: false },
      },
      colors: [theme.palette.primary.main],
      grid: {
        ...base.grid,
        show: true,
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
        labels: { show: true, style: { fontSize: '10px' } },
        min: 0,
        max: 5,
        tickAmount: 5,
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      stroke: { curve: 'smooth', width: 2 },
      legend: { show: false },
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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}
        >
          {t_i18n('Mean Time to Coordinate Response (MTCR)')}
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
          {t_i18n('Aggregated from timelines, cyber incidents and detection reports, threat hunting and forensics')}
        </Typography>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 2 }}>
          <Typography
            variant="h3"
            sx={{ fontWeight: 700, color: 'text.primary', fontSize: '2.5rem', lineHeight: 1 }}
          >
            3.5
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
              36%
            </Typography>
          </Box>
        </Box>

        <Box sx={{ flex: 1, minHeight: 160, width: '100%', marginTop: 'auto' }}>
          <Chart
            options={options}
            series={series}
            type="line"
            width="100%"
            height={160}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// --- Main Section ---

const NationalMetricsSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr' }}>
      <Grid item xs={12} md={4}>
        <NationalRiskScoreCard />
      </Grid>
      <Grid item xs={12} md={4}>
        <MttdCard />
      </Grid>
      <Grid item xs={12} md={4}>
        <MtcrCard />
      </Grid>
    </Grid>
  );
};

export default NationalMetricsSection;
