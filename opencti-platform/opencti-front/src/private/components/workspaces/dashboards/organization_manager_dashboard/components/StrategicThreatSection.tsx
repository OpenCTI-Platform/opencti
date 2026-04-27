import React, { useMemo } from 'react';
import {
  Avatar,
  Box,
  Card,
  CardContent,
  Grid,
  IconButton,
  LinearProgress,
  linearProgressClasses,
  Typography,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { areaChartOptions, verticalBarsChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

// =====================================================
// 1. Top Attackers by Strategic Impact
// =====================================================

const TOP_ATTACKERS = [
  { name: 'Qiyam', score: 32 },
  { name: 'Gonjeshk Darandeh', score: 24 },
  { name: 'Tapandegan', score: 12 },
  { name: 'Adie Ali', score: 8 },
  { name: 'APT33 (Elfin)', score: 7 },
  { name: 'APT35 (Charming Kitten)', score: 7 },
  { name: 'MuddyWater', score: 6 },
  { name: 'DEV-0270 / Nemesis Kitten', score: 6 },
];

const maxScore = Math.max(...TOP_ATTACKERS.map((a) => a.score));

const TopAttackersCard: React.FC = () => {
  const { t_i18n } = useFormatter();

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
          {t_i18n('Top Attackers by Strategic Impact')}
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
          {t_i18n('Ranked list of threat actors by industry and number of attacks')}
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {TOP_ATTACKERS.map((attacker, index) => (
            <Box key={attacker.name} sx={{ position: 'relative', width: '100%' }}>
              <LinearProgress
                variant="determinate"
                value={(attacker.score / maxScore) * 100}
                sx={{
                  height: 32,
                  borderRadius: 1,
                  [`&.${linearProgressClasses.colorPrimary}`]: {
                    backgroundColor: 'action.hover',
                  },
                  [`& .${linearProgressClasses.bar}`]: {
                    borderRadius: 1,
                    backgroundColor: '#5c6bc0',
                    opacity: 0.85,
                  },
                }}
              />
              <Box
                sx={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  display: 'flex',
                  alignItems: 'center',
                  paddingX: 1.5,
                }}
              >
                <Typography
                  variant="body2"
                  sx={{
                    color: 'text.primary',
                    fontSize: '0.8rem',
                    fontWeight: 500,
                    flex: 1,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {index + 1}. {attacker.name}
                </Typography>
                <Typography
                  variant="body2"
                  sx={{
                    color: 'text.primary',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    marginInlineStart: 1,
                  }}
                >
                  {attacker.score}
                </Typography>
              </Box>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. High Confidence Active Campaigns
// =====================================================

const MONTHS_SHORT = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

const CAMPAIGN_CATEGORIES = [
  { name: 'Energy', count: 3, color: '#4caf50' },
  { name: 'Political-Governance', count: 16, color: '#7e57c2' },
  { name: 'Financial', count: 13, color: '#42a5f5' },
];

const HighConfidenceCampaignsCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS_SHORT.map((m) => t_i18n(m));

  const series = [
    {
      name: t_i18n('Energy'),
      data: [12, 15, 18, 14, 20, 22, 25, 28, 30, 26, 32, 35],
    },
    {
      name: t_i18n('Political-Governance'),
      data: [30, 35, 32, 40, 38, 45, 50, 48, 55, 60, 58, 65],
    },
    {
      name: t_i18n('Financial'),
      data: [20, 22, 25, 28, 24, 30, 32, 35, 38, 34, 40, 42],
    },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = areaChartOptions(
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
      colors: CAMPAIGN_CATEGORIES.map((c) => c.color),
      fill: {
        type: 'gradient',
        gradient: {
          shadeIntensity: 1,
          opacityFrom: 0.25,
          opacityTo: 0.05,
          stops: [0, 90, 100],
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
        labels: {
          style: {
            fontSize: '10px',
            fontFamily: '"IBM Plex Sans", sans-serif',
          },
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
        itemMargin: { horizontal: 8, vertical: 4 },
      },
      tooltip: { ...base.tooltip, enabled: true },
      dataLabels: { enabled: false },
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
          {t_i18n('High Confidence Active Campaigns')}
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
          {t_i18n('Number of campaigns with confidence >= high')}
        </Typography>

        {/* Summary Metrics */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: 4,
            marginBottom: 2,
          }}
        >
          {CAMPAIGN_CATEGORIES.map((cat) => (
            <Box
              key={cat.name}
              sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 0.5,
              }}
            >
              <Avatar
                sx={{
                  width: 40,
                  height: 40,
                  backgroundColor: cat.color,
                  fontSize: '1rem',
                  fontWeight: 700,
                }}
              >
                {cat.count}
              </Avatar>
              <Typography
                variant="caption"
                sx={{ color: 'text.secondary', fontSize: '0.7rem' }}
              >
                {t_i18n(cat.name)}
              </Typography>
            </Box>
          ))}
        </Box>

        {/* Area Chart */}
        <Box sx={{ flex: 1, minHeight: 250, width: '100%' }}>
          <Chart
            options={options}
            series={series}
            type="area"
            width="100%"
            height={250}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 3. Resource Allocation Attribution
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
      colors: ['#7e57c2', '#42a5f5'],
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
            fontSize: '9px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
        title: {
          text: t_i18n('Year'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
      },
      yaxis: {
        ...base.yaxis,
        title: {
          text: t_i18n('Budget (million)'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
        labels: {
          style: { fontSize: '10px' },
        },
        axisBorder: { show: false },
      },
      legend: { show: false },
      tooltip: { ...base.tooltip, enabled: true },
    };
  }, [theme]);

  // Bottom chart: Counts (hacktivist groups, campaigns, incidents)
  const countSeries = [
    {
      name: t_i18n('Hacktivist Groups'),
      data: [2, 3, 4, 5, 8, 10, 12, 15, 18, 22, 30, 35, 40],
    },
    {
      name: t_i18n('Campaigns'),
      data: [5, 7, 8, 10, 12, 15, 18, 22, 28, 35, 42, 48, 50],
    },
    {
      name: t_i18n('Incidents'),
      data: [8, 10, 12, 15, 20, 25, 30, 35, 40, 45, 48, 50, 52],
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
      colors: ['#7e57c2', '#42a5f5', '#90caf9'],
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
            fontSize: '9px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
        title: {
          text: t_i18n('Year'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
      },
      yaxis: {
        ...base.yaxis,
        title: {
          text: t_i18n('Attacks, Campaigns & Groups'),
          style: { fontSize: '10px', color: theme.palette.text.secondary },
        },
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
        itemMargin: { horizontal: 6, vertical: 2 },
      },
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
          sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingInlineEnd: 4 }}
        >
          {t_i18n('Resource Allocation Attribution')}
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

        {/* Legend for all series */}
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
            { label: 'Hacktivist Groups', color: '#7e57c2' },
            { label: 'Budget', color: '#42a5f5' },
            { label: 'Campaigns', color: '#42a5f5' },
            { label: 'Incidents', color: '#90caf9' },
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
        <Box sx={{ width: '100%', minHeight: 170 }}>
          <Chart
            options={budgetOptions}
            series={budgetSeries}
            type="bar"
            width="100%"
            height={170}
          />
        </Box>

        {/* Counts Chart (bottom) */}
        <Box sx={{ width: '100%', minHeight: 170 }}>
          <Chart
            options={countOptions}
            series={countSeries}
            type="bar"
            width="100%"
            height={170}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const StrategicThreatSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      {/* Left: Top Attackers */}
      <Grid item xs={12} md={3}>
        <TopAttackersCard />
      </Grid>

      {/* Center: High Confidence Active Campaigns */}
      <Grid item xs={12} md={5}>
        <HighConfidenceCampaignsCard />
      </Grid>

      {/* Right: Resource Allocation Attribution */}
      <Grid item xs={12} md={4}>
        <ResourceAllocationCard />
      </Grid>
    </Grid>
  );
};

export default StrategicThreatSection;
