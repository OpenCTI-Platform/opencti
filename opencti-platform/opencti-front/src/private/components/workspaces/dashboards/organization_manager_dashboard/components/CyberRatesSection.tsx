import React, { useMemo } from 'react';
import {
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
import {
  ArrowUp24Regular as ArrowUpIcon,
  ArrowDown24Regular as ArrowDownIcon,
  ChevronRight24Regular as ChevronRightIcon,
} from '@fluentui/react-icons';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import { areaChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

const MONTHS_SHORT = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

// --- Ranked Organization Item ---

interface RankedOrgItemProps {
  rank: number;
  name: string;
  percentage: number;
  color: string;
}

const RankedOrgItem: React.FC<RankedOrgItemProps> = ({
  rank,
  name,
  percentage,
  color,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Box
      sx={{
        position: 'relative',
        width: '100%',
        marginBottom: 0.8,
      }}
    >
      {/* Large progress bar as background */}
      <LinearProgress
        variant="determinate"
        value={percentage}
        sx={{
          height: 32,
          borderRadius: 1,
          [`&.${linearProgressClasses.colorPrimary}`]: {
            backgroundColor: 'action.hover',
          },
          [`& .${linearProgressClasses.bar}`]: {
            borderRadius: 1,
            backgroundColor: color,
            opacity: 0.85,
          },
        }}
      />

      {/* Overlay text on top of the bar */}
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
        {/* Rank + Name */}
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
          {rank}. {t_i18n(name)}
        </Typography>

        {/* Percentage */}
        <Typography
          variant="body2"
          sx={{
            color: 'text.primary',
            fontSize: '0.8rem',
            fontWeight: 700,
            marginLeft: 1,
          }}
        >
          {percentage}%
        </Typography>
      </Box>
    </Box>
  );
};

// --- Reusable Rate Card ---

interface RateCardProps {
  title: string;
  description: string;
  value: number;
  trendValue: number;
  trendPositive: boolean;
  chartData: number[];
  chartColor: string;
  barColor: string;
  organizations: { name: string; percentage: number }[];
}

const RateCard: React.FC<RateCardProps> = ({
  title,
  description,
  value,
  trendValue,
  trendPositive,
  chartData,
  chartColor,
  barColor,
  organizations,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS_SHORT.map((m) => t_i18n(m));

  const series = [
    {
      name: t_i18n(title),
      data: chartData,
    },
  ];

  const options: ApexOptions = useMemo(() => {
    const base = areaChartOptions(
      theme,
      false,
      null,
      (v: number) => `${v}%`,
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
        sparkline: { enabled: false },
      },
      colors: [chartColor],
      fill: {
        type: 'gradient',
        gradient: {
          shadeIntensity: 1,
          opacityFrom: 0.3,
          opacityTo: 0.05,
          stops: [0, 90, 100],
        },
      },
      grid: {
        show: false,
        padding: { left: 0, right: 0, top: -20, bottom: 0 },
      },
      xaxis: {
        ...base.xaxis,
        categories,
        labels: { show: false },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      yaxis: {
        ...base.yaxis,
        labels: { show: false },
        axisBorder: { show: false },
        axisTicks: { show: false },
      },
      stroke: { curve: 'smooth', width: 2 },
      legend: { show: false },
      tooltip: { ...base.tooltip, enabled: true },
      dataLabels: { enabled: false },
    };
  }, [theme, categories, chartColor]);

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
          {t_i18n(title)}
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
          {t_i18n(description)}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, marginBottom: 0.5 }}>
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              color: 'text.primary',
              fontSize: '2.5rem',
              lineHeight: 1,
            }}
          >
            {value}%
          </Typography>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.3,
              backgroundColor: trendPositive ? 'success.lighter' : 'error.lighter',
              color: trendPositive ? 'success.main' : 'error.main',
              padding: '2px 8px',
              borderRadius: 1,
            }}
          >
            {trendPositive
              ? <ArrowUpIcon style={{ fontSize: 16 }} />
              : <ArrowDownIcon style={{ fontSize: 16 }} />
            }
            <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem' }}>
              {trendValue}%
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
            marginBottom: 1.5,
            '&:hover': { color: 'primary.main' },
          }}
        >
          <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
            {t_i18n('More details')}
          </Typography>
          <ChevronRightIcon style={{ fontSize: 16 }} />
        </Box>

        {/* Mini Area Chart */}
        <Box sx={{ width: '100%', height: 100, marginBottom: 1 }}>
          <Chart
            options={options}
            series={series}
            type="area"
            width="100%"
            height={100}
          />
        </Box>

        {/* Top 10 Organizations List */}
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          {organizations.map((org, index) => (
            <RankedOrgItem
              key={org.name}
              rank={index + 1}
              name={org.name}
              percentage={org.percentage}
              color={barColor}
            />
          ))}
        </Box>
      </CardContent>
    </Card>
  );
};

// --- Main Section ---

const complianceOrganizations = [
  { name: 'Oil Products Distribution Company', percentage: 90 },
  { name: 'Atomic Energy Organization', percentage: 70 },
  { name: 'Ministry of Intelligence', percentage: 40 },
  { name: 'Ministry of Education', percentage: 30 },
  { name: 'Ministry of Sports and Youth', percentage: 30 },
  { name: 'Ministry of Science', percentage: 20 },
  { name: 'Ministry of Industry', percentage: 20 },
  { name: 'Ministry of Interior', percentage: 20 },
  { name: 'Ministry of Defense', percentage: 20 },
  { name: 'Ministry of Health', percentage: 20 },
];

const gapOrganizations = [
  { name: 'Presidential Institution', percentage: 90 },
  { name: 'Supreme National Security Council', percentage: 70 },
  { name: 'National Cyberspace Center', percentage: 40 },
  { name: 'Passive Defense Organization', percentage: 30 },
  { name: 'Iran IT Organization', percentage: 30 },
  { name: 'AFTA Strategic Management Center', percentage: 20 },
  { name: 'Budget and Planning Organization', percentage: 20 },
  { name: 'Ministry of Roads and Urban Dev.', percentage: 20 },
  { name: 'Ministry of Economy and Finance', percentage: 10 },
  { name: 'Ministry of Health and Medical Edu.', percentage: 10 },
];

const CyberRatesSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      {/* Compliance Rate - Left */}
      <Grid item xs={12} md={6}>
        <RateCard
          title="National Cyber Compliance Rate"
          description="Percentage of subsidiary organizations that comply with standards and requirements"
          value={60}
          trendValue={43}
          trendPositive
          chartData={[40, 45, 42, 50, 48, 55, 52, 58, 54, 60, 57, 60]}
          chartColor="#4caf50"
          barColor="#4caf50"
          organizations={complianceOrganizations}
        />
      </Grid>

      {/* Gap Rate - Right */}
      <Grid item xs={12} md={6}>
        <RateCard
          title="National Cyber Gap Rate"
          description="Percentage of organizations lacking controls and requirements with critical status"
          value={40}
          trendValue={33}
          trendPositive={false}
          chartData={[60, 55, 58, 50, 52, 45, 48, 42, 46, 40, 43, 40]}
          chartColor="#f44336"
          barColor="#f44336"
          organizations={gapOrganizations}
        />
      </Grid>
    </Grid>
  );
};

export default CyberRatesSection;
