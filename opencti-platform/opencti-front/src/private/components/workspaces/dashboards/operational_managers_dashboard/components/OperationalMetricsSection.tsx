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
import type { ApexOptions } from 'apexcharts';

// =====================================================
// Metric Card with mini chart
// =====================================================

interface MetricChartCardProps {
  title: string;
  description: string;
  value: number;
  trend: number;
  chartData: number[];
}

const MetricChartCard: React.FC<MetricChartCardProps> = ({
  title,
  description,
  value,
  trend,
  chartData,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { t_i18n: t } = useFormatter();
  const months = ['Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar']
    .map((m) => t(m));

  const series = [{ name: t_i18n(title), data: chartData }];

  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'area',
      background: 'transparent',
      toolbar: { show: false },
      sparkline: { enabled: false },
    },
    theme: { mode: theme.palette.mode },
    colors: [theme.palette.primary.main],
    fill: {
      type: 'gradient',
      gradient: {
        shadeIntensity: 1,
        opacityFrom: 0.3,
        opacityTo: 0.05,
        stops: [0, 90, 100],
      },
    },
    stroke: { curve: 'smooth', width: 2 },
    xaxis: {
      categories: months,
      labels: {
        show: true,
        style: {
          fontSize: '8px',
          colors: theme.palette.text.secondary,
        },
      },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    yaxis: {
      show: true,
      labels: {
        style: { fontSize: '9px' },
      },
      axisBorder: { show: false },
    },
    grid: {
      show: true,
      borderColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .05)'
          : 'rgba(0, 0, 0, .05)',
      strokeDashArray: 4,
      padding: { left: 0, right: 0, top: -15, bottom: 0 },
    },
    tooltip: {
      theme: theme.palette.mode,
      fixed: { enabled: false },
      x: { show: true },
      y: { formatter: (val: number) => `${val}%` },
    },
    dataLabels: { enabled: false },
  }), [theme, months]);

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
          padding: 2.5,
          position: 'relative',
          '&:last-child': { paddingBottom: 1.5 },
        }}
      >
        <IconButton
          size="small"
          sx={{ position: 'absolute', top: 6, right: 6, color: 'text.secondary' }}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreVert sx={{ fontSize: 16 }} />
        </IconButton>

        {/* Title */}
        <Typography
          variant="body2"
          sx={{
            fontWeight: 600,
            color: 'text.primary',
            fontSize: '0.9rem',
            paddingRight: 3,
          }}
        >
          {t_i18n(title)}
        </Typography>

        {/* Description */}
        <Typography
          variant="caption"
          sx={{
            color: 'text.secondary',
            fontSize: '0.7rem',
            lineHeight: 1.4,
            marginTop: 0.3,
            marginBottom: 1.5,
          }}
        >
          {t_i18n(description)}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, marginBottom: 1 }}>
          <Typography
            sx={{
              fontWeight: 700,
              color: 'text.primary',
              fontSize: '2rem',
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
              backgroundColor: 'success.lighter',
              color: 'success.main',
              padding: '2px 6px',
              borderRadius: 1,
            }}
          >
            <ArrowUpIcon style={{ fontSize: 14 }} />
            <Typography variant="caption" sx={{ fontWeight: 600, fontSize: '0.7rem' }}>
              +{trend}%
            </Typography>
          </Box>
        </Box>

        {/* Mini Area Chart */}
        <Box sx={{ flex: 1, width: '100%', minHeight: 120, marginTop: 'auto' }}>
          <Chart
            options={options}
            series={series}
            type="area"
            width="100%"
            height={120}
          />
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const OperationalMetricsSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr' }}>
      <Grid item xs={12} sm={6} md={3}>
        <MetricChartCard
          title="Index Compliance Rate"
          description="Percentage of compliance of input data from reports with existing IOCs"
          value={87}
          trend={18}
          chartData={[52, 48, 58, 55, 50, 62, 58, 68, 72, 65, 78, 82, 75, 80, 85, 78, 83, 87, 90, 84, 88, 92, 87, 91]}
        />
      </Grid>
      <Grid item xs={12} sm={6} md={3}>
        <MetricChartCard
          title="Reduction Success Rate"
          description="Ratio of discovered threats that have been successfully neutralized"
          value={66}
          trend={18}
          chartData={[35, 30, 38, 42, 36, 45, 40, 48, 52, 46, 55, 50, 58, 54, 60, 56, 62, 58, 65, 60, 63, 68, 64, 66]}
        />
      </Grid>
      <Grid item xs={12} sm={6} md={3}>
        <MetricChartCard
          title="True Positive IOCs Rate"
          description="Ratio of confirmed incidents to all CTI team alerts based on IOCs in the system"
          value={35}
          trend={30}
          chartData={[12, 8, 15, 11, 18, 14, 20, 16, 22, 19, 25, 21, 28, 24, 30, 26, 32, 28, 34, 30, 33, 36, 32, 35]}
        />
      </Grid>
      <Grid item xs={12} sm={6} md={3}>
        <MetricChartCard
          title="TTP Detection Coverage"
          description="Percentage coverage of MITRE ATT&CK matrix"
          value={56}
          trend={30}
          chartData={[22, 18, 28, 24, 32, 26, 35, 30, 38, 34, 42, 36, 45, 40, 48, 44, 50, 46, 53, 48, 55, 52, 58, 56]}
        />
      </Grid>
    </Grid>
  );
};

export default OperationalMetricsSection;
