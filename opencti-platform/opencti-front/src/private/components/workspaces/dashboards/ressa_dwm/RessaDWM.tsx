import React from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  Alert,
} from '@mui/material';
import {
  SendOutlined,
  WebOutlined,
  MessageOutlined,
} from '@mui/icons-material';
import { Github } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import Loader from '../../../../../components/Loader';
import StatCard from './StatCard';
import DonutChart from './DonutChart';
import ProgressList from './ProgressList';
import TrendChart from './TrendChart';
import ChatInterface from './ChatInterface';
import { useRessaDWMData } from './useRessaDWMData';

const RessaDWM = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { data, loading, error } = useRessaDWMData();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Ressa DWM'));

  // Default data for fallback or while loading
  const defaultStats = [
    {
      title: t_i18n('All New Leaks'),
      value: 129,
      change: 30,
      icon: <SendOutlined />,
      isPositive: true,
    },
    {
      title: t_i18n('Dark Web'),
      value: 43,
      change: 19,
      icon: <Github />,
      isPositive: false,
    },
    {
      title: t_i18n('Web'),
      value: 26,
      change: 63,
      icon: <WebOutlined />,
      isPositive: true,
    },
    {
      title: t_i18n('Telegram'),
      value: 32,
      change: 39,
      icon: <MessageOutlined />,
      isPositive: true,
    },
  ];

  const defaultMonitoredSources = [
    { label: t_i18n('Web'), value: 25000, color: '#1565c0' },
    { label: t_i18n('Forums'), value: 12000, color: '#64b5f6' },
    { label: t_i18n('Telegram'), value: 15000, color: '#42a5f5' },
    { label: t_i18n('Dark Web'), value: 18000, color: '#0d47a1' },
    { label: t_i18n('Social Media'), value: 10000, color: '#42a5f5' },
    { label: t_i18n('Deep Web'), value: 8000, color: '#90caf9' },
    { label: t_i18n('Chat Apps'), value: 7000, color: '#42a5f5' },
    { label: t_i18n('Email'), value: 5000, color: '#0d47a1' },
    { label: t_i18n('Gaming Platforms'), value: 3000, color: '#42a5f5' },
    { label: t_i18n('File Sharing'), value: 1670, color: '#90caf9' },
  ];

  const defaultTopLeaks = [
    { name: 'IRLeaks', value: 150 },
    { name: 'bakhtak', value: 120 },
    { name: 'We Red Evils Original', value: 100 },
    { name: 'OnHex', value: 60 },
    { name: 'CVE Notify', value: 35 },
  ];

  const defaultTopDamageable = [
    { name: 'Tapsi.ir', value: 109 },
    { name: 'Snapp.ir', value: 85 },
    { name: 'Varzesh3.com', value: 78 },
    { name: 'Irancell.com', value: 66 },
    { name: 'mci.ir', value: 47 },
  ];

  const defaultTrendSeries = [
    {
      name: t_i18n('Dark Web'),
      data: [220, 240, 280, 320, 350, 380, 360, 400, 450, 500, 550, 580],
      color: '#64b5f6',
    },
    {
      name: t_i18n('Telegram'),
      data: [450, 470, 480, 490, 500, 510, 520, 530, 540, 550, 560, 580],
      color: '#42a5f5',
    },
    {
      name: t_i18n('Web'),
      data: [650, 680, 700, 720, 750, 780, 760, 800, 820, 840, 860, 880],
      color: '#1565c0',
    },
  ];

  // Use API data if available, otherwise use defaults
  const stats = data ? [
    {
      title: t_i18n('All New Leaks'),
      value: data.stats.allNewLeaks.value,
      change: data.stats.allNewLeaks.change,
      icon: <SendOutlined />,
      isPositive: data.stats.allNewLeaks.change > 0,
    },
    {
      title: t_i18n('Dark Web'),
      value: data.stats.darkWeb.value,
      change: data.stats.darkWeb.change,
      icon: <Github />,
      isPositive: data.stats.darkWeb.change > 0,
    },
    {
      title: t_i18n('Web'),
      value: data.stats.web.value,
      change: data.stats.web.change,
      icon: <WebOutlined />,
      isPositive: data.stats.web.change > 0,
    },
    {
      title: t_i18n('Telegram'),
      value: data.stats.telegram.value,
      change: data.stats.telegram.change,
      icon: <MessageOutlined />,
      isPositive: data.stats.telegram.change > 0,
    },
  ] : defaultStats;

  const monitoredSources = data?.monitoredSources || defaultMonitoredSources;
  const topLeaks = data?.topLeaks || defaultTopLeaks;
  const topDamageable = data?.topDamageable || defaultTopDamageable;
  const vulnerabilityTrends = data?.vulnerabilityTrends || defaultTrendSeries;
  const dataLeakTrends = data?.dataLeakTrends || defaultTrendSeries;
  const monitoredSourcesTotal = monitoredSources.reduce((sum, item) => sum + item.value, 0);

  if (loading) {
    return (
      <>
        <Breadcrumbs
          elements={[
            { label: t_i18n('Dashboards') },
            { label: t_i18n('Ressa DWM'), current: true },
          ]}
        />
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
          <Loader />
        </Box>
      </>
    );
  }

  // Show error banner if there's an error, but still render dashboard with default data
  const showErrorBanner = error && !data;

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Ressa DWM'), current: true },
        ]}
      />
      {showErrorBanner && (
        <Box sx={{ padding: 2, paddingBottom: 0 }}>
          <Alert severity="warning" sx={{ marginBottom: 2 }}>
            {t_i18n('Error loading dashboard data')}: {error}. {t_i18n('Using default data.')}
          </Alert>
        </Box>
      )}
      <Box sx={{ padding: 0 }}>
        <Grid container spacing={3} sx={{ marginBottom: 3 }}>
          {stats.map((stat) => (
            <Grid item xs={12} sm={6} md={3} key={stat.title}>
              <StatCard
                title={stat.title}
                value={stat.value}
                change={stat.change}
                icon={stat.icon}
                isPositive={stat.isPositive}
              />
            </Grid>
          ))}
        </Grid>

        {/* Three panels below */}
        <Grid container spacing={3}>
          {/* Monitored Sources Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: theme.palette.background?.paper || theme.palette.background?.default }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: theme.palette.text?.primary,
                    fontSize: '1rem',
                  }}
                >
                  {t_i18n('Monitored Sources')}
                </Typography>
                <DonutChart
                  data={monitoredSources}
                  total={monitoredSourcesTotal}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Top Leaks Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: theme.palette.background?.paper || theme.palette.background?.default }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: theme.palette.text?.primary,
                    fontSize: '1rem',
                  }}
                >
                  {t_i18n('Top Leaks')}
                </Typography>
                <ProgressList
                  items={topLeaks}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Top Damageable Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: theme.palette.background?.paper || theme.palette.background?.default }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: theme.palette.text?.primary,
                    fontSize: '1rem',
                  }}
                >
                  {t_i18n('Top Damageable')}
                </Typography>
                <ProgressList
                  items={topDamageable}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Two trend charts */}
        <Grid container spacing={3} sx={{ marginTop: 0 }}>
          {/* Vulnerability Trends Chart */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: theme.palette.background?.paper || theme.palette.background?.default }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: theme.palette.text?.primary,
                    fontSize: '1rem',
                  }}
                >
                  {t_i18n('Vulnerability Trends Over Time (by Source)')}
                </Typography>
                <TrendChart
                  series={vulnerabilityTrends}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Data Leak Trends Chart */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: theme.palette.background?.paper || theme.palette.background?.default }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: theme.palette.text?.primary,
                    fontSize: '1rem',
                  }}
                >
                  {t_i18n('Data Leak Trends Over Time (by Source)')}
                </Typography>
                <TrendChart
                  series={dataLeakTrends}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Chat Section */}
        <Box sx={{ marginTop: 3, marginBottom: 28 }}>
          <ChatInterface />
        </Box>
      </Box>
    </>
  );
};

export default RessaDWM;
