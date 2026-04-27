import React, { useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  IconButton,
  Typography,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import Chart from '@components/common/charts/Chart';
import type { ApexOptions } from 'apexcharts';

// MITRE ATT&CK Tactics (columns)
const TACTICS = [
  'Reconnaissance',
  'Resource Dev.',
  'Initial Access',
  'Execution',
  'Persistence',
  'Priv. Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'C2',
  'Exfiltration',
  'Impact',
];

// Technique rows (simplified labels)
const TECHNIQUES = [
  'T1595', 'T1592', 'T1589', 'T1590', 'T1591',
  'T1583', 'T1584', 'T1587', 'T1588', 'T1608',
  'T1566', 'T1190', 'T1133', 'T1078', 'T1199',
];

// Generate heatmap data
const generateHeatmapData = () => {
  const data: { name: string; data: { x: string; y: number }[] }[] = [];

  TECHNIQUES.forEach((technique) => {
    const row: { x: string; y: number }[] = [];
    TACTICS.forEach((tactic) => {
      // Random value: 0 = no data, 1-5 = intensity levels
      const rand = Math.random();
      let value = 0;
      if (rand > 0.35) {
        value = Math.ceil(Math.random() * 5);
      }
      row.push({ x: tactic, y: value });
    });
    data.push({ name: technique, data: row });
  });

  return data;
};

const TTPHeatmapSection: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const series = useMemo(() => generateHeatmapData(), []);

  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'heatmap',
      background: 'transparent',
      toolbar: { show: false },
      foreColor: theme.palette.text.secondary,
    },
    theme: { mode: theme.palette.mode },
    dataLabels: { enabled: false },
    plotOptions: {
      heatmap: {
        shadeIntensity: 0.5,
        radius: 2,
        enableShades: true,
        colorScale: {
          ranges: [
            { from: 0, to: 0, color: theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5', name: t_i18n('None') },
            { from: 1, to: 1, color: '#fff9c4', name: t_i18n('Low') },
            { from: 2, to: 2, color: '#ffe082', name: t_i18n('Medium-Low') },
            { from: 3, to: 3, color: '#ffab91', name: t_i18n('Medium') },
            { from: 4, to: 4, color: '#f48fb1', name: t_i18n('High') },
            { from: 5, to: 5, color: '#ce93d8', name: t_i18n('Critical') },
          ],
        },
      },
    },
    xaxis: {
      labels: {
        rotate: -45,
        rotateAlways: true,
        style: {
          fontSize: '9px',
          fontFamily: '"IBM Plex Sans", sans-serif',
          colors: theme.palette.text.secondary,
        },
      },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    yaxis: {
      labels: {
        style: {
          fontSize: '9px',
          fontFamily: '"IBM Plex Sans", sans-serif',
        },
      },
    },
    grid: {
      show: false,
      padding: { left: 10, right: 10, top: 0, bottom: 0 },
    },
    legend: {
      show: true,
      position: 'bottom',
      horizontalAlign: 'center',
      fontSize: '10px',
      markers: { size: 8, shape: 'square' },
      itemMargin: { horizontal: 8, vertical: 4 },
    },
    tooltip: {
      theme: theme.palette.mode,
      y: {
        formatter: (val: number) => {
          const levels = ['None', 'Low', 'Medium-Low', 'Medium', 'High', 'Critical'];
          return levels[val] || 'None';
        },
      },
    },
    stroke: {
      width: 2,
      colors: [theme.palette.background.paper],
    },
  }), [theme]);

  return (
    <Box sx={{ marginTop: 3 }}>
      <Card
        variant="outlined"
        sx={{
          backgroundColor: 'background.paper',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <CardContent
          sx={{
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
            {t_i18n('TTP Heatmap')}
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
            {t_i18n('Shows common attacker tactics, techniques and procedures and highlights supply chain infiltration')}
          </Typography>

          <Box sx={{ width: '100%', minHeight: 450, overflowX: 'auto' }}>
            <Chart
              options={options}
              series={series}
              type="heatmap"
              width="100%"
              height={450}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default TTPHeatmapSection;
