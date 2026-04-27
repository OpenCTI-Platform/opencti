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
import { lineChartOptions } from '../../../../../../utils/Charts';
import type { ApexOptions } from 'apexcharts';

const MONTHS = [
  'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
  'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar',
];

const INCIDENT_TYPES = [
  { name: 'Data Breach', color: '#1a237e' },
  { name: 'Ransomware Attack', color: '#3949ab' },
  { name: 'Phishing Attack', color: '#5c6bc0' },
  { name: 'Server Intrusion', color: '#7986cb' },
  { name: 'System Downtime', color: '#9fa8da' },
  { name: 'Threat to Data Publication', color: '#c5cae9' },
];

// Generate realistic-looking fluctuating data
const generateData = (base: number, variance: number): number[] => {
  const data: number[] = [];
  let current = base;
  for (let i = 0; i < 12; i++) {
    current = base + Math.round((Math.random() - 0.5) * variance * 2);
    current = Math.max(100, Math.min(1000, current));
    data.push(current);
  }
  return data;
};

const HacktivistActivitySection: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const categories = MONTHS.map((m) => t_i18n(m));

  const series = useMemo(() => [
    {
      name: t_i18n('Data Breach'),
      data: [750, 720, 780, 690, 710, 650, 680, 620, 600, 580, 550, 520],
    },
    {
      name: t_i18n('Ransomware Attack'),
      data: [680, 650, 700, 630, 660, 600, 620, 580, 560, 540, 500, 480],
    },
    {
      name: t_i18n('Phishing Attack'),
      data: [600, 580, 620, 560, 590, 550, 540, 510, 490, 470, 440, 420],
    },
    {
      name: t_i18n('Server Intrusion'),
      data: [500, 480, 520, 460, 490, 450, 440, 420, 400, 380, 360, 340],
    },
    {
      name: t_i18n('System Downtime'),
      data: [420, 400, 440, 380, 410, 370, 360, 350, 330, 310, 300, 280],
    },
    {
      name: t_i18n('Threat to Data Publication'),
      data: [350, 330, 370, 310, 340, 300, 290, 280, 260, 250, 240, 220],
    },
  ], [t_i18n]);

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
      colors: INCIDENT_TYPES.map((t) => t.color),
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
            fontSize: '11px',
            fontFamily: '"IBM Plex Sans", sans-serif',
            colors: theme.palette.text.secondary,
          },
        },
      },
      yaxis: {
        ...base.yaxis,
        min: 0,
        max: 1000,
        tickAmount: 5,
        labels: {
          style: {
            fontSize: '11px',
            fontFamily: '"IBM Plex Sans", sans-serif',
          },
        },
        axisBorder: { show: false },
      },
      stroke: {
        curve: 'smooth',
        width: 2,
      },
      legend: {
        show: true,
        position: 'top',
        horizontalAlign: 'right',
        fontSize: '11px',
        markers: { size: 6, shape: 'circle' },
        itemMargin: { horizontal: 10, vertical: 4 },
      },
      tooltip: { ...base.tooltip, enabled: true },
    };
  }, [theme, categories]);

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
            {t_i18n('Hacktivist Activity Count')}
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
            {t_i18n('Real-time count of incidents related to intelligence operations, data theft, sabotage with a visual approach to identifying increased attacker activity')}
          </Typography>

          <Box sx={{ width: '100%', minHeight: 350 }}>
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
    </Box>
  );
};

export default HacktivistActivitySection;
