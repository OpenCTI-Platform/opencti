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
import type { ApexOptions } from 'apexcharts';

// =====================================================
// 1. National Threat Heatmap
// =====================================================

interface ProvinceData {
  name: string;
  value: number;
  color: string;
}

const PROVINCES: ProvinceData[] = [
  { name: 'Tehran', value: 30, color: '#d32f2f' },
  { name: 'Khuzestan', value: 15, color: '#e65100' },
  { name: 'Bushehr', value: 10, color: '#ef6c00' },
  { name: 'Isfahan', value: 8, color: '#f9a825' },
  { name: 'Fars', value: 7, color: '#f9a825' },
  { name: 'Markazi', value: 6, color: '#fbc02d' },
  { name: 'Hormozgan', value: 5, color: '#cddc39' },
  { name: 'Alborz', value: 5, color: '#cddc39' },
  { name: 'East Azerbaijan', value: 4, color: '#66bb6a' },
  { name: 'West Azerbaijan', value: 4, color: '#66bb6a' },
  { name: 'Khorasan Razavi', value: 3, color: '#66bb6a' },
  { name: 'Mazandaran', value: 2, color: '#43a047' },
  { name: 'Sistan-Baluchestan', value: 1, color: '#2e7d32' },
  { name: 'Kerman', value: 1, color: '#2e7d32' },
];

const NationalThreatHeatmapCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const treemapSeries = [
    {
      data: PROVINCES.map((p) => ({
        x: t_i18n(p.name),
        y: p.value,
      })),
    },
  ];

  const treemapOptions: ApexOptions = useMemo(() => ({
    chart: {
      type: 'treemap',
      background: 'transparent',
      toolbar: { show: false },
      foreColor: theme.palette.text.secondary,
    },
    theme: { mode: theme.palette.mode },
    colors: ['#d32f2f'],
    plotOptions: {
      treemap: {
        distributed: false,
        enableShades: true,
        shadeIntensity: 0.5,
        colorScale: {
          ranges: [
            { from: 0, to: 3, color: '#43a047', name: t_i18n('Low') },
            { from: 4, to: 6, color: '#cddc39', name: t_i18n('Medium') },
            { from: 7, to: 10, color: '#f9a825', name: t_i18n('High') },
            { from: 11, to: 20, color: '#ef6c00', name: t_i18n('Very High') },
            { from: 21, to: 50, color: '#d32f2f', name: t_i18n('Critical') },
          ],
        },
      },
    },
    dataLabels: {
      enabled: true,
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    legend: {
      show: true,
      position: 'bottom',
      fontSize: '10px',
    },
    tooltip: {
      theme: theme.palette.mode,
    },
  }), [theme]);

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
          {t_i18n('National Threat Heatmap')}
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
          {t_i18n('Geographical and sectoral distribution of threats and hotspots targeted by state-sponsored APTs. Confidence and impact are used to display heat intensity.')}
        </Typography>

        <Box sx={{ display: 'flex', gap: 2, flex: 1 }}>
          {/* Treemap (map representation) */}
          <Box sx={{ flex: 1, minHeight: 320 }}>
            <Chart
              options={treemapOptions}
              series={treemapSeries}
              type="treemap"
              width="100%"
              height={320}
            />
          </Box>

          {/* Province ranking sidebar */}
          <Box
            sx={{
              minWidth: 180,
              maxWidth: 200,
              display: 'flex',
              flexDirection: 'column',
              gap: 0.3,
              overflowY: 'auto',
            }}
          >
            {PROVINCES.map((province) => (
              <Box
                key={province.name}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                  paddingY: 0.4,
                }}
              >
                <Box
                  sx={{
                    width: 10,
                    height: 10,
                    borderRadius: '2px',
                    backgroundColor: province.color,
                    flexShrink: 0,
                  }}
                />
                <Typography
                  variant="caption"
                  sx={{
                    color: 'text.primary',
                    fontSize: '0.72rem',
                    flex: 1,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {t_i18n(province.name)}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
                    color: 'text.secondary',
                    fontSize: '0.72rem',
                    fontWeight: 600,
                  }}
                >
                  {province.value}
                </Typography>
              </Box>
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. Targeted Industries (Bubble / Packed Circle Chart)
// =====================================================

interface IndustryBubble {
  name: string;
  value: number;
  color: string;
  size: number; // relative size factor
}

const INDUSTRIES: IndustryBubble[] = [
  { name: 'Ministry of Communications', value: 20, color: '#e65100', size: 1 },
  { name: 'Banks', value: 17, color: '#5c6bc0', size: 0.82 },
  { name: 'Broadcasting', value: 10, color: '#ef6c00', size: 0.55 },
  { name: 'Ministry of Defense', value: 13, color: '#c62828', size: 0.65 },
  { name: 'Oil & Gas', value: 6, color: '#fdd835', size: 0.35 },
  { name: 'Ministry of Education', value: 4, color: '#ec407a', size: 0.28 },
  { name: 'Other', value: 5, color: '#9e9e9e', size: 0.3 },
];

const TargetedIndustriesCard: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  // Use a bubble chart with ApexCharts
  const series = INDUSTRIES.map((ind) => ({
    name: t_i18n(ind.name),
    data: [
      {
        x: t_i18n(ind.name),
        y: ind.value,
        z: ind.value,
      },
    ],
  }));

  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'bubble',
      background: 'transparent',
      toolbar: { show: false },
      foreColor: theme.palette.text.secondary,
    },
    theme: { mode: theme.palette.mode },
    colors: INDUSTRIES.map((i) => i.color),
    dataLabels: {
      enabled: true,
      formatter: (val: number) => `${val}`,
      style: {
        fontSize: '14px',
        fontWeight: '700',
        fontFamily: '"IBM Plex Sans", sans-serif',
        colors: ['#fff'],
      },
    },
    xaxis: {
      labels: { show: false },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    yaxis: {
      labels: { show: false },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    grid: { show: false },
    legend: {
      show: true,
      position: 'top',
      horizontalAlign: 'center',
      fontSize: '10px',
      markers: { size: 6, shape: 'circle' },
      itemMargin: { horizontal: 6, vertical: 4 },
    },
    tooltip: {
      theme: theme.palette.mode,
      y: { formatter: (val: number) => `${val} attacks` },
    },
    plotOptions: {
      bubble: {
        zScaling: true,
        minBubbleRadius: 30,
      },
    },
    fill: { opacity: 0.85 },
  }), [theme]);

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
          {t_i18n('Targeted Industries of the Country')}
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
          {t_i18n('Industries targeted and attacked by state-sponsored APTs including ministries, banks and energy sector')}
        </Typography>

        {/* Packed Circles Visualization */}
        <Box
          sx={{
            flex: 1,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            position: 'relative',
            minHeight: 350,
          }}
        >
          {/* Custom CSS circles for the packed bubble layout */}
          <Box
            sx={{
              position: 'relative',
              width: '100%',
              height: 350,
            }}
          >
            {/* Largest: Ministry of Communications - 20 */}
            <Box
              sx={{
                position: 'absolute',
                left: '2%',
                top: '10%',
                width: 180,
                height: 180,
                borderRadius: '50%',
                backgroundColor: '#e65100',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '1.8rem' }}>20</Typography>
            </Box>

            {/* Banks - 17 */}
            <Box
              sx={{
                position: 'absolute',
                left: '32%',
                top: '5%',
                width: 155,
                height: 155,
                borderRadius: '50%',
                backgroundColor: '#5c6bc0',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '1.6rem' }}>17</Typography>
            </Box>

            {/* Ministry of Defense - 13 */}
            <Box
              sx={{
                position: 'absolute',
                left: '22%',
                top: '55%',
                width: 130,
                height: 130,
                borderRadius: '50%',
                backgroundColor: '#c62828',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '1.4rem' }}>13</Typography>
            </Box>

            {/* Broadcasting - 10 */}
            <Box
              sx={{
                position: 'absolute',
                left: '55%',
                top: '15%',
                width: 110,
                height: 110,
                borderRadius: '50%',
                backgroundColor: '#ef6c00',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '1.3rem' }}>10</Typography>
            </Box>

            {/* Oil & Gas - 6 */}
            <Box
              sx={{
                position: 'absolute',
                left: '55%',
                top: '55%',
                width: 80,
                height: 80,
                borderRadius: '50%',
                backgroundColor: '#fdd835',
                opacity: 0.9,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#333', fontWeight: 700, fontSize: '1.1rem' }}>6</Typography>
            </Box>

            {/* Other - 5 */}
            <Box
              sx={{
                position: 'absolute',
                left: '72%',
                top: '40%',
                width: 70,
                height: 70,
                borderRadius: '50%',
                backgroundColor: '#9e9e9e',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '1rem' }}>5</Typography>
            </Box>

            {/* Ministry of Education - 4 */}
            <Box
              sx={{
                position: 'absolute',
                left: '70%',
                top: '60%',
                width: 60,
                height: 60,
                borderRadius: '50%',
                backgroundColor: '#ec407a',
                opacity: 0.85,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Typography sx={{ color: '#fff', fontWeight: 700, fontSize: '0.95rem' }}>4</Typography>
            </Box>
          </Box>
        </Box>

        {/* Legend */}
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'center',
            gap: 1.5,
            marginTop: 1,
          }}
        >
          {INDUSTRIES.map((ind) => (
            <Box key={ind.name} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  backgroundColor: ind.color,
                }}
              />
              <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>
                {t_i18n(ind.name)}
              </Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const GeoThreatSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12} md={6}>
        <NationalThreatHeatmapCard />
      </Grid>
      <Grid item xs={12} md={6}>
        <TargetedIndustriesCard />
      </Grid>
    </Grid>
  );
};

export default GeoThreatSection;
