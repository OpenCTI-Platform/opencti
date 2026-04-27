import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import Chart from '@components/common/charts/Chart';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import type { ApexOptions } from 'apexcharts';

interface GaugeCardProps {
  title: string;
  description: string;
  value: number;
  maxValue: number;
  unit?: string;
  colors: string[]; // Array of colors for gradient
  labels: string[]; // Labels for the gauge segments (right to left in RTL)
}

const GaugeCard: React.FC<GaugeCardProps> = ({
  title,
  description,
  value,
  maxValue,
  unit = '',
  colors,
  labels,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const percentage = (value / maxValue) * 100;

  // Create gradient stops for colors
  const gradientStops = colors.map((_, index) => 
    Math.round((index / (colors.length - 1)) * 100)
  );

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
      <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 3, position: 'relative' }}>
        {/* Menu Icon */}
        <IconButton
          size="small"
          sx={{
            position: 'absolute',
            top: 8,
            right: 8,
            color: 'text.secondary',
          }}
          onClick={(e) => {
            e.stopPropagation();
            // TODO: Implement menu functionality
          }}
        >
          <MoreVert fontSize="small" />
        </IconButton>

        {/* Title */}
        <Typography
          variant="h6"
          sx={{
            fontWeight: 600,
            marginBottom: 1,
            color: 'text.primary',
            fontSize: '1rem',
            paddingInlineEnd: 4, // Space for menu icon
          }}
        >
          {t_i18n(title)}
        </Typography>

        {/* Description */}
        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            marginBottom: 3,
            fontSize: '0.875rem',
            lineHeight: 1.5,
          }}
        >
          {t_i18n(description)}
        </Typography>

        {/* Gauge Chart */}
        <Box sx={{ display: 'flex', justifyContent: 'center', marginBottom: 2 }}>
            <Chart
              options={{
                plotOptions: {
                  radialBar: {
                    startAngle: -90,
                    endAngle: 90,
                    hollow: {
                      margin: 0,
                      size: '70%',
                      background: 'transparent',
                    },
                    track: {
                      show: true,
                      background: theme.palette.divider,
                      strokeWidth: '97%',
                      margin: 5,
                    },
                    dataLabels: {
                      name: {
                        show: false,
                      },
                      value: {
                        show: true,
                        fontSize: '30px',
                        fontWeight: 700,
                        offsetY: 0,
                        color: theme.palette.text?.primary,
                        formatter: (val: number) => {
                          return `${Math.round((val / 100) * maxValue)}${unit}`;
                        },
                      },
                    },
                  },
                },
                fill: {
                  type: 'gradient',
                  gradient: {
                    shade: 'dark',
                    type: 'horizontal',
                    shadeIntensity: 0.5,
                    gradientToColors: colors,
                    inverseColors: true,
                    opacityFrom: 1,
                    opacityTo: 1,
                    stops: gradientStops,
                  },
                },
                stroke: {
                  lineCap: 'round',
                },
              }}
              series={[percentage]}
              type="radialBar"
              width="100%"
              height={200}
            />
        </Box>

        {/* Labels */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginTop: 'auto',
            flexDirection: 'row', // LTR
          }}
        >
          {labels.map((label, index) => (
            <Typography
              key={index}
              variant="body2"
              sx={{
                fontSize: '0.75rem',
                color: 'text.secondary',
                fontWeight: 500,
              }}
            >
              {t_i18n(label)}
            </Typography>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
};

export default GaugeCard;
