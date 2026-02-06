import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
} from '@mui/material';
import { ArrowUp24Regular as ArrowUpIcon } from '@fluentui/react-icons';
import { useFormatter } from '../../../../../../components/i18n';

interface MetricCardProps {
  title: string;
  description: string;
  value: string;
  trend: number;
  trendLabel?: string;
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  description,
  value,
  trend,
  trendLabel,
}) => {
  const { t_i18n } = useFormatter();

  const isPositive = trend < 0; // Negative trend is positive (decrease in time is good)

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
      <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 3 }}>
        {/* Title */}
        <Typography
          variant="h6"
          sx={{
            fontWeight: 600,
            marginBottom: 1,
            color: 'text.primary',
            fontSize: '1rem',
          }}
        >
          {t_i18n(title)}
        </Typography>

        {/* Description */}
        <Typography
          variant="body2"
          sx={{
            color: 'text.secondary',
            marginBottom: 2,
            fontSize: '0.875rem',
            lineHeight: 1.5,
          }}
        >
          {t_i18n(description)}
        </Typography>

        {/* Value and Trend */}
        <Box sx={{ marginTop: 'auto', display: 'flex', alignItems: 'flex-end', gap: 1.5 }}>
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              color: 'text.primary',
              fontSize: '2.5rem',
              lineHeight: 1,
            }}
          >
            {value}
          </Typography>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.5,
              backgroundColor: isPositive ? 'success.lighter' : 'error.lighter',
              color: isPositive ? 'success.main' : 'error.main',
              padding: '4px 8px',
              borderRadius: 1,
              marginBottom: 0.5,
            }}
          >
            <ArrowUpIcon fontSize="small" />
            <Typography
              variant="body2"
              sx={{
                fontWeight: 600,
                fontSize: '0.875rem',
              }}
            >
              {Math.abs(trend)}%
            </Typography>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default MetricCard;
