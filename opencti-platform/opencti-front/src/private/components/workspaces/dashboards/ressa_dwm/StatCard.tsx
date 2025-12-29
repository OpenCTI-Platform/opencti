import React from 'react';
import { Card, CardContent, Box, Typography } from '@mui/material';
import { ArrowUpward, ArrowDownward } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

interface StatCardProps {
  title: string;
  value: number;
  change: number;
  icon: React.ReactNode;
  isPositive: boolean;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, change, icon, isPositive }) => {
  const theme = useTheme<Theme>();
  const isDark = theme.palette.mode === 'dark';
  
  const changeColor = isPositive 
    ? (isDark ? '#f44336' : '#d32f2f')
    : (isDark ? '#66bb6a' : '#2e7d32');
  const changeBgColor = isPositive
    ? (isDark ? 'rgba(244, 67, 54, 0.2)' : '#ffebee')
    : (isDark ? 'rgba(102, 187, 106, 0.2)' : '#e8f5e9');

  return (
    <Card
      variant="outlined"
      sx={{
        height: '100%',
        position: 'relative',
        backgroundColor: theme.palette.background?.paper || theme.palette.background?.default,
      }}
    >
      <CardContent sx={{ padding: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
          {/* Icon on the left */}
          <Box
            sx={{
              color: theme.palette.text?.secondary,
              marginInlineEnd: 2,
              display: 'flex',
              alignItems: 'center',
              flexShrink: 0,
            }}
          >
            <Box sx={{ fontSize: '2.5rem' }}>
              {icon}
            </Box>
          </Box>
          {/* Content on the right - two rows */}
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            {/* First row: Title */}
            <Typography
              variant="body2"
              sx={{
                color: theme.palette.text?.secondary,
                fontWeight: 500,
                fontSize: '0.875rem',
                marginBottom: 1.5,
              }}
            >
              {title}
            </Typography>
            {/* Second row: Value and change percentage */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Typography
                variant="h4"
                sx={{
                  fontWeight: 600,
                  color: theme.palette.text?.primary,
                  fontSize: '1.2rem',
                }}
              >
                {value.toLocaleString()}
              </Typography>
              <Box
                sx={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  padding: '4px 8px',
                  borderRadius: '12px',
                  backgroundColor: changeBgColor,
                  color: changeColor,
                  fontSize: '0.75rem',
                  fontWeight: 500,
                }}
              >
                {Math.abs(change)}%
                {isPositive ? (
                  <ArrowUpward sx={{ fontSize: '0.875rem', marginInlineStart: 0.5 }} />
                ) : (
                  <ArrowDownward sx={{ fontSize: '0.875rem', marginInlineStart: 0.5 }} />
                )}
              </Box>
            </Box>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default StatCard;

