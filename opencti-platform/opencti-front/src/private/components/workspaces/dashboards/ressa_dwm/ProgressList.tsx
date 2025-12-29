import React from 'react';
import { Box, Typography, LinearProgress } from '@mui/material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';

interface ProgressListProps {
  items: { name: string; value: number }[];
}

const ProgressList: React.FC<ProgressListProps> = ({ items }) => {
  const theme = useTheme<Theme>();
  const maxValue = Math.max(...items.map((item) => item.value));

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {items.map((item, index) => (
        <Box key={index}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 0.5 }}>
            <Typography variant="body2" sx={{ fontSize: '0.875rem', color: theme.palette.text?.secondary }}>
              {item.name}
            </Typography>
            <Typography variant="body2" sx={{ fontSize: '0.875rem', fontWeight: 600, color: theme.palette.text?.primary }}>
              {item.value}
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(item.value / maxValue) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: theme.palette.mode === 'dark' 
                ? 'rgba(255, 255, 255, 0.1)' 
                : 'rgba(0, 0, 0, 0.08)',
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor: theme.palette.primary?.main || '#1976d2',
              },
            }}
          />
        </Box>
      ))}
    </Box>
  );
};

export default ProgressList;

