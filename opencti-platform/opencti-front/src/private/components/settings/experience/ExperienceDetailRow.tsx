import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface ExperienceDetailRowProps {
  label: ReactNode;
  divider?: boolean;
  children: ReactNode;
}

/**
 * Label / value row used in the Filigran Experience cards to display license
 * and connection details, with a subtle theme-aware separator. Aligned with
 * OpenAEV.
 */
const ExperienceDetailRow = ({ label, divider = true, children }: ExperienceDetailRowProps) => {
  const theme = useTheme<Theme>();

  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 2,
      paddingY: 1.25,
      borderBottom: divider ? `1px solid ${alpha(theme.palette.text?.primary ?? '#ffffff', 0.08)}` : 'none',
    }}
    >
      {typeof label === 'string'
        ? <Typography variant="body2" color="textSecondary">{label}</Typography>
        : label}
      {children}
    </Box>
  );
};

export default ExperienceDetailRow;
