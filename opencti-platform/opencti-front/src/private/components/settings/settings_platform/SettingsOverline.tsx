import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React, { ReactNode } from 'react';
import type { Theme } from '../../../../components/Theme';

interface SettingsOverlineProps {
  id?: string;
  children: ReactNode;
  count?: number;
  adornment?: ReactNode;
}

const SettingsOverline = ({ id, children, count, adornment }: SettingsOverlineProps) => {
  const theme = useTheme<Theme>();
  const textSx = {
    fontFamily: theme.typography.h1.fontFamily,
    fontSize: 11,
    fontWeight: 600,
    letterSpacing: '0.12em',
    lineHeight: '16px',
    textTransform: 'uppercase',
    color: theme.palette.text.secondary,
  } as const;
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, height: 24 }}>
      <Typography id={id} component="h6" sx={{ ...textSx, margin: 0 }}>{children}</Typography>
      {count !== undefined && (
        <Typography component="span" sx={{ ...textSx, color: theme.palette.text.disabled }}>{count}</Typography>
      )}
      {adornment}
    </Box>
  );
};

export default SettingsOverline;
