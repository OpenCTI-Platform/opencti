import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React, { ReactNode } from 'react';
import type { Theme } from '../../../../components/Theme';

interface SettingsInfoRowProps {
  label: ReactNode;
  children: ReactNode;
  divider?: boolean;
  // `field`: the 36 px of an input, for a setting row that sits among form fields.
  size?: 'default' | 'field';
  'data-testid'?: string;
}

const SettingsInfoRow = ({ label, children, divider = true, size = 'default', 'data-testid': testId }: SettingsInfoRowProps) => {
  const theme = useTheme<Theme>();
  return (
    <Box
      data-testid={testId}
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 2,
        height: size === 'field' ? 36 : 40,
        borderBottom: divider ? `1px solid ${theme.palette.divider}` : 'none',
      }}
    >
      <Typography
        variant="body1"
        component="div"
        sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0, whiteSpace: 'nowrap' }}
      >
        {label}
      </Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
        {children}
      </Box>
    </Box>
  );
};

export default SettingsInfoRow;
