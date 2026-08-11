import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface ExperienceFeatureTileProps {
  icon: ReactNode;
  label: string;
  accent?: string;
}

/**
 * Icon + label tile used in the Filigran Experience cards to showcase
 * capabilities (Enterprise Edition features, XTM Hub content). A tinted
 * rounded icon box sits next to the label, aligned with OpenAEV.
 */
const ExperienceFeatureTile = ({ icon, label, accent }: ExperienceFeatureTileProps) => {
  const theme = useTheme<Theme>();
  const color = accent ?? theme.palette.primary.main ?? '#ffffff';

  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      gap: 1,
      padding: 1,
      borderRadius: 1,
      border: `1px solid ${alpha(theme.palette.text?.primary ?? '#ffffff', 0.08)}`,
    }}
    >
      <Box sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 30,
        height: 30,
        borderRadius: 1,
        flexShrink: 0,
        color: color,
        background: alpha(color, 0.1),
        boxShadow: `inset 0 0 12px ${alpha(color, 0.13)}`,
        '& svg': { fontSize: 16 },
      }}
      >
        {icon}
      </Box>
      <Typography sx={{
        fontSize: 12,
        fontWeight: 500,
        lineHeight: 1.3,
        color: 'text.primary',
      }}
      >
        {label}
      </Typography>
    </Box>
  );
};

export default ExperienceFeatureTile;
