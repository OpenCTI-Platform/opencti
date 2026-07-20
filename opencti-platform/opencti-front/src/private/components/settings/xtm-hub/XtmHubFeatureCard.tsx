import { Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import type React from 'react';
import type { ReactNode } from 'react';
import type { Theme } from 'src/components/Theme';

interface XtmHubFeatureCardProps {
  icon: ReactNode;
  label: string;
}

const XtmHubFeatureCard: React.FC<XtmHubFeatureCardProps> = ({ icon, label }) => {
  const theme = useTheme<Theme>();

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: theme.spacing(1),
        padding: theme.spacing(2),
        borderRadius: 8,
        backgroundColor: theme.palette.background.accent,
      }}
    >
      {icon}
      <Typography
        variant="body2"
        align="center"
        sx={{
          color: theme.palette.text.primary,
          fontWeight: theme.typography.fontWeightMedium,
        }}
      >
        {label}
      </Typography>
    </div>
  );
};

export default XtmHubFeatureCard;
