import React from 'react';
import Button, { ButtonProps } from '@mui/material/Button';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';

// Only 'xtmhub' is supported for now
type GradientVariant = 'xtmhub';

interface GradientButtonProps extends ButtonProps {
  gradientVariant?: GradientVariant;
  target?: string;
}

const GradientButton: React.FunctionComponent<GradientButtonProps> = ({
  gradientVariant = 'xtmhub',
  sx,
  ...props
}) => {
  const theme = useTheme<Theme>();

  let startColor;
  let endColor;
  switch (gradientVariant) {
    case 'xtmhub':
    default:
      startColor = theme.palette.xtmhub.main;
      endColor = theme.palette.xtmhub.light;
      break;
  }

  return (
    <Button
      sx={{
        background: `
          linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
          linear-gradient(99.95deg, ${startColor} 0%, ${endColor} 100%) border-box
        `,
        border: '2px solid transparent',
        boxShadow: `1px 0px 4px -1px ${startColor}, -1px 0px 4px -1px ${endColor}`,
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          border: '2px solid transparent',
          boxShadow: `2px 0px 8px -1px ${startColor}, -2px 0px 8px -1px ${endColor}`,
          background: `
            linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
            linear-gradient(99.95deg, ${endColor} 0%, ${startColor} 100%) border-box
          `,
        },
        '&:active': {
          border: '2px solid transparent',
          boxShadow: `1px 0px 4px -1px ${startColor}, -1px 0px 4px -1px ${endColor}`,
        },
        ...sx,
      }}
      {...props}
    />
  );
};

export default GradientButton;
