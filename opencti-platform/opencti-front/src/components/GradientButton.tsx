import React from 'react';
import { styled } from '@mui/material/styles';
import Button, { ButtonProps } from '@mui/material/Button';

interface GradientButtonProps extends ButtonProps {
  lightModeStartColor?: string;
  lightModeEndColor?: string;
  darkModeStartColor?: string;
  darkModeEndColor?: string;
  withShadow?: boolean;
}

const GradientButton = styled(Button, {
  shouldForwardProp: (prop) => !['lightModeStartColor', 'lightModeEndColor', 'darkModeStartColor', 'darkModeEndColor', 'withShadow'].includes(String(prop)),
})<GradientButtonProps>(({
  theme,
  lightModeStartColor = '#001BDA',
  lightModeEndColor = '#0FBCFF',
  darkModeStartColor = '#0FBCFF',
  darkModeEndColor = '#00F1BD',
  withShadow = true,
}) => {
  const isDarkMode = theme.palette.mode === 'dark';
  const startColor = isDarkMode ? darkModeStartColor : lightModeStartColor;
  const endColor = isDarkMode ? darkModeEndColor : lightModeEndColor;
  return {
    background: `
    linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
    linear-gradient(99.95deg, ${startColor} 0%, ${endColor} 100%) border-box
  `,
    border: '2px solid transparent',
    boxShadow: withShadow ? `1px 0px 4px -1px ${startColor}, -1px 0px 4px -1px ${endColor}` : 'none',
    transition: 'all 0.3s ease-in-out',
    '&:hover': {
      border: '2px solid transparent',
      boxShadow: withShadow ? `2px 0px 8px -1px ${startColor}, -2px 0px 8px -1px ${endColor}` : 'none',
      background: `
      linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
      linear-gradient(99.95deg, ${endColor} 0%, ${startColor} 100%) border-box
    `,
    },
    '&:active': {
      border: '2px solid transparent',
      boxShadow: withShadow ? `1px 0px 4px -1px ${startColor}, -1px 0px 4px -1px ${endColor}` : 'none',
    }
  };
});

export default GradientButton;
