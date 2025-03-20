import React from 'react';
import { ButtonProps, Button } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';

type GradientVariant = 'default';

interface GradientButtonProps extends ButtonProps {
  gradientVariant?: GradientVariant;
  target?: string;
}

const GradientButton = ({
  gradientVariant = 'default',
  children,
  sx,
  ...otherProps
}: GradientButtonProps) => {
  const theme = useTheme<Theme>();

  let startColor;
  let endColor;
  switch (gradientVariant) {
    case 'default':
    default:
      startColor = theme.palette.primary.main;
      endColor = theme.palette.gradient.main;
      break;
  }

  const gradient = (reverse = false) => {
    const color1 = reverse ? endColor : startColor;
    const color2 = reverse ? startColor : endColor;
    return `linear-gradient(99.95deg, ${color1} 0%, ${color2} 100%)`;
  };

  const bgGradientStyle = (opts?: {
    active?: boolean
    hover?: boolean
  }) => {
    const { active = false, hover = false } = opts ?? {};
    let shadowY = 0;
    let blur = 4;
    if (active) {
      shadowY = 2;
      blur = 8;
    }
    if (hover) {
      blur = 6;
    }

    return {
      border: '2px solid transparent',
      boxShadow: `1px ${shadowY}px ${blur}px -1px ${startColor}, -1px ${shadowY}px ${blur}px -1px ${endColor}`,
      background: `
        linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
        ${gradient(hover || active)} border-box
      `,
    };
  };

  const textGradientStyle = (reverse = false) => {
    return {
      background: gradient(),
      '&:hover': gradient(reverse),
      '&:active': gradient(reverse),
      color: 'transparent',
      backgroundClip: 'text',
    };
  };

  return (
    <Button
      {...otherProps}
      sx={{
        transition: 'all 0.3s ease-in-out',
        ...bgGradientStyle(),
        '.text': textGradientStyle(),
        '&:hover': bgGradientStyle({ hover: true }),
        '&:active': bgGradientStyle({ active: true }),
        ...sx,
      }}
    >
      <span className="text">{children}</span>
    </Button>
  );
};

export default GradientButton;
