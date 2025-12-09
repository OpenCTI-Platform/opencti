import type { Theme } from '@mui/material/styles';
import { GradientColor } from './Button.types';

export const createGradientSx = (
  theme: Theme,
  gradientColors: GradientColor,
  gradientAngle: number,
  options: { hover?: boolean; active?: boolean } = {}
) => {
  const { hover = false, active = false } = options;
  const bgColor = theme.palette?.background?.paper || '#1a2332';
  
  const gradientStr = `linear-gradient(${gradientAngle}deg, ${gradientColors.start} 0%, ${gradientColors.end} 100%)`;

  const baseStyle = {
    border: '2px solid transparent',
    background: `linear-gradient(${bgColor}, ${bgColor}) padding-box, ${gradientStr} border-box`,
    transition: 'box-shadow 0.3s ease-out',
  };

  // Add box-shadow glow only on hover/active
  if (hover || active) {
    const shadowY = active ? 2 : 0;
    const blur = active ? 8 : 6;
    
    return {
      ...baseStyle,
      boxShadow: `1px ${shadowY}px ${blur}px -1px ${gradientColors.start}, -1px ${shadowY}px ${blur}px -1px ${gradientColors.end}`,
    };
  }

  return {
    ...baseStyle,
    boxShadow: 'none',
  };
};

export const createTextGradientSx = (
  gradientColors: { start: string; end: string },
  gradientAngle: number
) => {
  const gradientStr = `linear-gradient(${gradientAngle}deg, ${gradientColors.start} 0%, ${gradientColors.end} 100%)`;
  
  return {
    background: gradientStr,
    color: 'transparent',
    backgroundClip: 'text',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    '& svg': {
      fill: gradientColors.start,
      color: gradientColors.start,
    },
  };
};

export const getDisabledSx = (theme: Theme) => ({
  backgroundColor: theme.palette.action?.disabledBackground ?? '#363B46',
  color: theme.palette.action?.disabled ?? '#363B46',
});

export const getButtonContentSx = () => ({
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: '4px',
});