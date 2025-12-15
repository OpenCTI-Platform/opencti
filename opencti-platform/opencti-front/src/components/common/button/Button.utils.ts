import { Theme } from '@mui/material';
import type { GradientVariant, ColorDefinition, GradientColor, ButtonSize, ButtonColorKey } from './Button.types';

export const getColorDefinitions = (theme: Theme): Record<ButtonColorKey, ColorDefinition> => {
  return {
    default: {
      main: theme.palette.primary.main,
      hover: theme.palette.primary.dark,
      focus: theme.palette.text.primary,
      text: theme.palette.primary.contrastText,
      border: theme.palette.primary.main,
      borderColor: theme.palette?.border?.main ?? '#252A35',
    },
    destructive: {
      main: theme.palette.error.main,
      hover: theme.palette.error.dark,
      focus: theme.palette.text.primary,
      text: theme.palette.error.main,
      border: theme.palette.error.main,
      borderColor: theme.palette?.border?.main ?? '#252A35',
    },
    ai: {
      main: theme.palette.ai?.main ?? '#B286FF',
      hover: theme.palette?.ai?.dark ?? '#B286FF',
      focus: theme.palette?.ai?.main ?? '#B286FF',
      text: theme.palette.ai?.contrastText ?? '#B286FF',
      border: theme.palette?.ai?.light ?? '#B286FF',
      borderColor: '#252A35',
    },
    primary: {
      main: theme.palette.primary.main,
      hover: theme.palette.primary.dark,
      focus: theme.palette.primary.light,
      text: theme.palette.primary.contrastText,
      border: theme.palette.primary.main,
      borderColor: theme.palette.primary.main,
    },
    secondary: {
      main: theme.palette.secondary.main,
      hover: theme.palette.secondary.dark,
      focus: theme.palette.secondary.light,
      text: theme.palette.secondary.contrastText,
      border: theme.palette.secondary.main,
      borderColor: theme.palette.secondary.main,
    },
    success: {
      main: theme.palette.success.main,
      hover: theme.palette.success.dark,
      focus: theme.palette.success.light,
      text: theme.palette.success.contrastText,
      border: theme.palette.success.main,
      borderColor: theme.palette.success.main,
    },
    error: {
      main: theme.palette.error.main,
      hover: theme.palette.error.dark,
      focus: theme.palette.error.light,
      text: theme.palette.error.contrastText,
      border: theme.palette.error.main,
      borderColor: theme.palette.error.main,
    },
    warning: {
      main: theme.palette.warning.main,
      hover: theme.palette.warning.dark,
      focus: theme.palette.warning.light,
      text: theme.palette.warning.contrastText,
      border: theme.palette.warning.main,
      borderColor: theme.palette.warning.main,
    },
    info: {
      main: theme.palette.info.main,
      hover: theme.palette.info.dark,
      focus: theme.palette.info.light,
      text: theme.palette.info.contrastText,
      border: theme.palette.info.main,
      borderColor: theme.palette.info.main,
    },
  };
};

export const getGradientColors = (
  theme: Theme,
  gradient: boolean,
  gradientVariant: GradientVariant,
  currentColor: ColorDefinition,
  customStartColor?: string,
  customEndColor?: string,
): GradientColor => {
  if (!gradient) {
    return { start: '', end: '' };
  }

  if (customStartColor && customEndColor) {
    return {
      start: customStartColor,
      end: customEndColor,
    };
  }

  switch (gradientVariant) {
    case 'ai':
      return {
        start: theme.palette?.ai?.light || '#7C4DFF',
        end: theme.palette?.ai?.dark || '#6339D1',
      };
    case 'disabled':
      return {
        start: theme.palette?.action?.disabled || '#666666',
        end: theme.palette?.action?.disabled || '#666666',
      };
    case 'default':
    default:
      return {
        start: theme.palette?.primary?.main || currentColor.main,
        end: theme.palette?.gradient?.main || currentColor.focus,
      };
  }
};

export const createGradientSx = (
  theme: Theme,
  gradientColors: GradientColor,
  gradientAngle: number,
  options: { hover?: boolean; active?: boolean } = {},
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
  gradientColors: GradientColor,
  gradientAngle: number,
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

export const getSizeConfig = (theme: Theme, size: ButtonSize, iconOnly: boolean) => {
  const config = theme.button.sizes[size];

  return {
    ...config,
    padding: iconOnly ? '0' : config.padding,
    minWidth: iconOnly ? config.minWidth : '64px',
    width: iconOnly ? config.width : 'auto',
  };
};
