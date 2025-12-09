import { Theme } from '@mui/material';
import type { ButtonIntent, GradientVariant, ColorDefinition, GradientColor } from './Button.types';

export const getColorDefinitions = (theme: Theme): Record<ButtonIntent, ColorDefinition> => {
  return { 
    default: {
      main: theme.palette.primary.main,
      hover: theme.palette.primary.dark,
      focus: theme.palette.text.primary,
      text: theme.palette.primary.contrastText,
      border: theme.palette.primary.main,
      borderColor: theme.palette?.border?.main ?? '#252A35'
    },
    destructive: {
      main: theme.palette.error.main,
      hover: theme.palette.error.dark,
      focus: theme.palette.text.primary,
      text: theme.palette.error.main,
      border: theme.palette.error.main,
      borderColor: theme.palette?.border?.main ?? '#252A35'
    },
    ai: {
      main: theme.palette.ai?.main ?? '#B286FF',
      hover: theme.palette?.ai?.dark ?? '#B286FF',
      focus: theme.palette?.ai?.main ?? '#B286FF',
      text: theme.palette.ai?.contrastText ?? '#B286FF',
      border: theme.palette?.ai?.light ?? '#B286FF',
      borderColor: '#252A35'
    },
  };
};

export const getGradientColors = (
  theme: Theme,
  gradient: boolean,
  gradientVariant: GradientVariant,
  currentColor: ColorDefinition,
  customStartColor?: string,
  customEndColor?: string
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

