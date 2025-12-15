import type { SxProps, Theme } from '@mui/material/styles';
import type { ColorDefinition, GradientColor, SizeConfig } from './Button.types';
import { getDisabledSx, createGradientSx, createTextGradientSx, getButtonContentSx } from './Button.utils';

interface StyleFactoryParams {
  theme: Theme;
  currentColor: ColorDefinition;
  gradientColors: GradientColor;
  gradientAngle: number;
  sizeConfig: SizeConfig;
}

// BASE STYLES
export const createBaseStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, currentColor, sizeConfig } = params;

  return {
    height: sizeConfig.height,
    padding: sizeConfig.padding,
    minWidth: sizeConfig.minWidth,
    width: sizeConfig.width,
    fontSize: sizeConfig.fontSize,
    fontWeight: sizeConfig.fontWeight,
    lineHeight: sizeConfig.lineHeight,
    textTransform: 'none',
    borderRadius: `${theme.shape.borderRadius}px`,
    transition: 'all 0.2s ease-in-out',
    fontFamily: theme.typography.fontFamily,

    '& .MuiButton-startIcon, & .MuiButton-endIcon': {
      '& > *:nth-of-type(1)': {
        fontSize: sizeConfig.iconSize,
      },
    },

    '&:focus-visible': {
      outline: 'none',
      boxShadow: `0 0 0 2px ${currentColor.focus}`,
    },

    '&.Mui-disabled': getDisabledSx(theme),
  };
};

// PRIMARY VARIANT
export const createPrimaryGradientStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, gradientColors, gradientAngle } = params;

  return {
    ...createGradientSx(theme, gradientColors, gradientAngle),

    '& .button-content': {
      ...createTextGradientSx(gradientColors, gradientAngle),
      ...getButtonContentSx(),
    },

    '&:hover': createGradientSx(theme, gradientColors, gradientAngle, { hover: true }),

    '&:active': createGradientSx(theme, gradientColors, gradientAngle, { active: true }),

    '&.Mui-disabled': getDisabledSx(theme),
  };
};

export const createPrimarySolidStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, currentColor } = params;

  return {
    backgroundColor: currentColor.main,
    color: currentColor.text,

    '&:hover': {
      backgroundColor: currentColor.hover,
    },

    '&.Mui-disabled': getDisabledSx(theme),
  };
};

// SECONDARY VARIANT
export const createSecondaryGradientStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, gradientColors, gradientAngle } = params;

  return {
    ...createGradientSx(theme, gradientColors, gradientAngle),
    backgroundColor: 'transparent',
    transition: 'box-shadow 0.3s ease-out, background-color 0.2s ease-out',

    '& .button-content': {
      ...createTextGradientSx(gradientColors, gradientAngle),
      ...getButtonContentSx(),
    },

    '&:hover': {
      ...createGradientSx(theme, gradientColors, gradientAngle, { hover: true }),
      backgroundColor: 'transparent',
    },

    '&:active': {
      ...createGradientSx(theme, gradientColors, gradientAngle, { active: true }),
      backgroundColor: 'transparent',
    },

    '&.Mui-disabled': {
      opacity: 0.4,
    },
  };
};

export const createSecondarySolidStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, currentColor } = params;

  return {
    backgroundColor: 'transparent',
    color: currentColor.main,
    border: `1px solid ${currentColor.border}`,
    boxShadow: 'none',

    '&:hover': {
      backgroundColor: `${currentColor.main}15`,
    },

    '&:active': {
      backgroundColor: `${currentColor.main}25`,
      boxShadow: 'none',
    },

    '&.Mui-disabled': {
      ...getDisabledSx(theme),
      backgroundColor: 'transparent',
      borderColor: theme.palette.border?.main ?? '#252A35',
    },
  };
};

// TERTIARY VARIANT
export const createTertiaryGradientStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, gradientColors, gradientAngle } = params;

  return {
    backgroundColor: 'transparent',
    border: 'none',
    boxShadow: 'none',
    transition: 'background-color 0.2s ease-out',

    '& .button-content': {
      ...createTextGradientSx(gradientColors, gradientAngle),
      ...getButtonContentSx(),
    },

    '&:hover': {
      backgroundColor: `${gradientColors.start}15`,
    },

    '&:active': {
      backgroundColor: `${gradientColors.start}25`,
    },

    '&.Mui-disabled': {
      ...getDisabledSx(theme),
      transition: 'none',
    },
  };
};

export const createTertiarySolidStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, currentColor } = params;

  return {
    backgroundColor: 'transparent',
    color: currentColor.main,
    border: 'none',
    boxShadow: 'none',

    '&:hover': {
      backgroundColor: `${currentColor.main}15`,
      color: currentColor.hover,
      boxShadow: 'none',
    },

    '&:active': {
      backgroundColor: `${currentColor.main}15`,
      borderColor: currentColor.focus,
      boxShadow: `0 0 0 2px ${currentColor.focus}40`,
    },

    '&.Mui-disabled': {
      ...getDisabledSx(theme),
      backgroundColor: 'transparent',
    },
  };
};

// EXTRA VARIANT
export const createExtraStyles = (params: StyleFactoryParams): SxProps<Theme> => {
  const { theme, gradientColors, gradientAngle } = params;

  return {
    ...createGradientSx(theme, gradientColors, gradientAngle),
    backgroundColor: 'transparent',
    transition: 'box-shadow 0.3s ease-out, background-color 0.2s ease-out',

    '& .button-content': {
      ...createTextGradientSx(gradientColors, gradientAngle),
      ...getButtonContentSx(),
    },

    '&:hover': {
      ...createGradientSx(theme, gradientColors, gradientAngle, { hover: true }),
      backgroundColor: 'transparent',
    },

    '&:active': {
      ...createGradientSx(theme, gradientColors, gradientAngle, { active: true }),
      backgroundColor: 'transparent',
    },

    '&.Mui-disabled': {
      opacity: 0.4,
    },
  };
};
