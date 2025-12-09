import React from 'react';
import { Button as MuiButton } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { SxProps, Theme } from '@mui/material/styles';
import type { CustomButtonProps } from './Button.types';
import { getColorDefinitions, getGradientColors } from './Button.utils';
import {
  createBaseStyles,
  createPrimaryGradientStyles,
  createPrimarySolidStyles,
  createSecondaryGradientStyles,
  createSecondarySolidStyles,
  createTertiaryGradientStyles,
  createTertiarySolidStyles,
  createExtraStyles,
} from './Button.styles.factory';
import { getSizeConfig } from './Button.constants';

const Button: React.FC<CustomButtonProps> = ({
  variant = 'primary',
  intent = 'default',
  size = 'default',
  gradient = false,
  gradientVariant = 'default',
  gradientStartColor,
  gradientEndColor,
  gradientAngle = 99.95,
  iconOnly = false,
  children,
  startIcon,
  endIcon,
  sx: externalSx,
  ...props
}) => {
  const theme = useTheme();
  
  const colors = getColorDefinitions(theme);
  const currentColor = colors[intent];

  const isGradient = gradient || variant === 'extra';
  
  const gradientColors = getGradientColors(
    theme,
    isGradient,
    gradientVariant,
    currentColor,
    gradientStartColor,
    gradientEndColor
  );

  const sizeConfig = getSizeConfig(size, iconOnly);

  const styleParams = {
    theme,
    currentColor,
    gradientColors,
    gradientAngle,
    sizeConfig,
  };

  const baseSx = createBaseStyles(styleParams);

  const variantSx = (() => {
    switch (variant) {
      case 'primary':
        return gradient 
          ? createPrimaryGradientStyles(styleParams)
          : createPrimarySolidStyles(styleParams);
      
      case 'secondary':
        return gradient
          ? createSecondaryGradientStyles(styleParams)
          : createSecondarySolidStyles(styleParams);
      
      case 'tertiary':
        return gradient
          ? createTertiaryGradientStyles(styleParams)
          : createTertiarySolidStyles(styleParams);
      
      case 'extra':
        return createExtraStyles(styleParams);
      
      default:
        return {};
    }
  })();

  const combinedSx: SxProps<Theme> = [
    baseSx,
    variantSx,
    ...(Array.isArray(externalSx) ? externalSx : [externalSx]),
  ];

  // Wrap content for gradient
  const content = isGradient && children ? (
    <span className="button-content">{children}</span>
  ) : (
    children
  );

  const wrappedStartIcon = isGradient && startIcon ? (
    <span className="button-content">{startIcon}</span>
  ) : (
    startIcon
  );

  const wrappedEndIcon = isGradient && endIcon ? (
    <span className="button-content">{endIcon}</span>
  ) : (
    endIcon
  );

  return (
    <MuiButton
      sx={combinedSx}
      startIcon={wrappedStartIcon}
      endIcon={wrappedEndIcon}
      disableRipple={false}
      disableElevation
      {...props}
    >
      {content}
    </MuiButton>
  );
};

export default Button;