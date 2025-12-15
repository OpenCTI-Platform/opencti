import React from 'react';
import { Button as MuiButton, ButtonProps as MuiButtonProps } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { SxProps, Theme } from '@mui/material/styles';
import type { ButtonColorKey, ButtonIntent, ButtonSize, GradientVariant } from './Button.types';
import { getColorDefinitions, getGradientColors, getSizeConfig } from './Button.utils';
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

export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'extra';

interface BaseButtonProps extends Omit<MuiButtonProps, 'variant' | 'color' | 'size'> {
  variant?: ButtonVariant;
  color?: ButtonColorKey;
  intent?: ButtonIntent;
  size?: ButtonSize;
  gradient?: boolean;
  gradientVariant?: GradientVariant;
  gradientStartColor?: string;
  gradientEndColor?: string;
  gradientAngle?: number;
  startIcon?: React.ReactNode;
  endIcon?: React.ReactNode;
  fullWidth?: boolean;
  iconOnly?: boolean;
  component?: React.ElementType;
  to?: string;
  href?: string;
  target?: string;
  rel?: string;
  download?: string | boolean;
}

type RestrictedIntentButtonProps = BaseButtonProps & {
  intent: 'destructive' | 'ai';
  variant?: Exclude<ButtonVariant, 'primary'>;
};

// Default buttons can use any variant
type DefaultIntentButtonProps = BaseButtonProps & {
  intent?: 'default';
  variant?: ButtonVariant;
};

export type CustomButtonProps = RestrictedIntentButtonProps | DefaultIntentButtonProps;

const Button: React.FC<CustomButtonProps> = ({
  variant = 'primary',
  color,
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

  // color takes over intent
  const currentIntent: ButtonColorKey = color ?? intent;
  const colors = getColorDefinitions(theme);
  const currentColor = colors[currentIntent];

  const isGradient = gradient || variant === 'extra';

  const gradientColors = getGradientColors(
    theme,
    isGradient,
    gradientVariant,
    currentColor,
    gradientStartColor,
    gradientEndColor,
  );

  const sizeConfig = getSizeConfig(theme, size, iconOnly);

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
