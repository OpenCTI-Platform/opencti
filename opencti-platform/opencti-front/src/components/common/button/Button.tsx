import React, { useMemo } from 'react';
import { Button as MuiButton, ButtonProps as MuiButtonProps } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { ButtonColorKey, ButtonIntent, ButtonSize, GradientVariant } from './Button.types';
import { getColorDefinitions, getGradientColors, getSizeConfig } from './Button.utils';
import type { Theme } from '../../Theme';
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
  selected?: boolean;
  component?: React.ElementType;
  to?: string;
  href?: string;
  target?: string;
  rel?: string;
  download?: string | boolean;
}

type RestrictedIntentButtonProps = BaseButtonProps & {
  intent: 'ai' | 'ee';
  variant?: Exclude<ButtonVariant, 'primary'>;
};

// Default buttons can use any variant
type DefaultIntentButtonProps = BaseButtonProps & {
  intent?: 'default' | 'destructive';
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
  gradientAngle = 90,
  iconOnly = false,
  selected = false,
  children,
  startIcon,
  endIcon,
  sx: externalSx,
  ...props
}) => {
  const theme = useTheme<Theme>();

  const determineColorKey = (): ButtonColorKey => {
    // color takes over intent
    if (color) return color;
    if (intent !== 'default') return intent;

    switch (variant) {
      case 'secondary': return 'secondary';
      case 'primary': return 'primary';
      case 'tertiary': return 'default';
      default: return 'default';
    }
  };

  const combinedSx = useMemo(() => {
    const currentColorKey = determineColorKey();
    const colors = getColorDefinitions(theme);
    const currentColor = colors[currentColorKey];

    const isGradientLocal = gradient || variant === 'extra';

    const gradientColorsLocal = getGradientColors(
      theme,
      isGradientLocal,
      gradientVariant,
      currentColor,
      gradientStartColor,
      gradientEndColor,
    );

    const sizeConfig = getSizeConfig(theme, size, iconOnly);

    const styleParams = {
      theme,
      currentColor,
      gradientColors: gradientColorsLocal,
      gradientAngle,
      sizeConfig,
      selected,
    };

    const baseSx = createBaseStyles(styleParams);

    let variantSx;
    switch (variant) {
      case 'primary':
        variantSx = gradient
          ? createPrimaryGradientStyles(styleParams)
          : createPrimarySolidStyles(styleParams);
        break;
      case 'secondary':
        variantSx = gradient
          ? createSecondaryGradientStyles(styleParams)
          : createSecondarySolidStyles(styleParams);
        break;
      case 'tertiary':
        variantSx = gradient
          ? createTertiaryGradientStyles(styleParams)
          : createTertiarySolidStyles(styleParams);
        break;
      case 'extra':
        variantSx = createExtraStyles(styleParams);
        break;
      default:
        variantSx = {};
    }

    return [
      baseSx,
      variantSx,
      ...(Array.isArray(externalSx) ? externalSx : [externalSx]),
    ];
  }, [theme, variant, gradient, gradientVariant, gradientStartColor, gradientEndColor, gradientAngle, size, iconOnly, selected, externalSx]);

  const isGradient = gradient || variant === 'extra';

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
