import React from 'react';
import { Button as MuiButton, ButtonProps as MuiButtonProps } from '@mui/material';
import { Button as LibButton } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
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
  /**
   * Force the MUI path. For a site whose `color` is an expression: the wrapper
   * only ever sees the resolved value, so it cannot tell a literal from a
   * ternary, and a control that changes engine between renders is remounted --
   * losing keyboard focus at the moment of activation. @sandy ruled identity
   * stability over partial library rendering.
   */
  keepMui?: boolean;
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

type DefaultIntentButtonProps = BaseButtonProps & {
  intent?: 'default' | 'destructive';
  variant?: ButtonVariant;
};

export type CustomButtonProps = RestrictedIntentButtonProps | DefaultIntentButtonProps;

/**
 * The wrapper's `variant` is a PRIORITY and its `intent`/`color` are the TONE;
 * the library splits the same two axes as `priority` and `variant`. Mapping the
 * words across without this table is the whole trap: `variant="secondary"` (367
 * sites) is a priority, not a colour.
 */
const LIB_PRIORITY = { primary: 'primary', secondary: 'secondary', tertiary: 'tertiary' } as const;
const LIB_TONE_FROM_INTENT = { default: 'default', destructive: 'destructive', ai: 'ia', ee: 'highlight' } as const;

/**
 * `color` outranks `intent`, as it always did. `primary`, `secondary` and
 * `default` all resolve to `theme.palette.primary.main` in `getColorDefinitions`
 * -- they differ only by border -- so all three are the library's default tone.
 * `warn` and `success` have NO library tone and are deliberately absent: a site
 * using them keeps MUI rather than lose its colour.
 */
const LIB_TONE_FROM_COLOR: Partial<Record<ButtonColorKey, 'default' | 'destructive' | 'ia' | 'highlight'>> = {
  default: 'default',
  primary: 'default',
  secondary: 'default',
  error: 'destructive',
  destructive: 'destructive',
  ai: 'ia',
  ee: 'highlight',
};

/** `default` is 36px and the library's `md` is 36px -- exact. `small` is 26px against `sm`'s 24px. */
const LIB_SIZE = { default: 'md', small: 'sm' } as const;

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
  keepMui = false,
  children,
  startIcon,
  endIcon,
  sx: externalSx,
  ...props
}) => {
  const theme = useTheme<Theme>();
  const {
    component: Component, to, href, classes,
    // MUI-only props: they are not DOM attributes and the library button would
    // forward them straight onto the element.
    disableRipple: _disableRipple, disableElevation: _disableElevation,
    disableFocusRipple: _disableFocusRipple, focusRipple: _focusRipple,
    centerRipple: _centerRipple, TouchRippleProps: _TouchRippleProps,
    touchRippleRef: _touchRippleRef, LinkComponent: _LinkComponent,
    focusVisibleClassName: _focusVisibleClassName, onFocusVisible: _onFocusVisible,
    loading, loadingIndicator: _loadingIndicator, loadingPosition: _loadingPosition,
    ...rest
  } = props as typeof props & {
    classes?: unknown; disableRipple?: unknown; disableElevation?: unknown;
    disableFocusRipple?: unknown; focusRipple?: unknown; centerRipple?: unknown;
    TouchRippleProps?: unknown; touchRippleRef?: unknown; LinkComponent?: unknown;
    focusVisibleClassName?: unknown; onFocusVisible?: unknown;
    loading?: boolean | null; loadingIndicator?: unknown; loadingPosition?: unknown;
  };

  const rendersAnchor = Boolean(to) || Boolean(href) || Component === 'a';
  const libPriority = LIB_PRIORITY[variant as keyof typeof LIB_PRIORITY];
  const libTone = color ? LIB_TONE_FROM_COLOR[color] : LIB_TONE_FROM_INTENT[intent];
  const libSize = LIB_SIZE[size as keyof typeof LIB_SIZE];
  const isPolymorphic = Boolean(Component || to || href);

  /**
   * The library is used only where it can reproduce the site exactly. Anything
   * it cannot express keeps MUI, and a site passing a value outside the union
   * -- there are a few, and `TasksList` passes MUI's own `variant="outlined"`
   * -- lands here too instead of silently rendering the wrong thing.
   */
  const canUseLibrary = Boolean(libPriority)
    && Boolean(libTone)
    && Boolean(libSize)
    && !gradient
    && !selected
    && !externalSx
    && !classes
    && !keepMui
    // The icon-only delegate falls back here when the library cannot take the
    // site. The library Button pads for a text label, so it would draw a pill
    // around the glyph instead of MUI's square control: keep MUI's geometry.
    && !iconOnly
    /**
     * `asChild` REPLACES the child's content, and `component="label"` wraps a
     * real file input that would not survive it. MUI also gives the label the
     * role and tab stop the library path does not (WCAG 2.1.1).
     */
    && (!isPolymorphic || rendersAnchor)
    // `asChild` replaces the button with its child, and the library drops the
    // icon slots in that mode.
    && !(isPolymorphic && (startIcon || endIcon));

  if (canUseLibrary) {
    /**
     * MUI sized the glyph through `.MuiButton-startIcon`; the library's slot
     * does not, so an icon with no intrinsic size paints 0x0 there -- the
     * TableTuneIcon defect, which a class assertion cannot see. Sizing the slot
     * here fixes every icon site at once and keeps the 16px/14px the MUI
     * original drew.
     */
    const iconSize = theme.button.sizes[size].iconSize;
    const sizedIcon = (node: React.ReactNode) => (node ? (
      <span
        style={{ display: 'inline-flex', width: iconSize, height: iconSize, fontSize: iconSize }}
        aria-hidden="true"
      >
        {node}
      </span>
    ) : undefined);

    const libProps = {
      priority: libPriority,
      variant: libTone,
      size: libSize,
      // MUI types `loading` as nullable; the library does not.
      loading: loading ?? undefined,
      ...rest,
    };

    if (isPolymorphic) {
      const Child = (Component ?? (href ? 'a' : 'span')) as React.ElementType;
      // No `type` here: the rendered element is an anchor or a label, where the
      // attribute is invalid.
      return (
        <LibButton asChild {...libProps}>
          <Child to={to} href={href}>{children}</Child>
        </LibButton>
      );
    }
    /**
     * MUI's ButtonBase defaults to `type="button"`; a bare <button> inside a
     * <form> defaults to SUBMIT. Without this, every converted button in a form
     * fired its handler AND submitted the form -- caught as a double `onSubmit`
     * in FintelTemplateForm. `libProps` still overrides it.
     */
    return (
      <LibButton type="button" {...libProps} startIcon={sizedIcon(startIcon)} endIcon={sizedIcon(endIcon)}>
        {children}
      </LibButton>
    );
  }

  // FALLBACK — MUI, deliberately. See `canUseLibrary` above for what sends a
  // site here. These retire when the library grows the missing axis.
  const determineColorKey = (): ButtonColorKey => {
    if (color) return color;
    if (intent !== 'default') return intent;
    switch (variant) {
      case 'secondary': return 'secondary';
      case 'primary': return 'primary';
      case 'tertiary': return 'default';
      default: return 'default';
    }
  };

  const currentColorKey = determineColorKey();
  const colors = getColorDefinitions(theme);
  const currentColor = colors[currentColorKey];
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
  const styleParams = { theme, currentColor, gradientColors, gradientAngle, sizeConfig, selected };
  const baseSx = createBaseStyles(styleParams);
  const variantSx = (() => {
    switch (variant) {
      case 'primary':
        return gradient ? createPrimaryGradientStyles(styleParams) : createPrimarySolidStyles(styleParams);
      case 'secondary':
        return gradient ? createSecondaryGradientStyles(styleParams) : createSecondarySolidStyles(styleParams);
      case 'tertiary':
        return gradient ? createTertiaryGradientStyles(styleParams) : createTertiarySolidStyles(styleParams);
      case 'extra':
        return createExtraStyles(styleParams);
      default:
        return {};
    }
  })();
  const combinedSx = [baseSx, variantSx, ...(Array.isArray(externalSx) ? externalSx : [externalSx])];
  const content = isGradient && children ? <span className="button-content">{children}</span> : children;
  const wrappedStartIcon = isGradient && startIcon ? <span className="button-content">{startIcon}</span> : startIcon;
  const wrappedEndIcon = isGradient && endIcon ? <span className="button-content">{endIcon}</span> : endIcon;

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
