import { buttonClasses } from '@mui/material/Button';
import type { ExtendedThemeOptions } from './Theme';
import { fileUri } from '../relay/environment';
import LogoText from '../static/images/logo_text_light.svg';
import LogoCollapsed from '../static/images/logo_light.svg';
import { hexToRGB } from '../utils/Colors';
import { alpha, darken, lighten } from '@mui/material';
import { FDS } from './fds-tokens.generated';

const EE_COLOR = '#00BD94';

export const THEME_LIGHT_DEFAULT_BACKGROUND = FDS.colors.light['--color-elevation-background-layer-0'];
export const THEME_LIGHT_DEFAULT_BODY_END_GRADIENT = FDS.colors.light['--color-elevation-background-layer-0-gradient'];
export const THEME_LIGHT_DEFAULT_PRIMARY = FDS.colors.light['--color-filigran-brand-primary'];
const THEME_LIGHT_DEFAULT_SECONDARY = FDS.colors.light['--color-filigran-tonic-primary'];
const THEME_LIGHT_DEFAULT_ACCENT = FDS.colors.light['--color-elevation-background-layer-3'];
const THEME_LIGHT_DEFAULT_TEXT = FDS.colors.light['--color-text-default-primary'];
export const THEME_LIGHT_DEFAULT_PAPER = FDS.colors.light['--color-elevation-background-layer-1'];
const THEME_LIGHT_DEFAULT_NAV = FDS.colors.light['--color-elevation-surface-heading-layer-0'];
export const THEME_LIGHT_DIALOG_BACKGROUND = '#FFFFFF';

const getAppBodyGradientEndColor = (background: string | null): string => {
  if (background && background !== THEME_LIGHT_DEFAULT_BACKGROUND) {
    return lighten(background, 0.05);
  }
  return THEME_LIGHT_DEFAULT_BODY_END_GRADIENT;
};

const ThemeLight = (
  logo: string | null = null,
  logo_collapsed: string | null = null,
  background: string | null = null,
  paper: string | null = null,
  nav: string | null = null,
  primary: string | null = null,
  secondary: string | null = null,
  accent: string | null = null,
  text_color: string = THEME_LIGHT_DEFAULT_TEXT,
): ExtendedThemeOptions => ({
  logo: logo || fileUri(LogoText),
  logo_collapsed: logo_collapsed || fileUri(LogoCollapsed),
  borderRadius: 4,
  palette: {
    mode: 'light',
    common: { white: '#ffffff', grey: '#494A50', lightGrey: '#AFB0B6' },
    error: {
      main: FDS.colors.light['--color-feedback-error-primary'],
      dark: FDS.colors.light['--color-feedback-error-tertiary'],
    },
    warn: {
      main: FDS.colors.light['--color-feedback-warning-primary'],
    },
    dangerZone: {
      main: FDS.colors.light['--color-feedback-error-primary'],
      light: FDS.colors.light['--color-feedback-error-secondary'],
      dark: FDS.colors.light['--color-feedback-error-tertiary'],
      contrastText: '#000000',
      text: { primary: FDS.colors.light['--color-feedback-error-tertiary'] },
    },
    success: { main: FDS.colors.light['--color-feedback-success-primary'], dark: FDS.colors.light['--color-feedback-success-tertiary'] },
    primary: { main: primary || THEME_LIGHT_DEFAULT_PRIMARY, light: primary ? alpha(primary, 0.08) : '#7587FF' },
    secondary: { main: secondary || THEME_LIGHT_DEFAULT_SECONDARY },
    gradient: { main: '#00BD94' },
    border: {
      lightBackground: hexToRGB('#000000', 0.15),
      primary: hexToRGB((primary || THEME_LIGHT_DEFAULT_PRIMARY), 0.3),
      secondary: '#C2C2C2',
      pagination: hexToRGB('#000000', 0.5),
      paper: hexToRGB('#000000', 0.12),
      main: '#D2D2D2',
    },
    pagination: {
      main: '#000000',
    },
    chip: { main: '#000000' },
    ai: {
      main: FDS.colors.light['--color-filigran-ia-main'],
      light: FDS.colors.light['--color-filigran-ia-tertiary'],
      dark: FDS.colors.light['--color-filigran-ia-secondary'],
      contrastText: '#000000',
      background: 'rgba(221, 225, 254, 0.94)',
    },
    ee: {
      main: EE_COLOR,
      background: hexToRGB(EE_COLOR, 0.2),
      lightBackground: hexToRGB(EE_COLOR, 0.08),
      contrastText: '#F2F2F3',
    },
    background: {
      default: background || THEME_LIGHT_DEFAULT_BACKGROUND,
      paper: paper || THEME_LIGHT_DEFAULT_PAPER,
      nav: nav || THEME_LIGHT_DEFAULT_NAV,
      accent: accent || THEME_LIGHT_DEFAULT_ACCENT,
      shadow: alpha('#000000', 0.15),
      // the only way for now to know if we should apply the paper color or not
      secondary: paper === THEME_LIGHT_DEFAULT_PAPER
        ? '#FFFFFF'
        : (paper ?? '#FFFFFF'),
      drawer: nav === THEME_LIGHT_DEFAULT_PAPER
        ? '#FFFFFF'
        : (darken(nav ?? '#FFFFFF', 0.5)),
      disabled: '#DFDFDF',
      gradient: {
        start: background || THEME_LIGHT_DEFAULT_BACKGROUND,
        end: getAppBodyGradientEndColor(background),
      },
    },
    text: {
      secondary: THEME_LIGHT_DEFAULT_TEXT,
      tertiary: '#717172',
      light: '#494A50',
      disabled: '#6E7788',
    },
    leftBar: {
      header: {
        itemBackground: '#ECECF2',
      },
      popoverItem: '#ECECF2',
      hover: '#0015A81A',
      text: '#18191B',
    },
    severity: {
      critical: FDS.colors.light['--color-feedback-error-primary'],
      high: FDS.colors.light['--color-feedback-warning-primary'],
      medium: FDS.colors.light['--color-feedback-alert-primary'],
      low: FDS.colors.light['--color-feedback-success-primary'],
      info: FDS.colors.light['--color-feedback-info-primary'],
      none: '#424242',
      default: '#DDE1FE',
    },
    // This block used to be hand-copied from Figma exports — every value
    // below is now sourced from the generated FDS bridge (fds-tokens.generated.ts).
    // Where no confident FDS equivalent exists, the original hardcoded value
    // is kept as-is; see fds-migration/TOKEN-MAPPING.md for the full rationale.
    designSystem: {
      primary: {
        main: FDS.colors.light['--color-filigran-brand-primary'],
        light: FDS.colors.light['--color-filigran-brand-secondary'],
        dark: FDS.colors.light['--color-filigran-brand-tertiary'],
      },
      // No confident FDS match for light/dark shades (tonic doesn't vary by
      // mode and its secondary/tertiary tiers don't match these old values) -
      // only `main` is wired, left as-is otherwise.
      secondary: {
        main: FDS.colors.light['--color-filigran-tonic-primary'],
        light: '#74E9CA',
        dark: '#0A8268',
      },
      destructive: {
        main: FDS.colors.light['--color-feedback-error-primary'],
        light: FDS.colors.light['--color-feedback-error-secondary'],
        dark: FDS.colors.light['--color-feedback-error-tertiary'],
      },
      ia: {
        main: FDS.colors.light['--color-filigran-ia-main'],
        light: FDS.colors.light['--color-filigran-ia-tertiary'],
        dark: FDS.colors.light['--color-filigran-ia-secondary'],
      },
      background: {
        main: THEME_LIGHT_DEFAULT_BACKGROUND,
        // bg1-bg4/disabled: no confident 1:1 FDS token found, left as-is.
        bg1: '#F7F7F7',
        bg2: '#FFFFFF',
        bg3: '#E4E4E4',
        bg4: '#DDE1FE',
        disabled: '#DFDFDF',
      },
      // No confident FDS token found for any of these three, left as-is.
      border: {
        main: '#D2D2D2',
        border1: '#C2C2C2',
        border2: '#999797',
      },
      gradient: {
        background: FDS.gradients.light['--gradient-background'],
        ia: FDS.gradients.light['--gradient-ia'],
        focus: FDS.gradients.light['--gradient-focus'],
      },
      alert: {
        info: {
          primary: FDS.colors.light['--color-feedback-info-primary'],
          secondary: FDS.colors.light['--color-feedback-info-secondary'],
        },
        success: {
          primary: FDS.colors.light['--color-feedback-success-primary'],
          secondary: FDS.colors.light['--color-feedback-success-secondary'],
          tertiary: FDS.colors.light['--color-feedback-success-tertiary'],
        },
        alert: {
          primary: FDS.colors.light['--color-feedback-alert-primary'],
          secondary: FDS.colors.light['--color-feedback-alert-secondary'],
        },
        warning: {
          primary: FDS.colors.light['--color-feedback-warning-primary'],
          secondary: FDS.colors.light['--color-feedback-warning-secondary'],
        },
        error: {
          primary: FDS.colors.light['--color-feedback-error-primary'],
          secondary: FDS.colors.light['--color-feedback-error-secondary'],
        },
      },
      tertiary: {
        grey: {
          400: FDS.colors.light['--color-gray-400'],
          700: FDS.colors.light['--color-gray-700'],
          800: FDS.colors.light['--color-gray-800'],
        },
        // No FDS scale matches these two values, left as-is.
        blue: {
          500: '#0099CC',
          900: '#003242',
        },
        darkBlue: {
          300: FDS.colors.light['--color-darkblue-300'],
          500: FDS.colors.light['--color-darkblue-500'],
        },
        turquoise: {
          600: FDS.colors.light['--color-turquoise-600'],
          800: FDS.colors.light['--color-turquoise-800'],
        },
        green: {
          400: FDS.colors.light['--color-green-400'],
          600: FDS.colors.light['--color-green-600'],
          800: FDS.colors.light['--color-green-800'],
        },
        red: {
          100: FDS.colors.light['--color-red-100'],
          200: FDS.colors.light['--color-red-200'],
          400: FDS.colors.light['--color-red-400'],
          500: FDS.colors.light['--color-red-500'],
          600: FDS.colors.light['--color-red-600'],
          700: FDS.colors.light['--color-red-700'],
        },
        orange: {
          400: FDS.colors.light['--color-orange-400'],
          500: FDS.colors.light['--color-orange-500'],
        },
        yellow: {
          400: FDS.colors.light['--color-yellow-400'],
        },
      },
    },
  },
  tag: {
    overflowColor: primary || THEME_LIGHT_DEFAULT_PRIMARY,
  },
  typography: {
    fontFamily: '"IBM Plex Sans", sans-serif',
    body2: {
      fontSize: '0.8rem',
      lineHeight: '1.2rem',
      color: text_color,
    },
    body1: {
      fontSize: '0.9rem',
      color: text_color,
    },
    overline: {
      fontWeight: 500,
      color: text_color,
    },
    h1: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 400,
      fontSize: 22,
      fontFamily: '"Geologica", sans-serif',
      color: text_color,
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 500,
      fontSize: 16,
      fontFamily: '"Geologica", sans-serif',
      color: text_color,
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: text_color,
      fontWeight: 400,
      fontSize: 13,
      fontFamily: '"Geologica", sans-serif',
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    h4: {
      height: 15,
      margin: '0 0 10px 0',
      padding: 0,
      fontSize: 12,
      fontWeight: 500,
      color: text_color,
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    h5: {
      fontWeight: 700,
      fontSize: 16,
      color: text_color,
      fontFamily: '"Geologica", sans-serif',
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    h6: {
      fontWeight: 600,
      fontSize: 14,
      color: text_color,
      fontFamily: '"Geologica", sans-serif',
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
    subtitle2: {
      fontWeight: 400,
      fontSize: 18,
      color: text_color,
      textTransform: 'lowercase',
      '&::first-letter': {
        textTransform: 'uppercase',
      },
    },
  },
  button: {
    sizes: {
      default: {
        height: '36px',
        padding: '8px 16px',
        minWidth: '36px',
        width: '36px',
        fontSize: '14px',
        fontWeight: 600,
        lineHeight: '21px',
        iconSize: '16px',
      },
      small: {
        height: '26px',
        padding: '4px 12px',
        minWidth: '26px',
        width: '26px',
        fontSize: '13px',
        fontWeight: 600,
        lineHeight: '21px',
        iconSize: '14px',
      },
    },
  },
  components: {
    MuiAccordion: {
      defaultProps: {
        slotProps: {
          transition: {
            unmountOnExit: true,
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          [`&.${buttonClasses.outlined}.${buttonClasses.sizeSmall}`]: {
            padding: '4px 9px',
          },
          '&.icon-outlined': {
            borderColor: hexToRGB('#000000', 0.15),
            padding: 7,
            minWidth: 0,
            '&:hover': {
              borderColor: hexToRGB('#000000', 0.15),
              backgroundColor: hexToRGB('#000000', 0.05),
            },
          },
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          backgroundColor: paper === THEME_LIGHT_DEFAULT_PAPER
            ? '#FFFFFF'
            : (paper ?? '#FFFFFF'),
          borderRadius: 4,
        },
      },
    },
    MuiDialogTitle: {
      defaultProps: {
        variant: 'h5',
      },
    },
    MuiDialogActions: {
      styleOverrides: {
        root: ({ theme }) => ({
          gap: theme.spacing(1),
          padding: 0,
          marginTop: theme.spacing(4),
          marginLeft: 0,
          '& .MuiButton-root': {
            textTransform: 'none',
          },
          '& > :not(style) ~ :not(style)': {
            marginLeft: 0,
          },
        }),
      },
    },
    MuiToggleButtonGroup: {
      defaultProps: {
        size: 'small',
      },
      styleOverrides: {
        root: {
          height: 36,
          '& .MuiTouchRipple-root': {
            display: 'none',
          },
          '& .MuiToggleButton-root': {
            border: '1px solid #D2D2D2',
            color: primary,

            '&:focus-visible': {
              outline: 'none',
              boxShadow: '0 0 0 2px #74E9CA',
            },

            '&.Mui-selected': {
              backgroundColor: hexToRGB(primary || THEME_LIGHT_DEFAULT_PRIMARY, 0.25),
            },

            '&:hover:not(.Mui-selected)': {
              backgroundColor: hexToRGB(primary || THEME_LIGHT_DEFAULT_PRIMARY, 0.15),
            },
          },
        },
      },
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          backgroundColor: 'rgba(0,0,0,0.7)',
        },
        arrow: {
          color: 'rgba(0,0,0,0.7)',
        },
        popper: {
          textTransform: 'lowercase',
          '&::first-letter': {
            textTransform: 'uppercase',
          },
        },
      },
    },
    MuiFormControl: {
      defaultProps: {
        variant: 'standard',
      },
      styleOverrides: {
        root: {
          color: text_color,
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        variant: 'standard',
      },
      styleOverrides: {
        root: {
          color: text_color,
          // Shrink = when at the top of the input in small size.
          '& .MuiFormLabel-root:not(.MuiInputLabel-shrink):not(.Mui-error)': {
            color: '#494A50',
          },
        },
      },
    },
    MuiSelect: {
      defaultProps: {
        variant: 'standard',
      },
      styleOverrides: {
        root: {
          color: text_color,
          '& fieldset': {
            border: 'none',
          },
        },
        outlined: {
          backgroundColor: paper === THEME_LIGHT_DEFAULT_PAPER
            ? '#FFFFFF'
            : (paper ?? '#FFFFFF'),
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          color: text_color,
        },
      },
    },
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          scrollbarColor: `${accent || THEME_LIGHT_DEFAULT_ACCENT} ${paper || THEME_LIGHT_DEFAULT_PAPER}`,
          scrollbarWidth: 'thin',
          background: `linear-gradient(100deg, ${background || THEME_LIGHT_DEFAULT_BACKGROUND} 0%, ${getAppBodyGradientEndColor(background)} 100%)`,
          backgroundAttachment: 'fixed',
          backgroundColor: background || THEME_LIGHT_DEFAULT_BACKGROUND,
        },
        body: {
          background: `linear-gradient(100deg, ${background || THEME_LIGHT_DEFAULT_BACKGROUND} 0%, ${getAppBodyGradientEndColor(background)} 100%)`,
          backgroundAttachment: 'fixed',
          scrollbarColor: `${accent || THEME_LIGHT_DEFAULT_ACCENT} ${paper || THEME_LIGHT_DEFAULT_PAPER}`,
          scrollbarWidth: 'thin',
          html: {
            WebkitFontSmoothing: 'auto',
          },
          a: {
            color: primary || THEME_LIGHT_DEFAULT_PRIMARY,
          },
          'input:-webkit-autofill': {
            WebkitAnimation: 'autofill 0s forwards',
            animation: 'autofill 0s forwards',
            WebkitTextFillColor: '#000000 !important',
            caretColor: 'transparent !important',
            WebkitBoxShadow:
                '0 0 0 1000px rgba(4, 8, 17, 0.88) inset !important',
            borderTopLeftRadius: 'inherit',
            borderTopRightRadius: 'inherit',
          },
          pre: {
            fontFamily: 'Consolas, monaco, monospace',
            color: `${text_color} !important`,
            background: `${accent || THEME_LIGHT_DEFAULT_ACCENT} !important`,
            borderRadius: 4,
          },
          'pre.light': {
            fontFamily: 'Consolas, monaco, monospace',
            background: `${nav || THEME_LIGHT_DEFAULT_NAV} !important`,
            borderRadius: 4,
          },
          code: {
            fontFamily: 'Consolas, monaco, monospace',
            color: `${text_color} !important`,
            background: `${accent || THEME_LIGHT_DEFAULT_ACCENT} !important`,
            padding: 3,
            fontSize: 12,
            fontWeight: 400,
            borderRadius: 4,
          },
          '.react-mde': {
            border: '0 !important',
          },
          '.error .react-mde textarea': {
            border: '0 !important',
            borderBottom: '2px solid #F14337 !important',
            '&:hover': {
              border: '0 !important',
              borderBottom: '2px solid #F14337 !important',
            },
            '&:focus': {
              border: '0 !important',
              borderBottom: '2px solid #F14337 !important',
            },
          },
          '.mde-header': {
            border: '0 !important',
            backgroundColor: 'transparent !important',
            color: `${text_color} !important`,
          },
          '.mde-header-item button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: `${text_color} !important`,
          },
          '.mde-tabs button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: `${text_color} !important`,
          },
          '.mde-textarea-wrapper textarea': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            fontSize: 13,
            color: `${text_color} !important`,
            background: 'transparent',
            borderBottom: '1px solid rgba(0, 0, 0, 0.87) !important',
            transition: 'borderBottom .3s',
            '&:hover': {
              borderBottom: '2px solid #000000 !important',
            },
            '&:focus': {
              borderBottom: `2px solid ${primary || THEME_LIGHT_DEFAULT_PRIMARY} !important`,
            },
          },
          '.mde-preview .mde-preview-content a': {
            color: `${text_color} !important`,
          },
          '.react-grid-placeholder': {
            backgroundColor: `${accent || THEME_LIGHT_DEFAULT_ACCENT} !important`,
          },
          '.react_time_range__track': {
            backgroundColor: 'rgba(1, 226, 255, 0.1) !important',
            borderLeft: '1px solid #00bcd4 !important',
            borderRight: '1px solid #00bcd4 !important',
          },
          '.react_time_range__handle_marker': {
            backgroundColor: '#00bcd4 !important',
          },
          '.leaflet-container': {
            backgroundColor: `${paper || '#ffffff'} !important`,
          },
          '.react-grid-item .react-resizable-handle::after': {
            borderRight: '2px solid #AFB0B6 !important',
            borderBottom: '2px solid #AFB0B6 !important',
          },
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          borderBottom: '1px solid rgba(255, 255, 255, 0.15)',
        },
        body: {
          borderTop: '1px solid rgba(255, 255, 255, 0.15)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.15)',
        },
      },
    },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          ':hover': {
            backgroundColor: 'rgba(0,0,0,0.04)',
          },
          '&.Mui-selected': {
            boxShadow: `2px 0 ${primary || THEME_LIGHT_DEFAULT_PRIMARY} inset`,
            backgroundColor: hexToRGB(primary || THEME_LIGHT_DEFAULT_PRIMARY, 0.12),
          },
          '&.Mui-selected:hover': {
            boxShadow: `2px 0 ${primary || THEME_LIGHT_DEFAULT_PRIMARY} inset`,
            backgroundColor: hexToRGB(primary || THEME_LIGHT_DEFAULT_PRIMARY, 0.16),
          },
        },
      },
    },
    MuiTypography: {
      styleOverrides: {
        root: {
          color: text_color,
          textTransform: 'none',
        },
      },
    },
    MuiInputBase: {
      styleOverrides: {
        root: {
          color: text_color,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          color: text_color,
          textTransform: 'lowercase',
          '&::first-letter': {
            textTransform: 'uppercase',
          },
        },
        label: {
          textTransform: 'lowercase',
          '&::first-letter': {
            textTransform: 'uppercase',
          },
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'lowercase',
          display: 'inline-block',
          '&::first-letter': {
            textTransform: 'uppercase',
          },
        },
      },
    },
    MuiFab: {
      styleOverrides: {
        root: {
          textTransform: 'none',
        },
      },
    },
    MuiAutocomplete: {
      styleOverrides: {
        root: {
          // Shrink = when at the top of the input in small size.
          '& .MuiFormLabel-root:not(.MuiInputLabel-shrink):not(.Mui-error)': {
            color: '#494A50',
          },
          '& .MuiOutlinedInput-root': {
            // the only way for now to know if we should apply the paper color or not
            backgroundColor: paper === THEME_LIGHT_DEFAULT_PAPER
              ? '#FFFFFF'
              : (paper ?? '#FFFFFF'),
            '& fieldset': {
              borderColor: 'transparent',
            },
          },
        },
      },
    },
  },
});

export default ThemeLight;
