import { buttonClasses } from '@mui/material/Button';
import type { ExtendedThemeOptions } from './Theme';
import { fileUri } from '../relay/environment';
import LogoText from '../static/images/logo_text_light.svg';
import LogoCollapsed from '../static/images/logo_light.svg';
import { hexToRGB } from '../utils/Colors';
import { alpha, lighten } from '@mui/material';

const EE_COLOR = '#00BD94';

export const THEME_LIGHT_DEFAULT_BACKGROUND = '#ececf2';
export const THEME_LIGHT_DEFAULT_BODY_END_GRADIENT = '#F7F7F7';
const THEME_LIGHT_DEFAULT_PRIMARY = '#0015a8';
const THEME_LIGHT_DEFAULT_SECONDARY = '#00BD94';
const THEME_LIGHT_DEFAULT_ACCENT = '#dfdfdf';
const THEME_LIGHT_DEFAULT_TEXT = '#18191B';
const THEME_LIGHT_DEFAULT_PAPER = '#ffffff';
const THEME_LIGHT_DEFAULT_NAV = '#ffffff';

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
  text_color = THEME_LIGHT_DEFAULT_TEXT,
): ExtendedThemeOptions => ({
  logo: logo || fileUri(LogoText),
  logo_collapsed: logo_collapsed || fileUri(LogoCollapsed),
  borderRadius: 4,
  palette: {
    mode: 'light',
    common: { white: '#ffffff', grey: '#494A50', lightGrey: '#AFB0B6' },
    error: {
      main: '#F14337',
      dark: '#881106',
    },
    warn: {
      main: '#E6700F',
    },
    dangerZone: {
      main: '#E51E10',
      light: '#F8958C',
      dark: '#881106',
      contrastText: '#000000',
      text: { primary: '#881106' },
    },
    success: { main: '#1CA55E', dark: '#0D7E39' },
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
      main: '#5E1AD5',
      light: '#D6C2FA',
      dark: '#3C108C',
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
      secondary: '#FFFFFF',
      drawer: '#f4f1f1',
      disabled: '#DFDFDF',
      gradient: {
        start: background || THEME_LIGHT_DEFAULT_BACKGROUND,
        end: getAppBodyGradientEndColor(background),
      },
    },
    text: {
      secondary: '#494A50',
      light: '#494A50',
      disabled: '#6E7788',
    },
    leftBar: {
      header: {
        itemBackground: '#ECECF2',
      },
      popoverItem: '#ECECF2',
    },
    severity: {
      critical: '#EE3838',
      high: '#E6700F',
      medium: '#E1B823',
      low: '#16AD34',
      info: '#1565c0',
      none: '#424242',
      default: '#DDE1FE',
    },
    designSystem: {
      primary: {
        main: '#0015A8',
        light: '#7587FF',
        dark: '#000842',
      },
      secondary: {
        main: '#00BD94',
        light: '#74E9CA',
        dark: '#0A8268',
      },
      destructive: {
        main: '#E51E10',
        light: '#F8958C',
        dark: '#881106',
      },
      ia: {
        main: '#5E1AD5',
        light: '#D6C2FA',
        dark: '#3C108C',
      },
      alert: {
        info: {
          primary: '#00719E',
          secondary: '#2AB3E0',
        },
        success: {
          primary: '#1CA55E',
          secondary: '#4CD990',
          tertiary: '#0D7E39',
        },
        alert: {
          primary: '#F2BE3A',
          secondary: '#F6CE6A',
        },
        warning: {
          primary: '#E6700F',
          secondary: '#F8C08C',
        },
        error: {
          primary: '#F14337',
          secondary: '#F8958C',
        },
      },
      tertiary: {
        grey: {
          400: '#95969D',
          700: '#494A50',
          800: '#313235',
        },
        blue: {
          500: '#0099CC',
          900: '#003242',
        },
        darkBlue: {
          300: '#7587FF',
          500: '#0F2DFF',
        },
        turquoise: {
          600: '#00BD94',
          800: '#005744',
        },
        green: {
          400: '#41E149',
          600: '#17AB1F',
          800: '#094E0B',
        },
        red: {
          100: '#FBCBC5',
          200: '#F8958C',
          400: '#F14337',
          500: '#E51E10',
          600: '#B8180A',
          700: '#881106',
        },
        orange: {
          400: '#F2933A',
          500: '#E6700F',
        },
        yellow: {
          400: '#F2BE3A',
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
      fontWeight: 400,
      fontSize: 18,
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
        },
        body: {
          background: `linear-gradient(100deg, ${background || THEME_LIGHT_DEFAULT_BACKGROUND} 0%, ${getAppBodyGradientEndColor(background)} 100%)`,
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
    MuiDialogActions: {
      styleOverrides: {
        root: {
          '& .MuiButton-root': {
            textTransform: 'none',
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
          '& .MuiOutlinedInput-root': {
            backgroundColor: '#ffffff',
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
