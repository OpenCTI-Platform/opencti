import { buttonClasses } from '@mui/material/Button';
import type { ExtendedThemeOptions } from './Theme';
import { fileUri } from '../relay/environment';
import LogoText from '../static/images/logo_text_dark.png';
import LogoCollapsed from '../static/images/logo_dark.png';
import { hexToRGB } from '../utils/Colors';

const EE_COLOR = '#00f1bd';

export const THEME_DARK_DEFAULT_BACKGROUND = '#070d19';
const THEME_DARK_DEFAULT_PRIMARY = '#0fbcff';
const THEME_DARK_DEFAULT_SECONDARY = '#00f1bd';
const THEME_DARK_DEFAULT_ACCENT = '#0f1e38';
const THEME_DARK_DEFAULT_PAPER = '#09101e';
const THEME_DARK_DEFAULT_NAV = '#070d19';

const ThemeDark = (
  logo: string | null = null,
  logo_collapsed: string | null = null,
  background: string | null = null,
  paper: string | null = null,
  nav: string | null = null,
  primary: string | null = null,
  secondary: string | null = null,
  accent: string | null = null,
): ExtendedThemeOptions => ({
  logo: logo || fileUri(LogoText),
  logo_collapsed: logo_collapsed || fileUri(LogoCollapsed),
  borderRadius: 4,
  palette: {
    mode: 'dark',
    common: { white: '#ffffff', grey: '#7A7C85' },
    error: {
      main: '#f44336',
      dark: '#c62828',
    },
    success: { main: '#03a847' },
    primary: { main: primary || THEME_DARK_DEFAULT_PRIMARY },
    secondary: { main: secondary || THEME_DARK_DEFAULT_SECONDARY },
    border: {
      primary: hexToRGB((primary || THEME_DARK_DEFAULT_PRIMARY), 0.3),
      secondary: hexToRGB((secondary || THEME_DARK_DEFAULT_SECONDARY), 0.3),
      pagination: hexToRGB('#ffffff', 0.5),
    },
    pagination: {
      main: '#ffffff',
    },
    chip: { main: '#ffffff' },
    ee: {
      main: EE_COLOR,
      contrastText: '#ffffff',
      background: hexToRGB(EE_COLOR, 0.2),
      lightBackground: hexToRGB(EE_COLOR, 0.08),
    },
    background: {
      default: background || THEME_DARK_DEFAULT_BACKGROUND,
      paper: paper || THEME_DARK_DEFAULT_PAPER,
      nav: nav || THEME_DARK_DEFAULT_NAV,
      accent: accent || THEME_DARK_DEFAULT_ACCENT,
      shadow: 'rgba(255, 255, 255, 0)',
    },
  },
  typography: {
    fontFamily: '"IBM Plex Sans", sans-serif',
    body2: {
      fontSize: '0.8rem',
    },
    body1: {
      fontSize: '0.9rem',
    },
    overline: {
      fontWeight: 500,
    },
    h1: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 400,
      fontSize: 22,
      fontFamily: '"Geoligica", sans-serif',
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
      fontFamily: '"Geoligica", sans-serif',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#bebebe',
      fontWeight: 400,
      fontSize: 13,
      fontFamily: '"Geoligica", sans-serif',
    },
    h4: {
      height: 15,
      margin: '0 0 10px 0',
      padding: 0,
      textTransform: 'uppercase',
      fontSize: 12,
      fontWeight: 500,
      color: '#a8a8a8',
    },
    h5: {
      fontWeight: 400,
      fontSize: 13,
      textTransform: 'uppercase',
      marginTop: -4,
    },
    h6: {
      fontWeight: 400,
      fontSize: 18,
      color: primary || THEME_DARK_DEFAULT_PRIMARY,
      fontFamily: '"Geoligica", sans-serif',
    },
    subtitle2: {
      fontWeight: 400,
      fontSize: 18,
      color: 'rgba(255, 255, 255, 0.7)',
    },
  },
  components: {
    MuiAccordion: {
      defaultProps: {
        TransitionProps: {
          unmountOnExit: true,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          [`&.${buttonClasses.outlined}.${buttonClasses.sizeSmall}`]: {
            padding: '4px 9px',
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
      },
    },
    MuiFormControl: {
      defaultProps: {
        variant: 'standard',
      },
    },
    MuiTextField: {
      defaultProps: {
        variant: 'standard',
      },
    },
    MuiSelect: {
      defaultProps: {
        variant: 'standard',
      },
    },
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          scrollbarColor: `${background || THEME_DARK_DEFAULT_BACKGROUND} ${accent || THEME_DARK_DEFAULT_ACCENT}`,
          scrollbarWidth: 'thin',
        },
        body: {
          scrollbarColor: `${background || THEME_DARK_DEFAULT_BACKGROUND} ${accent || THEME_DARK_DEFAULT_ACCENT}`,
          scrollbarWidth: 'thin',
          html: {
            WebkitFontSmoothing: 'auto',
          },
          a: {
            color: primary || THEME_DARK_DEFAULT_PRIMARY,
          },
          'input:-webkit-autofill': {
            WebkitAnimation: 'autofill 0s forwards',
            animation: 'autofill 0s forwards',
            WebkitTextFillColor: '#ffffff !important',
            caretColor: 'transparent !important',
            WebkitBoxShadow:
              '0 0 0 1000px rgba(4, 8, 17, 0.88) inset !important',
            borderTopLeftRadius: 'inherit',
            borderTopRightRadius: 'inherit',
          },
          pre: {
            fontFamily: 'Consolas, monaco, monospace',
            color: '#ffffff !important',
            background: `${accent || THEME_DARK_DEFAULT_ACCENT} !important`,
            borderRadius: 4,
          },
          'pre.light': {
            fontFamily: 'Consolas, monaco, monospace',
            background: `${nav || THEME_DARK_DEFAULT_NAV} !important`,
            borderRadius: 4,
          },
          code: {
            fontFamily: 'Consolas, monaco, monospace',
            color: '#ffffff !important',
            background: `${accent || THEME_DARK_DEFAULT_ACCENT} !important`,
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
            borderBottom: '2px solid #f44336 !important',
            '&:hover': {
              border: '0 !important',
              borderBottom: '2px solid #f44336 !important',
            },
            '&:focus': {
              border: '0 !important',
              borderBottom: '2px solid #f44336 !important',
            },
          },
          '.mde-header': {
            border: '0 !important',
            backgroundColor: 'transparent !important',
            color: '#ffffff !important',
          },
          '.mde-header-item button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: '#ffffff !important',
          },
          '.mde-tabs button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: '#ffffff !important',
          },
          '.mde-textarea-wrapper textarea': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            fontSize: 13,
            color: '#ffffff',
            background: 'transparent',
            borderBottom: '1px solid rgba(255, 255, 255, 0.7) !important',
            transition: 'borderBottom .3s',
            '&:hover': {
              borderBottom: '2px solid #ffffff !important',
            },
            '&:focus': {
              borderBottom: `2px solid ${primary || THEME_DARK_DEFAULT_PRIMARY} !important`,
            },
          },
          '.mde-preview .mde-preview-content a': {
            color: `${primary || THEME_DARK_DEFAULT_PRIMARY} !important`,
          },
          '.react-grid-placeholder': {
            backgroundColor: `${accent || THEME_DARK_DEFAULT_ACCENT} !important`,
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
            backgroundColor: `${paper || THEME_DARK_DEFAULT_PAPER} !important`,
          },
          '.react-grid-item .react-resizable-handle::after': {
            borderRight: '2px solid rgba(255, 255, 255, 0.4) !important',
            borderBottom: '2px solid rgba(255, 255, 255, 0.4) !important',
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
          '&.Mui-selected': {
            boxShadow: `2px 0 ${primary || THEME_DARK_DEFAULT_PRIMARY} inset`,
          },
          '&.Mui-selected:hover': {
            boxShadow: `2px 0 ${primary || THEME_DARK_DEFAULT_PRIMARY} inset`,
          },
        },
      },
    },
  },
});

export default ThemeDark;
