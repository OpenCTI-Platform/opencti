import type { ExtendedThemeOptions } from './Theme';
import { fileUri } from '../relay/environment';
import LogoText from '../static/images/logo_text.png';
import LogoCollapsed from '../static/images/logo_dark.png';
import { hexToRGB } from '../utils/Colors';

const EE_COLOR = '#00f1bd';

export const THEME_DARK_DEFAULT_BACKGROUND = '#01020e'; // 0a1929
const THEME_DARK_DEFAULT_PRIMARY = '#0fbcff'; // 1c8eb6 // for road:
const THEME_DARK_DEFAULT_SECONDARY = '#00f1bd'; // d81b60
const THEME_DARK_DEFAULT_ACCENT = '#030721'; // 01478d // for building: 030721
const THEME_DARK_DEFAULT_PAPER = '#01020e'; // 001e3c
const THEME_DARK_DEFAULT_NAV = '#01020e'; // 071a2e

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
  borderRadius: 2,
  palette: {
    mode: 'dark',
    common: { white: '#ffffff' },
    error: {
      main: '#f44336',
      dark: '#c62828',
    },
    success: { main: '#03A847' },
    primary: { main: primary || THEME_DARK_DEFAULT_PRIMARY },
    secondary: { main: secondary || THEME_DARK_DEFAULT_SECONDARY },
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
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      color: '#bebebe',
      fontWeight: 400,
      fontSize: 13,
    },
    h4: {
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
          scrollbarColor: `${accent || THEME_DARK_DEFAULT_BACKGROUND} ${paper || THEME_DARK_DEFAULT_ACCENT}`,
          scrollbarWidth: 'thin',
        },
        body: {
          scrollbarColor: `${accent || THEME_DARK_DEFAULT_BACKGROUND} ${paper || THEME_DARK_DEFAULT_ACCENT}`,
          scrollbarWidth: 'thin',
          '&::-webkit-scrollbar, & *::-webkit-scrollbar': {
            backgroundColor: paper || THEME_DARK_DEFAULT_ACCENT,
          },
          '&::-webkit-scrollbar-thumb, & *::-webkit-scrollbar-thumb': {
            borderRadius: 8,
            backgroundColor: accent || THEME_DARK_DEFAULT_BACKGROUND,
            minHeight: 24,
            border: `3px solid ${paper || THEME_DARK_DEFAULT_ACCENT}`,
          },
          '&::-webkit-scrollbar-thumb:focus, & *::-webkit-scrollbar-thumb:focus':
            {
              backgroundColor: accent || THEME_DARK_DEFAULT_BACKGROUND,
            },
          '&::-webkit-scrollbar-thumb:active, & *::-webkit-scrollbar-thumb:active':
            {
              backgroundColor: accent || THEME_DARK_DEFAULT_BACKGROUND,
            },
          '&::-webkit-scrollbar-thumb:hover, & *::-webkit-scrollbar-thumb:hover':
            {
              backgroundColor: accent || THEME_DARK_DEFAULT_BACKGROUND,
            },
          '&::-webkit-scrollbar-corner, & *::-webkit-scrollbar-corner': {
            backgroundColor: accent || THEME_DARK_DEFAULT_BACKGROUND,
          },
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
          },
          'pre.light': {
            fontFamily: 'Consolas, monaco, monospace',
            background: `${nav || THEME_DARK_DEFAULT_NAV} !important`,
          },
          code: {
            fontFamily: 'Consolas, monaco, monospace',
            color: '#ffffff !important',
            background: `${accent || THEME_DARK_DEFAULT_ACCENT} !important`,
            padding: 3,
            fontSize: 12,
            fontWeight: 400,
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
