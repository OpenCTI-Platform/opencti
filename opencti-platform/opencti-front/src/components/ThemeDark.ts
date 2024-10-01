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

const ThemeDarkEntities = {
  'Attack-Pattern': '#d4e157',
  'Case-Incident': '#ad1457',
  'Case-Rfi': '#0c5c98',
  'Case-Rft': '#ea80fc',
  'Case-Feedback': '#00acc1',
  Task: '#304ffe',
  Campaign: '#8e24aa',
  Note: '#33691e',
  'Observed-Data': '#00acc1',
  Opinion: '#1565c0',
  Report: '#4a148c',
  Grouping: '#689f38',
  'Course-Of-Action': '#8bc34a',
  Individual: '#9c27b0',
  User: '#9c27b0',
  Group: '#006064',
  Capability: '#424242',
  Organization: '#3880b7',
  Sector: '#0d47a1',
  System: '#8bc34a',
  Event: '#00acc1',
  Indicator: '#ffc107',
  Infrastructure: '#512da8',
  'Intrusion-Set': '#bf360c',
  City: '#00acc1',
  Country: '#304ffe',
  Region: '#33691e',
  'Administrative-Area': '#ffc107',
  Position: '#00acc1',
  Malware: '#ff9800',
  'Malware-Analysis': '#006064',
  'Threat-Actor-Group': '#880e4f',
  'Threat-Actor-Individual': '#4a148c',
  Tool: '#986937',
  Channel: '#ad1457',
  Narrative: '#8bc34a',
  Language: '#afb42b',
  Vulnerability: '#5d4037',
  Incident: '#f44336',
  Dashboard: '#689f38',
  Investigation: '#689f38',
  Session: '#5d4037',
  Artifact: '#f2699c',
  'Stix-Cyber-Observable': '#84ffff',
  'Autonomous-System': '#84ffff',
  Directory: '#84ffff',
  'Domain-Name': '#84ffff',
  'Email-Addr': '#84ffff',
  'Email-Message': '#84ffff',
  'Email-Mime-Part-Type': '#84ffff',
  StixFile: '#84ffff',
  'X509-Certificate': '#84ffff',
  'IPv4-Addr': '#84ffff',
  'IPv6-Addr': '#84ffff',
  'Mac-Addr': '#84ffff',
  Mutex: '#84ffff',
  'Network-Traffic': '#84ffff',
  Process: '#84ffff',
  Software: '#84ffff',
  Url: '#84ffff',
  'User-Account': '#84ffff',
  'Windows-Registry-Key': '#84ffff',
  'Windows-Registry-Value-Type': '#84ffff',
  'Cryptographic-Key': '#84ffff',
  'Cryptocurrency-Wallet': '#84ffff',
  Text: '#84ffff',
  'User-Agent': '#84ffff',
  'Bank-Account': '#84ffff',
  Credential: '#84ffff',
  'Tracking-Number': '#84ffff',
  'Phone-Number': '#84ffff',
  'Payment-Card': '#84ffff',
  'Media-Content': '#84ffff',
  Persona: '#84ffff',
};

const ThemeDarkRelationships = {
  'Stix-Core-Relationship': '#616161',
  Relationship: '#616161',
  'stix-core-relationship': '#616161',
  targets: '#616161',
  uses: '#616161',
  'located-at': '#616161',
  'related-to': '#616161',
  mitigates: '#616161',
  impersonates: '#616161',
  indicates: '#616161',
  'comes-after': '#616161',
  'attributed-to': '#616161',
  'variant-of': '#616161',
  'part-of': '#616161',
  'employed-by': '#616161',
  'resides-in': '#616161',
  'citizen-of': '#616161',
  'national-of': '#616161',
  drops: '#616161',
  delivers: '#616161',
  compromises: '#616161',
  'belongs-to': '#616161',
  'based-on': '#616161',
  'communicates-with': '#616161',
  amplifies: '#616161',
  'analyses-of': '#616161',
  'authored-by': '#616161',
  'beacons-to': '#616161',
  characterizes: '#616161',
  'consists-of': '#616161',
  controls: '#616161',
  'cooperates-with': '#616161',
  'derived-from': '#616161',
  downloads: '#616161',
  has: '#616161',
  bcc: '#616161',
  cc: '#616161',
  'obs_belongs-to': '#616161',
  owns: '#616161',
  dst: '#616161',
  from: '#616161',
  hosts: '#616161',
  image: '#616161',
  publishes: '#616161',
  'duplicate-of': '#616161',
  obs_content: '#616161',
  'service-dll': '#616161',
  'dynamic-analyses-of': '#616161',
  contains: '#616161',
  'exfiltrates-to': '#616161',
  exploits: '#616161',
  investigates: '#616161',
  'originates-from': '#616161',
  'participates-in': '#616161',
  'body-multipart': '#616161',
  'body-raw': '#616161',
  child: '#616161',
  'creator-user': '#616161',
  detects: '#616161',
  'dst-payload': '#616161',
  'encapsulated-by': '#616161',
  encapsulates: '#616161',
  'opened-connection': '#616161',
  'operating-system': '#616161',
  parent: '#616161',
  'parent-directory': '#616161',
  'raw-email': '#616161',
  'src-payload': '#616161',
  remediates: '#616161',
  'resolves-to': '#616161',
  'obs_resolves-to': '#616161',
  'revoked-by': '#616161',
  sample: '#616161',
  sender: '#616161',
  src: '#616161',
  to: '#616161',
  values: '#616161',
  'static-analyses-of': '#616161',
  'subnarrative-of': '#616161',
  'subtechnique-of': '#616161',
  numberOfConnectedElement: '#616161',
  'known-as': '#616161',
};

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
    common: { white: '#ffffff', grey: '#7A7C85', lightGrey: '#ffffffb3' },
    error: {
      main: '#f44336',
      dark: '#c62828',
    },
    warn: {
      main: '#ffa726',
    },
    dangerZone: { main: '#f6685e', light: '#fbc2be', dark: '#f44336', contrastText: '#000000', text: { primary: '#fbc2be' } },
    success: { main: '#03a847' },
    primary: { main: primary || THEME_DARK_DEFAULT_PRIMARY },
    secondary: { main: secondary || THEME_DARK_DEFAULT_SECONDARY },
    gradient: { main: '#00f1bd' },
    border: {
      primary: hexToRGB((primary || THEME_DARK_DEFAULT_PRIMARY), 0.3),
      secondary: hexToRGB((secondary || THEME_DARK_DEFAULT_SECONDARY), 0.3),
      pagination: hexToRGB('#ffffff', 0.5),
    },
    pagination: {
      main: '#ffffff',
    },
    chip: { main: '#ffffff' },
    ai: { main: '#9575cd', light: '#d1c4e9', dark: '#673ab7', contrastText: '#000000', text: { primary: '#9575cd' } },
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
    entities: ThemeDarkEntities,
    relationships: ThemeDarkRelationships,
  },
  typography: {
    fontFamily: '"IBM Plex Sans", sans-serif',
    body2: {
      fontSize: '0.8rem',
      lineHeight: '1.2rem',
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
      fontFamily: '"Geologica", sans-serif',
    },
    h2: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 500,
      fontSize: 16,
      textTransform: 'uppercase',
      fontFamily: '"Geologica", sans-serif',
    },
    h3: {
      margin: '0 0 10px 0',
      padding: 0,
      fontWeight: 400,
      fontSize: 13,
      fontFamily: '"Geologica", sans-serif',
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
      fontFamily: '"Geologica", sans-serif',
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
            borderColor: hexToRGB('#ffffff', 0.15),
            padding: 7,
            minWidth: 0,
            '&:hover': {
              borderColor: hexToRGB('#ffffff', 0.15),
              backgroundColor: hexToRGB('#ffffff', 0.05),
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
            backgroundColor: `${hexToRGB(primary || THEME_DARK_DEFAULT_PRIMARY, 0.24)}`,
          },
          '&.Mui-selected:hover': {
            boxShadow: `2px 0 ${primary || THEME_DARK_DEFAULT_PRIMARY} inset`,
            backgroundColor: `${hexToRGB(primary || THEME_DARK_DEFAULT_PRIMARY, 0.32)}`,
          },
        },
      },
    },
  },
});

export default ThemeDark;
