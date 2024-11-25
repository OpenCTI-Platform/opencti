import { buttonClasses } from '@mui/material/Button';
import type { ExtendedThemeOptions } from './Theme';
import { fileUri } from '../relay/environment';
import LogoText from '../static/images/logo_text_light.png';
import LogoCollapsed from '../static/images/logo_light.png';
import { hexToRGB, stringToColour } from '../utils/Colors';

const EE_COLOR = '#0c7e69';

export const THEME_LIGHT_DEFAULT_BACKGROUND = '#f8f8f8';
const THEME_LIGHT_DEFAULT_PRIMARY = '#001bda';
const THEME_LIGHT_DEFAULT_SECONDARY = '#0c7e69';
const THEME_LIGHT_DEFAULT_ACCENT = '#eeeeee';
const THEME_LIGHT_DEFAULT_PAPER = '#ffffff';
const THEME_LIGHT_DEFAULT_NAV = '#ffffff';

const ThemeLightEntities = {
  'Attack-Pattern': '#827717',
  'Case-Incident': '#ec407a',
  'Case-Rfi': '#3880b7',
  'Case-Rft': '#8e24aa',
  'Case-Feedback': '#006064',
  Task: '#283593',
  Campaign: '#ea80fc',
  Note: '#689f38',
  'Observed-Data': '#006064',
  Opinion: '#1976d2',
  Report: '#9c27b0',
  Grouping: '#8bc34a',
  'Course-Of-Action': '#689f38',
  Individual: '#9c27b0',
  User: '#9c27b0',
  Group: '#00bcd4',
  Capability: '#757575',
  Organization: '#0c5c98',
  Sector: '#2196f3',
  System: '#689f38',
  Event: '#006064',
  Indicator: '#b69007',
  Infrastructure: '#651fff',
  'Intrusion-Set': '#ff5622',
  City: '#006064',
  Country: '#283593',
  Region: '#689f38',
  'Administrative-Area': '#b69007',
  Position: '#827717',
  Malware: '#d68100',
  'Malware-Analysis': '#00acc1',
  'Threat-Actor-Group': '#e91e63',
  'Threat-Actor-Individual': '#9c27b0',
  Tool: '#986937',
  Channel: '#ec407a',
  Narrative: '#689f38',
  Language: '#d4e157',
  Vulnerability: '#795548',
  Incident: '#f44336',
  Dashboard: '#33691e',
  Investigation: '#33691e',
  Session: '#795548',
  Artifact: '#ff4081',
  'Stix-Cyber-Observable': stringToColour('Stix-Cyber-Observable'),
  'Autonomous-System': '#000000',
  Directory: '#000000',
  'Domain-Name': '#000000',
  'Email-Addr': '#000000',
  'Email-Message': '#000000',
  'Email-Mime-Part-Type': '#000000',
  StixFile: '#000000',
  'X509-Certificate': '#000000',
  'IPv4-Addr': '#000000',
  'IPv6-Addr': '#000000',
  'Mac-Addr': '#000000',
  Mutex: '#000000',
  'Network-Traffic': '#000000',
  Process: '#000000',
  Software: '#000000',
  Url: '#000000',
  'User-Account': '#000000',
  'Windows-Registry-Key': '#000000',
  'Windows-Registry-Value-Type': '#000000',
  'Cryptographic-Key': '#000000',
  'Cryptocurrency-Wallet': '#000000',
  Text: '#000000',
  'User-Agent': '#000000',
  'Bank-Account': '#000000',
  Credential: '#000000',
  'Tracking-Number': '#000000',
  'Phone-Number': '#000000',
  'Payment-Card': '#000000',
  'Media-Content': '#000000',
  Persona: '#000000',
};

const ThemeLightRelationships = {
  'Stix-Core-Relationship': '#9e9e9e',
  Relationship: '#9e9e9e',
  'stix-core-relationship': '#9e9e9e',
  targets: '#9e9e9e',
  uses: '#9e9e9e',
  'located-at': '#9e9e9e',
  'related-to': '#9e9e9e',
  mitigates: '#9e9e9e',
  impersonates: '#9e9e9e',
  indicates: '#9e9e9e',
  'comes-after': '#9e9e9e',
  'attributed-to': '#9e9e9e',
  'variant-of': '#9e9e9e',
  'part-of': '#9e9e9e',
  'employed-by': '#9e9e9e',
  'resides-in': '#9e9e9e',
  'citizen-of': '#9e9e9e',
  'national-of': '#9e9e9e',
  drops: '#9e9e9e',
  delivers: '#9e9e9e',
  compromises: '#9e9e9e',
  'belongs-to': '#9e9e9e',
  'based-on': '#9e9e9e',
  'communicates-with': '#9e9e9e',
  amplifies: '#9e9e9e',
  'analyses-of': '#9e9e9e',
  'authored-by': '#9e9e9e',
  'beacons-to': '#9e9e9e',
  characterizes: '#9e9e9e',
  'consists-of': '#9e9e9e',
  controls: '#9e9e9e',
  'cooperates-with': '#9e9e9e',
  'derived-from': '#9e9e9e',
  downloads: '#9e9e9e',
  has: '#9e9e9e',
  bcc: '#9e9e9e',
  cc: '#9e9e9e',
  'obs_belongs-to': '#9e9e9e',
  owns: '#9e9e9e',
  dst: '#9e9e9e',
  from: '#9e9e9e',
  hosts: '#9e9e9e',
  image: '#9e9e9e',
  publishes: '#9e9e9e',
  'duplicate-of': '#9e9e9e',
  obs_content: '#9e9e9e',
  'service-dll': '#9e9e9e',
  'dynamic-analyses-of': '#9e9e9e',
  contains: '#9e9e9e',
  'exfiltrates-to': '#9e9e9e',
  exploits: '#9e9e9e',
  investigates: '#9e9e9e',
  'originates-from': '#9e9e9e',
  'participates-in': '#9e9e9e',
  'body-multipart': '#9e9e9e',
  'body-raw': '#9e9e9e',
  child: '#9e9e9e',
  'creator-user': '#9e9e9e',
  detects: '#9e9e9e',
  'dst-payload': '#9e9e9e',
  'encapsulated-by': '#9e9e9e',
  encapsulates: '#9e9e9e',
  'opened-connection': '#9e9e9e',
  'operating-system': '#9e9e9e',
  parent: '#9e9e9e',
  'parent-directory': '#9e9e9e',
  'raw-email': '#9e9e9e',
  'src-payload': '#9e9e9e',
  remediates: '#9e9e9e',
  'resolves-to': '#9e9e9e',
  'obs_resolves-to': '#9e9e9e',
  'revoked-by': '#9e9e9e',
  sample: '#9e9e9e',
  sender: '#9e9e9e',
  src: '#9e9e9e',
  to: '#9e9e9e',
  values: '#9e9e9e',
  'static-analyses-of': '#9e9e9e',
  'subnarrative-of': '#9e9e9e',
  'subtechnique-of': '#9e9e9e',
  numberOfConnectedElement: '#9e9e9e',
  'known-as': '#9e9e9e',
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
): ExtendedThemeOptions => ({
  logo: logo || fileUri(LogoText),
  logo_collapsed: logo_collapsed || fileUri(LogoCollapsed),
  borderRadius: 4,
  palette: {
    mode: 'light',
    common: { white: '#ffffff', grey: '#494A50', lightGrey: 'rgba(0, 0, 0, 0.6)' },
    error: {
      main: '#f44336',
      dark: '#c62828',
    },
    warn: {
      main: '#ffa726',
    },
    dangerZone: { main: '#f6685e', light: '#fbc2be', dark: '#d1584f', contrastText: '#000000', text: { primary: '#d1584f' } },
    success: { main: '#03a847' },
    primary: { main: primary || THEME_LIGHT_DEFAULT_PRIMARY },
    secondary: { main: secondary || THEME_LIGHT_DEFAULT_SECONDARY },
    gradient: { main: '#00f1bd' },
    border: {
      lightBackground: hexToRGB('#000000', 0.15),
      primary: hexToRGB((primary || THEME_LIGHT_DEFAULT_PRIMARY), 0.3),
      secondary: hexToRGB((secondary || THEME_LIGHT_DEFAULT_SECONDARY), 0.3),
      pagination: hexToRGB('#000000', 0.5),
    },
    pagination: {
      main: '#000000',
    },
    chip: { main: '#000000' },
    ai: { main: '#9c27b0', light: '#ba68c8', dark: '#7b1fa2', contrastText: '#000000', text: { primary: '#673ab7' } },
    ee: {
      main: EE_COLOR,
      background: hexToRGB(EE_COLOR, 0.2),
      lightBackground: hexToRGB(EE_COLOR, 0.08),
      contrastText: '#ffffff',
    },
    background: {
      default: background || THEME_LIGHT_DEFAULT_BACKGROUND,
      paper: paper || THEME_LIGHT_DEFAULT_PAPER,
      nav: nav || THEME_LIGHT_DEFAULT_NAV,
      accent: accent || THEME_LIGHT_DEFAULT_ACCENT,
      shadow: 'rgba(0, 0, 0, .05)',
    },
    entities: ThemeLightEntities,
    relationships: ThemeLightRelationships,
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
      color: '#757575',
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
      color: '#505050',
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
      color: primary || THEME_LIGHT_DEFAULT_PRIMARY,
      fontFamily: '"Geologica", sans-serif',
    },
    subtitle2: {
      fontWeight: 400,
      fontSize: 18,
      color: 'rgba(0, 0, 0, 0.87)',
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
          scrollbarColor: `${accent || THEME_LIGHT_DEFAULT_ACCENT} ${paper || THEME_LIGHT_DEFAULT_PAPER}`,
          scrollbarWidth: 'thin',
        },
        body: {
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
            color: '#000000 !important',
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
            color: '#000000 !important',
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
            color: '#000000 !important',
          },
          '.mde-header-item button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: '#000000 !important',
          },
          '.mde-tabs button': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            color: '#000000 !important',
          },
          '.mde-textarea-wrapper textarea': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            fontSize: 13,
            color: 'rgba(0, 0, 0, 0.87)',
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
            color: `${primary || THEME_LIGHT_DEFAULT_PRIMARY} !important`,
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
            borderRight: '2px solid rgba(0, 0, 0, 0.6) !important',
            borderBottom: '2px solid rgba(0, 0, 0, 0.6) !important',
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
  },
});

export default ThemeLight;
