import { buttonClasses } from '@mui/material/Button';
import type { ExtendedThemeOptions } from './Theme';
import LogoText from '../static/images/logo_text_dark.svg';
import LogoCollapsed from '../static/images/logo_dark.svg';
import { hexToRGB } from '../utils/Colors';
import { alpha, darken, lighten } from '@mui/material';
import { FDS } from './fds-tokens.generated';

const EE_COLOR = '#00f18d';

export const THEME_DARK_DEFAULT_BACKGROUND = FDS.colors.dark['--bg-elevation-default-layer-0'];
const THEME_DARK_DEFAULT_BODY_END_GRADIENT = FDS.colors.dark['--bg-elevation-default-layer-0-gradient'];
export const THEME_DARK_DEFAULT_PRIMARY = FDS.colors.dark['--color-filigran-brand-primary'];
export const THEME_DARK_DEFAULT_SECONDARY = FDS.colors.dark['--color-filigran-tonic-primary'];
export const THEME_DARK_DEFAULT_ACCENT = FDS.colors.dark['--bg-elevation-default-layer-3'];
export const THEME_DARK_DEFAULT_PAPER = FDS.colors.dark['--bg-elevation-default-layer-1'];
export const THEME_DARK_DEFAULT_TEXT = FDS.colors.dark['--text-default-primary'];
const THEME_DARK_DEFAULT_NAV = FDS.colors.dark['--bg-elevation-heading-layer-0'];
export const THEME_DARK_DIALOG_BACKGROUND = '#0F1D34';

const getAppBodyGradientEndColor = (background: string | null): string => {
  if (background && background !== THEME_DARK_DEFAULT_BACKGROUND) {
    return lighten(background, 0.05);
  }
  return THEME_DARK_DEFAULT_BODY_END_GRADIENT;
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
  text_color: string = THEME_DARK_DEFAULT_TEXT,
): ExtendedThemeOptions => ({
  logo: logo || LogoText,
  logo_collapsed: logo_collapsed || LogoCollapsed,
  borderRadius: 4,
  palette: {
    mode: 'dark',
    common: { white: '#ffffff', grey: '#95969D', lightGrey: '#E4E5E7' },
    error: {
      main: FDS.colors.dark['--color-feedback-error-primary'],
      dark: FDS.colors.dark['--color-feedback-error-secondary'],
    },
    warn: {
      main: FDS.colors.dark['--color-feedback-warning-primary'],
    },
    dangerZone: {
      main: FDS.colors.dark['--color-feedback-error-primary'],
      light: FDS.colors.dark['--color-feedback-error-tertiary'],
      dark: FDS.colors.dark['--color-feedback-error-secondary'],
      contrastText: '#000000',
      text: { primary: FDS.colors.dark['--color-feedback-error-tertiary'] } },
    success: { main: FDS.colors.dark['--color-feedback-success-primary'], dark: FDS.colors.dark['--color-feedback-success-secondary'] },
    primary: { main: primary || THEME_DARK_DEFAULT_PRIMARY, light: primary ? alpha(primary, 0.08) : FDS.colors.dark['--color-filigran-brand-secondary'] },
    secondary: { main: secondary || THEME_DARK_DEFAULT_SECONDARY },
    gradient: { main: '#00f18d' },
    border: {
      primary: hexToRGB((primary || THEME_DARK_DEFAULT_PRIMARY), 0.3),
      secondary: '#424751',
      pagination: hexToRGB('#ffffff', 0.5),
      paper: hexToRGB('#ffffff', 0.12),
      main: '#252A35',
    },
    pagination: {
      main: '#ffffff',
    },
    chip: { main: '#ffffff' },
    ai: {
      main: FDS.colors.dark['--color-filigran-ia-primary'],
      light: FDS.colors.dark['--color-filigran-ia-secondary'],
      dark: FDS.colors.dark['--color-filigran-ia-tertiary'],
      contrastText: '#000000',
      background: 'rgba(28, 47, 73, 0.94)',
    },
    ee: {
      main: EE_COLOR,
      contrastText: THEME_DARK_DEFAULT_TEXT,
      background: hexToRGB(EE_COLOR, 0.2),
      lightBackground: hexToRGB(EE_COLOR, 0.08),
    },
    // Aligned with the OpenAEV xtmhub token so the Filigran Experience
    // screens share the same accent on both platforms.
    xtmhub: { main: '#00f1bd' },
    background: {
      default: background || THEME_DARK_DEFAULT_BACKGROUND,
      paper: paper || THEME_DARK_DEFAULT_PAPER,
      nav: nav || THEME_DARK_DEFAULT_NAV,
      accent: accent || THEME_DARK_DEFAULT_ACCENT,
      shadow: 'rgba(200, 200, 200, 0.15)',
      // the only way for now to know if we should apply the paper color or not
      secondary: paper === THEME_DARK_DEFAULT_PAPER
        ? '#0C1524'
        : (paper ?? '#0C1524'),
      drawer: nav === THEME_DARK_DEFAULT_NAV
        ? '#0f1d34'
        : (darken(nav ?? '#0f1d34', 0.5)),

      disabled: '#363B46',
      gradient: {
        start: background || THEME_DARK_DEFAULT_BACKGROUND,
        end: getAppBodyGradientEndColor(background),
      },
    },
    text: {
      secondary: THEME_DARK_DEFAULT_TEXT,
      tertiary: '#848592',
      light: '#AFB0B6',
      disabled: '#75829A',
    },
    leftBar: {
      header: {
        itemBackground: '#253348',
      },
      popoverItem: THEME_DARK_DEFAULT_BACKGROUND,
      hover: '#253348',
      text: '#F2F2F3',
    },
    severity: {
      // critical/high/medium/low/info mapped to the closest FDS feedback
      // token (not 1:1 — see TOKEN-MAPPING.md). none/default now share the
      // neutral feedback token (both are semantically "no severity set");
      // this makes the two visually identical for the first time.
      critical: FDS.colors.dark['--color-feedback-error-primary'],
      high: FDS.colors.dark['--color-feedback-warning-primary'],
      medium: FDS.colors.dark['--color-feedback-alert-primary'],
      low: FDS.colors.dark['--color-feedback-success-primary'],
      info: FDS.colors.dark['--color-feedback-info-primary'],
      none: FDS.colors.dark['--color-feedback-neutral-primary'],
      default: FDS.colors.dark['--color-feedback-neutral-primary'],
    },
    // This block used to be hand-copied from Figma exports — every value
    // below is now sourced from the generated FDS bridge (fds-tokens.generated.ts).
    // Where no confident FDS equivalent exists, the original hardcoded value
    // is kept as-is; see fds-migration/TOKEN-MAPPING.md for the full rationale.
    designSystem: {
      // "filigran-brand" family: light/dark are the -secondary/-tertiary
      // tiers of the same family as `main`.
      primary: {
        main: FDS.colors.dark['--color-filigran-brand-primary'],
        light: FDS.colors.dark['--color-filigran-brand-secondary'],
        dark: FDS.colors.dark['--color-filigran-brand-tertiary'],
      },
      // "filigran-tonic" family.
      secondary: {
        main: FDS.colors.dark['--color-filigran-tonic-primary'],
        light: FDS.colors.dark['--color-filigran-tonic-secondary'],
        dark: FDS.colors.dark['--color-filigran-tonic-tertiary'],
      },
      // No dedicated "destructive" family in FDS - feedback-error is the closest match.
      destructive: {
        main: FDS.colors.dark['--color-feedback-error-primary'],
        light: FDS.colors.dark['--color-feedback-error-tertiary'],
        dark: FDS.colors.dark['--color-feedback-error-secondary'],
      },
      // "filigran-ia" family.
      ia: {
        main: FDS.colors.dark['--color-filigran-ia-primary'],
        light: FDS.colors.dark['--color-filigran-ia-secondary'],
        dark: FDS.colors.dark['--color-filigran-ia-tertiary'],
      },
      background: {
        main: THEME_DARK_DEFAULT_BACKGROUND,
        // bg1-bg4 map to the elevation-layer scale (layer-0..3, darkest to
        // lightest); disabled uses the dedicated disabled-elevation token.
        bg1: FDS.colors.dark['--bg-elevation-default-layer-0'],
        bg2: FDS.colors.dark['--bg-elevation-default-layer-1'],
        bg3: FDS.colors.dark['--bg-elevation-default-layer-2'],
        bg4: FDS.colors.dark['--bg-elevation-default-layer-3'],
        disabled: FDS.colors.dark['--bg-elevation-disabled'],
      },
      // main uses the default elevation border; border1/border2 share the
      // subtle elevation border (see TOKEN-MAPPING.md).
      border: {
        main: FDS.colors.dark['--border-elevation-default'],
        border1: FDS.colors.dark['--border-elevation-subtle'],
        border2: FDS.colors.dark['--border-elevation-subtle'],
      },
      gradient: {
        background: FDS.gradients.dark['--gradient-default'],
        ia: FDS.gradients.dark['--gradient-ia'],
        focus: FDS.gradients.dark['--gradient-focus'],
      },
      alert: {
        info: {
          primary: FDS.colors.dark['--color-feedback-info-primary'],
          secondary: FDS.colors.dark['--color-feedback-info-secondary'],
        },
        success: {
          primary: FDS.colors.dark['--color-feedback-success-primary'],
          secondary: FDS.colors.dark['--color-feedback-success-secondary'],
          tertiary: FDS.colors.dark['--color-feedback-success-tertiary'],
        },
        alert: {
          primary: FDS.colors.dark['--color-feedback-alert-primary'],
          secondary: FDS.colors.dark['--color-feedback-alert-secondary'],
        },
        warning: {
          primary: FDS.colors.dark['--color-feedback-warning-primary'],
          secondary: FDS.colors.dark['--color-feedback-warning-secondary'],
        },
        error: {
          primary: FDS.colors.dark['--color-feedback-error-primary'],
          secondary: FDS.colors.dark['--color-feedback-error-secondary'],
        },
      },
      tertiary: {
        grey: {
          400: FDS.scalars['--gray-400'],
          700: FDS.scalars['--gray-700'],
          800: FDS.scalars['--gray-800'],
        },
        // Mapped to the opaque feedback-info-secondary token (not its
        // -transparency sibling proposed by the guide — see TOKEN-MAPPING.md,
        // ScaleBar.tsx needs a solid fill). .500/.900 now share one value;
        // .900 has zero live consumers today (same note in the guide itself).
        blue: {
          500: FDS.colors.dark['--color-feedback-info-secondary'],
          900: FDS.colors.dark['--color-feedback-info-secondary'],
        },
        darkBlue: {
          300: FDS.scalars['--darkblue-300'],
          500: FDS.scalars['--darkblue-500'],
        },
        turquoise: {
          600: FDS.scalars['--turquoise-600'],
          800: FDS.scalars['--turquoise-800'],
        },
        green: {
          400: FDS.scalars['--green-400'],
          600: FDS.scalars['--green-600'],
          800: FDS.scalars['--green-800'],
        },
        red: {
          100: FDS.scalars['--red-100'],
          200: FDS.scalars['--red-200'],
          400: FDS.scalars['--red-400'],
          500: FDS.scalars['--red-500'],
          600: FDS.scalars['--red-600'],
          700: FDS.scalars['--red-700'],
        },
        orange: {
          400: FDS.scalars['--orange-400'],
          500: FDS.scalars['--orange-500'],
        },
        yellow: {
          400: FDS.scalars['--yellow-400'],
        },
      },
    },
  },
  tag: {
    overflowColor: primary || THEME_DARK_DEFAULT_PRIMARY,
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
      fontWeight: 400,
      fontSize: 13,
      fontFamily: '"Geologica", sans-serif',
      color: text_color,
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
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          // Sandy's ruling: a dialog is treated EXACTLY like a drawer, which
          // means the same paper colour. The drawer's paper reads
          // `--bg-elevation-default` at layer 2; this used to be a hardcoded
          // hex that resolved to a different shade, which is why the two
          // surfaces never matched. Every dialog paper now declares layer 2
          // (the shared Dialog, and every direct MUI mount), so the alias lands
          // on the same value. A platform-customised paper colour still wins.
          backgroundColor: paper === THEME_DARK_DEFAULT_PAPER
            ? 'var(--bg-elevation-default)'
            : (paper ?? 'var(--bg-elevation-default)'),
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
          // Override the default margin-left
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
            border: '1px solid #2B3447',
            color: primary,

            '&:focus-visible': {
              outline: 'none',
              boxShadow: '0 0 0 2px #BDFFED',
            },

            '&.Mui-selected': {
              backgroundColor: hexToRGB(primary || THEME_DARK_DEFAULT_PRIMARY, 0.25),
            },

            '&:hover:not(.Mui-selected)': {
              backgroundColor: hexToRGB(primary || THEME_DARK_DEFAULT_PRIMARY, 0.15),
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
    // Interim homogenisation (night-3 visual pass). Every MUI field that is
    // OUTLINED now sits on the same background as a library Input --
    // `--bg-input-default` -- so the fields still waiting for a conversion read
    // as one family with the converted ones instead of as a second set.
    //
    // Deliberately scoped to the outlined variant, and deliberately NOT paired
    // with a flip of `MuiTextField.defaultProps.variant` to `outlined`: that
    // one line would change the height, the label behaviour and the hit area of
    // every remaining MUI field at once, which is a change to look at on
    // screenshots before it lands, and e2e resolves many of those fields by
    // their label. The fields the pass named by hand are switched at their own
    // call sites instead.
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          // Layer-aware on purpose. This used to be the STATIC hex exported for
          // `--bg-input-default`, so an outlined field kept the layer-0 colour
          // even inside a drawer, a dialog or a filter popover that had
          // correctly declared layer 2. Reading the custom property instead
          // makes every outlined field pick up the surface it actually sits on.
          backgroundColor: 'var(--bg-input-default)',
          // Geometry borrowed from the library `Input` (h-9, rounded-sm,
          // pl-3/pr-2, transparent resting border, token border on hover and
          // focus) so a MUI field standing next to a library one reads as the
          // same control. Behaviour is untouched — this is paint only.
          borderRadius: 'var(--radius-sm)',
          minHeight: 36,
          '& .MuiOutlinedInput-notchedOutline': {
            borderColor: 'transparent',
          },
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: 'var(--border-input-hover)',
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: 'var(--border-input-focus)',
          },
          '&.Mui-error .MuiOutlinedInput-notchedOutline': {
            borderColor: 'var(--border-input-error)',
          },
          '&.Mui-disabled': {
            backgroundColor: 'var(--bg-input-disabled)',
          },
        },
        input: {
          // MUI's outlined input pads 16.5px vertically, which makes a 54px
          // row next to the library's 36px one. 8px lands the single-line row
          // on the library's height; `minHeight` above keeps the floor, and
          // multiline inputs still grow from their own rows.
          padding: '8px 8px 8px 12px',
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        // Sandy's standing ruling: every remaining MUI field is outlined,
        // so it can carry the same background as the library fields beside
        // it. This is the default for the mounts that name no variant; the
        // ones that named `standard` explicitly were swept in the same change.
        variant: 'outlined',
      },
      styleOverrides: {
        root: {
          color: text_color,
          // Shrink = when at the top of the input in small size.
          '& .MuiFormLabel-root:not(.MuiInputLabel-shrink):not(.Mui-error)': {
            color: '#AFB0B6',
          },
        },
      },
    },
    MuiSelect: {
      defaultProps: {
        // Sandy's standing ruling: every remaining MUI field is outlined,
        // so it can carry the same background as the library fields beside
        // it. This is the default for the mounts that name no variant; the
        // ones that named `standard` explicitly were swept in the same change.
        variant: 'outlined',
      },
      styleOverrides: {
        root: {
          color: text_color,
          '& fieldset': {
            border: 'none',
          },
        },
        outlined: {
          backgroundColor: paper === THEME_DARK_DEFAULT_PAPER
            ? '#0C1524'
            : (paper ?? '#0C1524'),
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
          scrollbarColor: `${background || THEME_DARK_DEFAULT_BACKGROUND} ${accent || THEME_DARK_DEFAULT_ACCENT}`,
          scrollbarWidth: 'thin',
          background: `linear-gradient(100deg, ${background || THEME_DARK_DEFAULT_BACKGROUND} 0%, ${getAppBodyGradientEndColor(background)} 100%)`,
          backgroundAttachment: 'fixed',
          backgroundColor: background || THEME_DARK_DEFAULT_BACKGROUND,
        },
        body: {
          background: `linear-gradient(100deg, ${background || THEME_DARK_DEFAULT_BACKGROUND} 0%, ${getAppBodyGradientEndColor(background)} 100%)`,
          backgroundAttachment: 'fixed',
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
            color: `${text_color} !important`,
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
            color: `${text_color} !important`,
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
            border: '1px solid var(--border-input-error) !important',
            '&:hover': {
              border: '1px solid var(--border-input-error) !important',
            },
            '&:focus': {
              border: '1px solid var(--border-input-error) !important',
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
          // The markdown editor is a textarea like any other field, so it takes
          // the field surface instead of the bare underline it had. Written in
          // tokens, which makes it layer-aware for free: inside a drawer or a
          // dialog `--bg-input-default` resolves to that surface's own layer
          // (#0c1527), and at page level it stays layer 0.
          '.mde-textarea-wrapper textarea': {
            fontFamily: '"IBM Plex Sans", sans-serif',
            fontSize: 13,
            color: text_color,
            background: 'var(--bg-input-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '8px 12px',
            border: '1px solid transparent !important',
            transition: 'border-color .3s',
            '&:hover': {
              border: '1px solid var(--border-input-hover) !important',
            },
            '&:focus': {
              border: '1px solid var(--border-input-focus) !important',
            },
          },
          '.mde-preview .mde-preview-content a': {
            color: `${text_color} !important`,
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
    MuiMenu: {
      styleOverrides: {
        paper: {
          // The library's menu surface: `bg-elevation-highlight`, 4px radius,
          // and no padding of its own (rows run edge to edge). Written as the
          // alias so a menu opened from a layered surface follows it.
          backgroundColor: 'var(--bg-elevation-highlight)',
          borderRadius: 'var(--radius-sm)',
        },
        list: {
          paddingTop: 0,
          paddingBottom: 0,
        },
      },
    },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          // Geometry moved toward the library's own menu row (SelectItem:
          // min-h-8, gap-2, pl-4/pr-2, 12px compact type, 16px leading glyph).
          // The selected and hover tones below are deliberately left as they
          // are — this is spacing and size only, no behaviour and no colour.
          minHeight: 32,
          paddingLeft: 16,
          paddingRight: 8,
          gap: 8,
          fontSize: 12,
          lineHeight: 1.5,
          '& .MuiListItemIcon-root': {
            minWidth: 'auto',
          },
          '& .MuiSvgIcon-root': {
            fontSize: 16,
          },
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
            color: '#AFB0B6',
          },
          '& .MuiOutlinedInput-root': {
            // Same layer-aware background as every other outlined field; the
            // hardcoded hex this used to carry was a near-miss of the token's
            // own value and could not follow a surface's layer.
            backgroundColor: paper === THEME_DARK_DEFAULT_PAPER
              ? 'var(--bg-input-default)'
              : (paper ?? 'var(--bg-input-default)'),
            '& fieldset': {
              borderColor: 'transparent',
            },
          },
        },
      },
    },

  },
});

export default ThemeDark;
