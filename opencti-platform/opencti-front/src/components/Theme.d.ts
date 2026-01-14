import { CommonColors, PaletteColorOptions, PaletteMode, PaletteOptions, TypeBackground, TypeText } from '@mui/material/styles/createPalette';
import { Theme as MuiTheme, ThemeOptions } from '@mui/material/styles/createTheme';

declare module '@mui/material/IconButton' {
  interface IconButtonPropsColorOverrides {
    ee: true;
    dangerZone: true;
  }
}

declare module '@mui/material/Button' {
  interface ButtonPropsColorOverrides {
    ee: true;
    dangerZone: true;
    pagination: true;
  }
}

declare module '@mui/material/ButtonGroup' {
  interface ButtonGroupPropsColorOverrides {
    pagination: true;
  }
}

declare module '@mui/material/SvgIcon' {
  interface SvgIconPropsColorOverrides {
    ee: true;
  }
}

declare module '@mui/material/Fab' {
  interface FabPropsColorOverrides {
    dangerZone: true;
  }
}

declare module '@mui/material/Alert' {
  interface AlertPropsColorOverrides {
    dangerZone: true;
    secondary: true;
    ee: true;
  }
}

declare module '@mui/material/styles' {
  interface Palette {
    border: {
      main: string;
      primary: string;
    };
    gradient?: {
      main: string;
      light: string;
      dark: string;
    };
    ai?: {
      main: string;
      contrastText: string;
      light?: string;
      dark?: string;
    };
    background: {
      paper: string;
      default: string;
      secondary: string;
      nav: string;
      popoverItem: string;
      drawer: string;
    };
    severity?: {
      critical: string;
      high: string;
      medium: string;
      low: string;
      info: string;
      none: string;
      default: string;
    };
  }

  interface PaletteOptions {
    border?: {
      main?: string;
      primary?: string;
    };
    gradient?: {
      main?: string;
      light?: string;
      dark?: string;
    };
    ai?: {
      main?: string;
      contrastText?: string;
      light?: string;
      dark?: string;
    };
    background?: {
      paper?: string;
      default?: string;
      secondary?: string;
      nav?: string;
      popoverItem?: string;
      drawer?: string;
    };
    severity?: {
      critical?: string;
      high?: string;
      medium?: string;
      low?: string;
      info?: string;
      clear?: string;
    };
  }

  interface Theme {
    logo: string | undefined;
    logo_collapsed: string | undefined;
    borderRadius: number;
    button: {
      sizes: {
        default: SizeConfig;
        small: SizeConfig;
      };
    };
    tag: {
      overflowColor: string;
    };
  }

  interface ThemeOptions {
    logo?: string | null;
    logo_collapsed?: string | null;
    borderRadius?: number;
    button?: {
      sizes?: {
        default?: SizeConfig;
        small?: SizeConfig;
      };
    };
    tag?: {
      overflowColor?: string;
    };
  }
}

export interface SizeConfig {
  height: string;
  padding: string;
  minWidth: string;
  width: string;
  fontSize: string;
  fontWeight: number;
  lineHeight: string;
  iconSize: string;
}

interface ExtendedColor extends PaletteColorOptions {
  main: string;
  dark: string;
  light: string;
  palette: ExtendedPaletteOptions;
  text: Partial<TypeText>;
  mode: PaletteMode;
  background: string;
  lightBackground: string;
  contrastText: string;
}

interface ExtendedBackground extends TypeBackground {
  nav: string;
  accent: string;
  shadow: string;
  secondary: string;
  gradient: {
    start: string;
    end: string;
  };
  drawer: string;
}

interface ExtendedText extends TypeText {
  light: string;
}

interface ExtendedPaletteOptions extends PaletteOptions {
  common: Partial<CommonColors & { grey: string; lightGrey: string }>;
  background: Partial<ExtendedBackground>;
  leftBar: {
    header: {
      itemBackground: string;
    };
    popoverItem: string;
  };
  border: {
    primary: string;
    secondary: string;
    pagination: string;
    main?: string;
    lightBackground?: string;
    paper?: string;
  };
  dangerZone: Partial<ExtendedColor>;
  primary: Partial<ExtendedColor>;
  error: Partial<ExtendedColor>;
  warn: Partial<ExtendedColor>;
  success: Partial<ExtendedColor>;
  chip: Partial<ExtendedColor>;
  pagination: Partial<ExtendedColor>;
  ee: Partial<ExtendedColor>;
  ai: Partial<ExtendedColor>;
  gradient: Partial<ExtendedColor>;
  secondary: Partial<ExtendedColor>;
  mode: PaletteMode;
  text: Partial<ExtendedText>;
  severity: {
    critical: string;
    high: string;
    medium: string;
    low: string;
    info: string;
    none: string;
    default: string;
  };
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null;
  logo_collapsed: string | null;
  palette: ExtendedPaletteOptions;
  borderRadius: number;
  button: {
    sizes: {
      default: SizeConfig;
      small: SizeConfig;
    };
  };
}

export interface Theme extends MuiTheme {
  logo: string | undefined;
  logo_collapsed: string | undefined;
  borderRadius: number;
  palette: ExtendedPaletteOptions;
  button: {
    sizes: {
      default: SizeConfig;
      small: SizeConfig;
    };
  };
}
