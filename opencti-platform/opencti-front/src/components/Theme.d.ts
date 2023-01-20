import {
  PaletteColorOptions,
  PaletteOptions,
  TypeBackground,
  TypeText,
  PaletteMode,
} from '@mui/material/styles/createPalette';
import {
  Theme as MuiTheme,
  ThemeOptions,
} from '@mui/material/styles/createTheme';

interface ExtendedColor extends PaletteColorOptions {
  main: string;
  palette: ExtendedPaletteOptions;
  text: Partial<TypeText>;
  mode: PaletteMode;
}

interface ExtendedBackground extends TypeBackground {
  nav: string;
  accent: string;
  shadow: string;
}

interface ExtendedPaletteOptions extends PaletteOptions {
  background: Partial<ExtendedBackground>;
  primary: Partial<ExtendedColor>;
  error: Partial<ExtendedColor>;
  chip: Partial<ExtendedColor>;
  secondary: Partial<ExtendedColor>;
  mode: PaletteMode;
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null;
  logo_collapsed: string | null;
  palette: ExtendedPaletteOptions;
}

export interface Theme extends MuiTheme {
  logo: string | undefined
  logo_collapsed: string | undefined
  palette: ExtendedPaletteOptions;
}
