import { PaletteColorOptions, PaletteOptions, TypeBackground } from '@mui/material/styles/createPalette';
import { Theme as MuiTheme, ThemeOptions, Theme as MuiTheme } from '@mui/material/styles/createTheme';

interface ExtendedColor extends PaletteColorOptions {
  main: string
}

interface ExtendedBackground extends TypeBackground {
  nav: string
  accent: string
  shadow: string
}

interface ExtendedPaletteOptions extends PaletteOptions {
  background: Partial<ExtendedBackground>
  primary: Partial<ExtendedColor>
  error: Partial<ExtendedColor>
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null
  palette: ExtendedPaletteOptions
}

export interface Theme extends MuiTheme {
  palette: ExtendedPaletteOptions
}

export interface Theme extends MuiTheme {
  palette: ExtendedPaletteOptions;
}
