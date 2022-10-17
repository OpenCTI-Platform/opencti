import { PaletteOptions, TypeBackground } from '@mui/material/styles/createPalette';
import { ThemeOptions } from '@mui/material/styles/createTheme';

interface ExtendedBackground extends TypeBackground {
  nav: string,
  accent: string,
  shadow: string,
}

interface ExtendedPaletteOptions extends PaletteOptions {
  background?: Partial<ExtendedBackground>;
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null,
  palette?: ExtendedPaletteOptions;
}
