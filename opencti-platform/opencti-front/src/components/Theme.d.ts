import { CommonColors, PaletteColorOptions, PaletteMode, PaletteOptions, TypeBackground, TypeText } from '@mui/material/styles/createPalette';
import { Theme as MuiTheme, ThemeOptions } from '@mui/material/styles/createTheme';

declare module '@mui/material/IconButton' {
  interface IconButtonPropsColorOverrides {
    ee: true
  }
}

declare module '@mui/material/Button' {
  interface ButtonPropsColorOverrides {
    ee: true
    pagination: true
  }
}

declare module '@mui/material/ButtonGroup' {
  interface ButtonGroupPropsColorOverrides {
    pagination: true
  }
}

declare module '@mui/material/SvgIcon' {
  interface SvgIconPropsColorOverrides {
    ee: true
  }
}

interface ExtendedColor extends PaletteColorOptions {
  main: string
  dark: string
  palette: ExtendedPaletteOptions
  text: Partial<TypeText>
  mode: PaletteMode
  background: string
  lightBackground: string
  contrastText: string
}

interface ExtendedBackground extends TypeBackground {
  nav: string
  accent: string
  shadow: string
}

interface ExtendedPaletteOptions extends PaletteOptions {
  common: Partial<CommonColors & { grey: string }>
  background: Partial<ExtendedBackground>
  border: {
    primary: string
    secondary: string
    pagination: string
    lightBackground?: string
  }
  primary: Partial<ExtendedColor>
  error: Partial<ExtendedColor>
  success: Partial<ExtendedColor>
  chip: Partial<ExtendedColor>
  pagination: Partial<ExtendedColor>
  ee: Partial<ExtendedColor>
  secondary: Partial<ExtendedColor>
  mode: PaletteMode
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null
  logo_collapsed: string | null
  palette: ExtendedPaletteOptions
  borderRadius: number
}

export interface Theme extends MuiTheme {
  logo: string | undefined
  logo_collapsed: string | undefined
  borderRadius: number
  palette: ExtendedPaletteOptions
}
