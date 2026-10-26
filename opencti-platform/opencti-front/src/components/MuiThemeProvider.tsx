import React, { ReactNode } from 'react';
import { Theme, ThemeProvider } from '@mui/material/styles';
import { ThemeProvider as LegacyStylesThemeProvider } from '@mui/styles';

interface MuiThemeProviderProps {
  theme: Theme;
  children: ReactNode;
}

/**
 * Provides the theme to Material UI and to the legacy JSS APIs of `@mui/styles`
 * (makeStyles, withStyles, useTheme, withTheme).
 *
 * `@mui/styles` 6 bundles its own `@mui/private-theming`, so it does not see the
 * theme provided by Material UI 7's ThemeProvider. Replace this component with
 * Material UI's ThemeProvider once `@mui/styles` is removed.
 */
const MuiThemeProvider = ({ theme, children }: MuiThemeProviderProps) => (
  <ThemeProvider theme={theme}>
    <LegacyStylesThemeProvider theme={theme}>{children}</LegacyStylesThemeProvider>
  </ThemeProvider>
);

export default MuiThemeProvider;
