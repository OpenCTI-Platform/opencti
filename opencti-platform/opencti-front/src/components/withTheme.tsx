import React, { ComponentType } from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';

// Hands the theme to class components, which cannot call useTheme themselves.
const withTheme = <P extends object>(WrappedComponent: ComponentType<P & { theme: Theme }>) => {
  const WithTheme = (props: P) => <WrappedComponent {...props} theme={useTheme<Theme>()} />;
  WithTheme.displayName = `WithTheme(${
    WrappedComponent.displayName || WrappedComponent.name || 'Component'
  })`;
  return WithTheme;
};

export default withTheme;
