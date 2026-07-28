import { type MutableRefObject, useEffect } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../components/Theme';

/**
 * Bridges the app's MUI `theme.palette.mode` to the `.dark`/`.light`
 * scoping classes that FDS components (`@filigran/design-system`) rely on
 * for their CSS custom properties, applied to an arbitrary container
 * instead of `<html>`/`<body>`.
 *
 * This generalizes the ad hoc pattern already in production in
 * `AskArianePanel.tsx` (`isDarkMode = theme.palette.mode === 'dark'`
 * toggling a single `'dark'` class on its portal container): it reads the
 * exact same source, but always sets exactly one of `dark`/`light` (the
 * original only ever set `dark` or nothing) and stays reactive to theme
 * changes that happen after mount — e.g. a user flipping dark/light in
 * Settings.
 *
 * Attach `containerRef` to the root of whichever subtree renders FDS
 * components. Never point it at `document.documentElement`/`document.body`:
 * FDS scoping is meant to nest per-subtree, not replace the app-wide
 * `data-theme` attribute already managed by `useDocumentThemeModifier`.
 *
 * This hook only wires the classes — it isn't applied to any component
 * yet, that's a deliberate separate step for each future consumer.
 */
const useFdsThemeScope = (containerRef: MutableRefObject<HTMLDivElement | null>) => {
  const theme = useTheme<Theme>();
  const isDarkMode = theme.palette.mode === 'dark';

  useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return;
    }
    container.classList.toggle('dark', isDarkMode);
    container.classList.toggle('light', !isDarkMode);
  }, [containerRef, isDarkMode]);
};

export default useFdsThemeScope;
