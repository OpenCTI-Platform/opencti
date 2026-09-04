import { useEffect } from 'react';
import { isLightThemeName } from '../themeName';

export type FdsThemeMode = 'light' | 'dark';

/**
 * Single writer of the `.light` / `.dark` class FDS components read, on the document
 * ROOT because FDS portals its floating layers into `<body>`. See
 * fds-migration/MIGRATION-DECISIONS.md#theme-scope-root
 */
/** Customer surface colour: per-layer BASE only, layer 1. See fds-migration/MIGRATION-DECISIONS.md#theme-scope-root */
const SURFACE_BASE = '--bg-elevation-default-layer-1';
const BORDER_BASE = '--border-elevation-subtle-soft-layer-1';

const useFdsThemeScope = (
  themeName: string | undefined,
  customPaperColor?: string | null,
): FdsThemeMode => {
  const mode: FdsThemeMode = isLightThemeName(themeName) ? 'light' : 'dark';

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', mode === 'dark');
    root.classList.toggle('light', mode === 'light');
  }, [mode]);

  useEffect(() => {
    const root = document.documentElement;
    if (customPaperColor) {
      root.style.setProperty(SURFACE_BASE, customPaperColor);
      root.style.setProperty(BORDER_BASE, customPaperColor);
    } else {
      root.style.removeProperty(SURFACE_BASE);
      root.style.removeProperty(BORDER_BASE);
    }
  }, [customPaperColor]);

  return mode;
};

export default useFdsThemeScope;
