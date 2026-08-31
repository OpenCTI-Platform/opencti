import { useEffect } from 'react';
import { isLightThemeName } from '../themeName';

export type FdsThemeMode = 'light' | 'dark';

/**
 * Single writer of the `.light` / `.dark` class FDS components read to resolve
 * their custom properties, and the returned mode so callers do not re-derive it.
 *
 * The class goes on `document.documentElement` because FDS portals its floating
 * layers (flyouts, tooltips, dropdowns) into `<body>`: a container-scoped class
 * themes the component and leaves every portalled layer unthemed.
 *
 * Anything that is not a light theme resolves to `dark` — custom themes carry
 * arbitrary names. The name test is shared with `themeBuilder` through
 * `isLightThemeName` so the two can no longer drift apart.
 */
/**
 * Customer surface colour. Overriding the semantic alias does nothing — it is
 * substituted on the declaring element — so only the per-layer BASE can be
 * moved, border base included (the diluted variant is derived from it).
 *
 * Layer 1 only: the Paper default elevation, and the customer supplies exactly
 * one paper colour. A customised install therefore has no visible panel edge,
 * which is the arbitrated outcome, not a defect.
 */
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
      // Back to a built-in theme: hand the ramp back rather than leave a stale override.
      root.style.removeProperty(SURFACE_BASE);
      root.style.removeProperty(BORDER_BASE);
    }
  }, [customPaperColor]);

  return mode;
};

export default useFdsThemeScope;
