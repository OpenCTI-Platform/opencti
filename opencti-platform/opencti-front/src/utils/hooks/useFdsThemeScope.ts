import { useEffect } from 'react';

export type FdsThemeMode = 'light' | 'dark';

/**
 * Single writer of the `.light` / `.dark` class that FDS components
 * (`@filigran/design-system`) read to resolve their CSS custom properties.
 * The class goes on `document.documentElement`, and the hook also returns the
 * resolved mode so callers do not re-derive it.
 *
 * WHY THE DOCUMENT ROOT (decision taken 2026-08-04, revising this hook's
 * original scoped design):
 * FDS portals its floating layers — submenu flyouts, tooltips, dropdown
 * content — directly into `<body>`, outside whatever subtree rendered the
 * component. A class scoped to a container therefore themes the component but
 * leaves every floating layer unthemed, and the defect only shows on hover or
 * on a collapsed rail, which is exactly where review does not look. Targeting
 * the root is the only placement that covers both the in-tree markup and the
 * portalled layers. This mirrors the mechanism already proven in the OpenAEV
 * migration.
 *
 * The earlier version of this hook took a container ref and its documentation
 * explicitly forbade targeting the root. That guidance is obsolete — it
 * predates the portal analysis above — and has been removed rather than left
 * to contradict the code.
 *
 * DEFENSIVE MAPPING: anything that is not the built-in `Light` theme resolves
 * to `dark`. Custom themes are stored in database with arbitrary names, and
 * `themeBuilder` already branches the same way; keeping a single rule here is
 * what stops MUI and FDS from disagreeing on a theme named e.g. `Corporate`.
 *
 * NOT A DUPLICATE: `useDocumentThemeModifier` and `private/Index.tsx` both
 * write `body[data-theme]`, which is a different attribute on a different
 * node, consumed by the product's own stylesheets. Neither touches the root
 * class, so they do not compete with this hook. `AskArianePanel` additionally
 * sets `dark` on its own portal container; since it derives from the same
 * palette mode it stays consistent, and it becomes redundant once this hook
 * is in place.
 */
/**
 * CUSTOMER SURFACE COLOUR — the host's half of the library's theming contract.
 *
 * The library resolves a Paper's surface and border from a BASE PER LAYER, and
 * re-declares the semantic alias inside each `.layer-N` block. Overriding the
 * alias (`--bg-elevation-default`, `--border-elevation-subtle-soft`) therefore
 * does NOTHING — verified in a browser, both directions — because the alias is
 * substituted at computed-value time on the declaring element. The base is the
 * only thing a host can move, and the border base must be moved too: the
 * diluted variant is derived from it, so re-declaring the diluted value
 * directly would short-circuit the 15% dilution.
 *
 * Layer 1 only: that is the Paper default elevation, and the customer supplies
 * exactly one paper colour. The other layers keep the Filigran ramp.
 *
 * Arbitrated: the border takes the CUSTOMER'S CARD COLOUR, and only on
 * a custom theme. Accepted consequence — a 15% dilution of the surface colour
 * over that same surface composites back to the surface, so a customised
 * install has NO visible edge on its panels. That is wanted, not a defect.
 */
const SURFACE_BASE = '--bg-elevation-default-layer-1';
const BORDER_BASE = '--border-elevation-subtle-soft-layer-1';

const useFdsThemeScope = (
  themeName: string | undefined,
  customPaperColor?: string | null,
): FdsThemeMode => {
  const mode: FdsThemeMode = themeName === 'Light' ? 'light' : 'dark';

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
      // Back to a built-in theme: hand the ramp back to the library rather
      // than leaving a stale override behind.
      root.style.removeProperty(SURFACE_BASE);
      root.style.removeProperty(BORDER_BASE);
    }
  }, [customPaperColor]);

  return mode;
};

export default useFdsThemeScope;
