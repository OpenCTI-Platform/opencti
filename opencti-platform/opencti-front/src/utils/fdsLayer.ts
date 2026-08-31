/**
 * Elevation layers: the page is layer 0, a panel over it layer 1, a panel
 * inside that layer 2. The library's `.layer-N` class re-declares the elevation
 * aliases, but a `var()` inside a custom-property declaration is substituted on
 * the element that DECLARES it — so `--bg-input-default`, declared once at the
 * root, keeps the layer-0 value however deep the class is applied. The three
 * input tokens that alias an elevation token must therefore be re-declared on
 * the same element as the class.
 *
 * LIBRARY GAP (LIBRARY-FEEDBACK #57): when the `.layer-N` blocks carry these
 * three themselves, drop `layerInputVars` and keep the class.
 */

export type FdsLayer = 0 | 1 | 2 | 3;

/**
 * The three input backgrounds that alias an elevation token, re-declared so
 * they resolve at the layer of the element carrying them.
 */
export const layerInputVars = {
  '--bg-input-default': 'var(--bg-elevation-highlight)',
  '--bg-input-disabled': 'var(--bg-elevation-disabled)',
  '--bg-input-hover': 'var(--bg-elevation-hover)',
} as const;

/**
 * The library class for a layer. Put it on the SAME node that carries
 * `layerInputVars`, or the compensation resolves against the wrong layer.
 */
export const fdsLayerClass = (layer: FdsLayer) => `layer-${layer}`;

/** Drawers and dialogs: layer 2. */
export const SURFACE_LAYER: FdsLayer = 2;

/**
 * Filter popovers: the surface is `--bg-elevation-highlight` at layer 1, the
 * fields inside sit at layer 2. Both halves live on the paper itself, so the
 * surface must name its layer-1 value explicitly — the layer-2 class it shares
 * the node with has already moved the ambient alias.
 */
export const FILTER_POPOVER_LAYER: FdsLayer = 2;

export const filterPopoverPaperSx = {
  ...layerInputVars,
  background: 'var(--bg-elevation-highlight-layer-1)',
} as const;

/**
 * The tab-scoped right bars (Knowledge, Content): layer 1, not 2 — they are
 * page chrome beside the content, not a panel over it.
 */
export const RIGHT_BAR_LAYER: FdsLayer = 1;
