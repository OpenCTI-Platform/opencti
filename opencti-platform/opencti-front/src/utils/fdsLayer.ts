/**
 * Elevation LAYERS — the half of the library's contract the product has to
 * declare itself.
 *
 * The library ships `.layer-0` … `.layer-3` classes that re-declare the
 * elevation aliases (`--bg-elevation-default`, `--bg-elevation-highlight`, …)
 * to that layer's value. Nesting depth is the whole idea: the page is layer 0,
 * a panel over it is layer 1, a panel inside that is layer 2 (Figma
 * 0PmhuZzF9XcaIEfMMW2a51, node 5416-12183).
 *
 * The product declared NO layer anywhere, so every surface resolved at the
 * root — layer 0 — including drawers and dialogs and every field inside them.
 *
 * WHY A CLASS IS NOT ENOUGH, and this is the part that bites:
 *
 * A `var()` inside a custom-property declaration is substituted at
 * computed-value time ON THE ELEMENT THAT DECLARES IT. The library declares
 *
 *     --bg-input-default: var(--bg-elevation-highlight);
 *
 * once, at the root. So it is resolved against the ROOT's highlight — layer 0 —
 * and adding `.layer-2` further down re-declares the elevation alias but can no
 * longer reach the input one. Measured in the browser on the served build:
 *
 *     context              --bg-elevation-highlight   --bg-input-default
 *     root (layer 0)       #13213e                    #13213e
 *     .layer-2 alone       #0c1527                    #13213e   <- the bug
 *     .layer-2 + below     #0c1527                    #0c1527   <- wanted
 *
 * Re-declaring the three aliases ON THE SAME ELEMENT as the layer class makes
 * them resolve against that element's own elevation values. Exactly three input
 * tokens alias an elevation token; the rest of the family aliases feedback and
 * text tokens, which are layer-independent and correctly left alone.
 *
 * This is a LIBRARY GAP (LIBRARY-FEEDBACK #57), not a product decision: the
 * `.layer-N` blocks should carry these three themselves. When they do, drop
 * `layerInputVars` and keep the class.
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
 *
 * Drawers and dialogs are layer 2 — the designer's ruling, and it agrees with
 * the drawer's own Figma frame (node 5415-3010), whose body reads
 * `--bg-elevation-default-layer-2`.
 */
export const fdsLayerClass = (layer: FdsLayer) => `layer-${layer}`;

/** Drawers and dialogs: layer 2. */
export const SURFACE_LAYER: FdsLayer = 2;
