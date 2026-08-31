/**
 * Elevation layers, and the three input aliases the `.layer-N` class cannot reach on
 * its own. LIBRARY GAP (LIBRARY-FEEDBACK #57): when `.layer-N` carries them, drop
 * `layerInputVars` and keep the class. Mechanism: fds-migration/MIGRATION-DECISIONS.md#elevation-layer-compensation
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

/** The library class for a layer. */
export const fdsLayerClass = (layer: FdsLayer) => `layer-${layer}`;

/** Drawers and dialogs: layer 2. */
export const SURFACE_LAYER: FdsLayer = 2;

/** Filter popovers: surface at layer 1, fields at layer 2 on the same node. */
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
