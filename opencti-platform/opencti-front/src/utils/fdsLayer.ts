/**
 * Elevation layers, and the three input aliases the `.layer-N` class cannot reach on
 * its own. LIBRARY GAP (LIBRARY-FEEDBACK #57): when `.layer-N` carries them, drop
 * `layerInputVars` and keep the class. Mechanism: fds-migration/MIGRATION-DECISIONS.md#elevation-layer-compensation
 */

export type FdsLayer = 0 | 1 | 2 | 3;

export const layerInputVars = {
  '--bg-input-default': 'var(--bg-elevation-highlight)',
  '--bg-input-disabled': 'var(--bg-elevation-disabled)',
  '--bg-input-hover': 'var(--bg-elevation-hover)',
} as const;

export const fdsLayerClass = (layer: FdsLayer) => `layer-${layer}`;

export const SURFACE_LAYER: FdsLayer = 2;

export const FILTER_POPOVER_LAYER: FdsLayer = 2;

export const filterPopoverPaperSx = {
  ...layerInputVars,
  background: 'var(--bg-elevation-highlight-layer-1)',
} as const;

export const RIGHT_BAR_LAYER: FdsLayer = 1;
