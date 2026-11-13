import type { HeatScale, TechniqueUsage } from './matrixTypes';

export const HEAT_STOPS: readonly string[] = [
  'var(--yellow-300)',
  // FDS-WORKAROUND #81: --yellow-500 is not compiled into dist/index.css — see fds-migration/LIBRARY-FEEDBACK.md #81
  'var(--yellow-400)',
  'var(--orange-400)',
  'var(--orange-500)',
  'var(--red-400)',
];

const LAST_STOP_INDEX = HEAT_STOPS.length - 1;

// Only techniques and sub-techniques in the selected kill chain count toward the scale.
export const computeHeatScale = (usage: Map<string, TechniqueUsage>, killChainTechniqueIds: Set<string>): HeatScale => {
  let max = 0;
  usage.forEach((technique, id) => {
    if (killChainTechniqueIds.has(id) && technique.score > max) max = technique.score;
  });
  return { max };
};

// Linear map of [1, max] onto the stop indexes 0..4. Out-of-range scores are clamped.
export const heatStopIndex = (score: number, scale: HeatScale): number => {
  if (scale.max <= 1) return 0;
  const index = Math.round(((score - 1) / (scale.max - 1)) * LAST_STOP_INDEX);
  return Math.min(LAST_STOP_INDEX, Math.max(0, index));
};

// Cells are filled with the solid stop: the --black-1000 label is 5.6:1 or more on every stop, in both themes.
export const heatFill = (stopIndex: number): string => HEAT_STOPS[stopIndex];

export const heatBorder = (stopIndex: number): string => HEAT_STOPS[stopIndex];
