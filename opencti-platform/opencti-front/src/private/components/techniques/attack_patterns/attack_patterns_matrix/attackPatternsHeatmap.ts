// Relative frequency heatmap colour scale for the TTP Analyser matrix (US.3).
//
// The scale is relative to the current dataset: the minimum frequency maps to
// the low end and the maximum frequency maps to the high end, with all values
// in between interpolated linearly. A soft pastel palette (pale yellow ->
// peach -> coral) is used so the cells read cleanly against the dark matrix
// background instead of the muddy fully-saturated yellow/red spectrum.

export interface HeatmapScale {
  min: number;
  max: number;
}

export interface HeatmapCellColors {
  // Solid colour used for the cell border.
  border: string;
  // Semi-transparent fill so the cell label stays legible in dark mode.
  background: string;
}

type RGB = [number, number, number];

// Pastel stops from low usage (pale yellow) through peach to high usage (coral).
const HEATMAP_STOPS: RGB[] = [
  [253, 246, 179], // pale yellow
  [252, 205, 144], // peach
  [245, 150, 137], // coral
];

// The palette stops as ready-to-use CSS colours, exposed so UI (e.g. the legend
// scale) can render discrete swatches that match the cell colours exactly.
export const HEATMAP_STEP_COLORS: string[] = HEATMAP_STOPS.map(([r, g, b]) => `rgb(${r}, ${g}, ${b})`);

const HEATMAP_FILL_OPACITY = 0.85;

const lerp = (a: number, b: number, t: number): number => Math.round(a + (b - a) * t);

// Interpolate across the pastel stops for a ratio in [0, 1].
const colorForRatio = (ratio: number): RGB => {
  const clamped = Math.min(1, Math.max(0, ratio));
  const segments = HEATMAP_STOPS.length - 1;
  const scaled = clamped * segments;
  const index = Math.min(segments - 1, Math.floor(scaled));
  const localT = scaled - index;
  const start = HEATMAP_STOPS[index];
  const end = HEATMAP_STOPS[index + 1];
  return [
    lerp(start[0], end[0], localT),
    lerp(start[1], end[1], localT),
    lerp(start[2], end[2], localT),
  ];
};

// Map a frequency count to its colour on the relative pastel scale.
// When every technique shares the same frequency (max === min) the whole
// dataset collapses onto the maximum (coral) end of the scale.
export const getHeatmapColors = (count: number, scale: HeatmapScale): HeatmapCellColors => {
  const { min, max } = scale;
  const ratio = max > min ? (count - min) / (max - min) : 1;
  const [r, g, b] = colorForRatio(ratio);
  return {
    border: `rgb(${r}, ${g}, ${b})`,
    background: `rgba(${r}, ${g}, ${b}, ${HEATMAP_FILL_OPACITY})`,
  };
};
