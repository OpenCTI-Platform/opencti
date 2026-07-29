// Relative frequency heatmap colour scale for the TTP Analyser matrix (US.3).
//
// The scale is relative to the current dataset: the minimum frequency maps to
// the low end and the maximum frequency maps to the high end, with all values
// in between interpolated linearly. The palette runs from amber-yellow (a
// technique used by a single linked entity) up to the platform's error-red
// (the most frequently used technique). Green is intentionally NOT used here:
// it is reserved for a future iteration that will overlay an assessment of our
// mitigation coverage.

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

// Yellow -> red risk stops anchored at the 0 / 25 / 50 / 75 / 100 % marks of
// the linear scale. The low end is amber-yellow (a single linked entity) and
// the high end is the theme's error red (#F14337, the same red used by the
// coverage score percentages). Five evenly-spaced stops make `colorForRatio`
// place the band boundaries exactly at 0.25, 0.5 and 0.75, so each quarter of
// the scale (0-25, 25-50, 50-75, 75-100) is a clean linear gradient between two
// anchors: yellow -> amber -> orange -> red-orange -> red.
const HEATMAP_STOPS: RGB[] = [
  [245, 215, 66], // amber-yellow   (0%, single linked entity)
  [243, 178, 52], // amber          (25%)
  [240, 140, 40], // orange         (50%)
  [238, 100, 44], // red-orange     (75%)
  [241, 67, 55], // error red      (#F14337, 100%, maximum)
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
