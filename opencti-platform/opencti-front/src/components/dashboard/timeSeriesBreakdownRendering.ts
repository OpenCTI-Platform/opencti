import * as C from '@mui/material/colors';
import type { WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';
import { colors } from '../../utils/Charts';
import { itemColor, itemFamily } from '../../utils/Colors';

// ApexCharts bar rendering cost grows with the square of the number of bars (every bar is
// revealed again for each bar drawn), so bar charts are kept under these sizes. The bar budget follows
// the width of the chart: bars thinner than PIXELS_PER_BAR add cost without adding readable detail.
export const MIN_RENDERED_BARS = 150;
export const MAX_RENDERED_BARS = 600;
export const PIXELS_PER_BAR = 2;
// Lines, areas and heatmaps draw every series across the whole width: a point closer than
// PIXELS_PER_LINE_POINT to the next one, or a heatmap cell thinner than PIXELS_PER_HEATMAP_CELL,
// adds cost (SVG nodes, path length, hover lookups) without adding readable detail
export const PIXELS_PER_LINE_POINT = 2;
export const PIXELS_PER_HEATMAP_CELL = 6;
const MIN_RENDERED_POINTS_PER_SERIES = 10;
// Whatever the width, a chart draws at most this many points: past them, a wide chart with many series
// still blocks the main thread (about 0.12 ms per heatmap cell)
export const MAX_RENDERED_LINE_POINTS = 5000;
export const MAX_RENDERED_HEATMAP_CELLS = 1500;
export const PIXELS_PER_X_LABEL = 60;
// Animating more points than this blocks the main thread for seconds, whatever the chart type
export const ANIMATION_POINTS_THRESHOLD = 300;
// Relative change under which a new chart width is ignored, to not redraw the chart on small resizes
const CHART_WIDTH_HYSTERESIS = 0.2;
// Height the plot and its x axis keep under the legend, which scrolls past it, and the height of a row of
// the compact legend, which always shows one
export const MIN_PLOT_HEIGHT = 120;
export const COMPACT_LEGEND_ROW_HEIGHT = 20;

/**
 * Number of bars the chart can draw for a given width in pixels, an unknown width gives the maximum.
 */
export const getRenderedBarsBudget = (width: number) => {
  if (!(width > 0)) return MAX_RENDERED_BARS;
  return Math.min(MAX_RENDERED_BARS, Math.max(MIN_RENDERED_BARS, Math.floor(width / PIXELS_PER_BAR)));
};

/**
 * Number of points the chart can draw for a given width in pixels: grouped bars share the width between
 * every series, while stacked bars share it between their columns, one per date, as lines, areas and
 * heatmaps draw each series across the whole width. Stacked bars still draw a bar per series and date:
 * their cost keeps them under MAX_RENDERED_BARS.
 */
export const getRenderedPointsBudget = (type: string, width: number, seriesCount: number, isStacked = false) => {
  if (type === 'vertical-bar') {
    return isStacked
      ? Math.min(MAX_RENDERED_BARS, getRenderedBarsBudget(width) * Math.max(1, seriesCount))
      : getRenderedBarsBudget(width);
  }
  const chartWidth = width > 0 ? width : MAX_RENDERED_BARS * PIXELS_PER_BAR;
  const isHeatmap = type === 'heatmap';
  const pixelsPerPoint = isHeatmap ? PIXELS_PER_HEATMAP_CELL : PIXELS_PER_LINE_POINT;
  const series = Math.max(1, seriesCount);
  const pointsPerSeries = Math.max(MIN_RENDERED_POINTS_PER_SERIES, Math.floor(chartWidth / pixelsPerPoint));
  const maxPoints = Math.max(isHeatmap ? MAX_RENDERED_HEATMAP_CELLS : MAX_RENDERED_LINE_POINTS, MIN_RENDERED_POINTS_PER_SERIES * series);
  return Math.min(pointsPerSeries * series, maxPoints);
};

/**
 * Whether two breakdowns draw the same chart. A refresh hands a new breakdown even when nothing changed
 * (its end date moved), and redrawing every chart of a dashboard for nothing blocks the page for seconds.
 */
export const isSameBreakdown = (a?: WidgetTimeSeriesBreakdownData | null, b?: WidgetTimeSeriesBreakdownData | null) => {
  if (a === b) return true;
  if (!a || !b || a.truncated !== b.truncated || a.dates.length !== b.dates.length || a.series.length !== b.series.length) {
    return false;
  }
  if (a.dates.some((date, index) => date !== b.dates[index])) return false;
  return a.series.every((serie, index) => {
    const other = b.series[index];
    return serie.label === other.label
      && serie.isOther === other.isOther
      && serie.entity?.id === other.entity?.id
      && serie.entity?.entity_type === other.entity?.entity_type
      && serie.entity?.name === other.entity?.name
      && serie.entity?.representative?.main === other.entity?.representative?.main
      && serie.entity?.color === other.entity?.color
      && serie.entity?.x_opencti_color === other.entity?.x_opencti_color
      && serie.values.length === other.values.length
      && serie.values.every((value, valueIndex) => value === other.values[valueIndex]);
  });
};

/**
 * Width the chart is laid out for after a resize: the previous one is kept until the new one differs
 * by 20 % or more, so that the bars budget and the x axis labels do not change on every pixel.
 */
export const nextBreakdownChartWidth = (previous: number | undefined, width: number) => {
  if (previous === undefined || !(previous > 0)) return width;
  return Math.abs(width - previous) < previous * CHART_WIDTH_HYSTERESIS ? previous : width;
};

/**
 * Height the legend of a chart of a given height in pixels scrolls past, to keep MIN_PLOT_HEIGHT to the plot,
 * when the cap of ApexCharts (half of the chart) does not keep it. One row of the legend always shows.
 */
export const getBreakdownLegendMaxHeight = (height: number) => {
  if (!(height > 0) || height - MIN_PLOT_HEIGHT >= height / 2) return undefined;
  return Math.max(COMPACT_LEGEND_ROW_HEIGHT, height - MIN_PLOT_HEIGHT);
};

/**
 * Number of labels of the x axis for a given width in pixels.
 */
export const getBreakdownTickAmount = (width: number) => {
  return Math.max(2, Math.floor(width / PIXELS_PER_X_LABEL));
};

const COARSER_INTERVAL: Record<string, string> = {
  day: 'week',
  week: 'month',
  month: 'quarter',
  quarter: 'year',
};

// Start of the UTC calendar bucket, matching the backend date histogram (weeks start on Monday)
const getBucketStart = (date: Date, interval: string) => {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  switch (interval) {
    case 'week': {
      const daysSinceMonday = (date.getUTCDay() + 6) % 7;
      return Date.UTC(year, month, date.getUTCDate() - daysSinceMonday);
    }
    case 'month':
      return Date.UTC(year, month, 1);
    case 'quarter':
      return Date.UTC(year, month - (month % 3), 1);
    case 'year':
      return Date.UTC(year, 0, 1);
    default:
      return Date.UTC(year, month, date.getUTCDate());
  }
};

type TimeSeriesPoint = { x: Date; y: number };

const sumByInterval = (data: TimeSeriesPoint[], interval: string): TimeSeriesPoint[] => {
  const sums = new Map<number, number>();
  data.forEach(({ x, y }) => {
    const bucketStart = getBucketStart(x, interval);
    sums.set(bucketStart, (sums.get(bucketStart) ?? 0) + y);
  });
  return Array.from(sums, ([bucketStart, y]) => ({ x: new Date(bucketStart), y }));
};

/**
 * Sums the series into coarser intervals until the chart draws at most `maxPoints` points.
 * Buckets are always rebuilt from the original points, so counts stay exact when starting
 * from days; starting from weeks, a week overlapping two months counts in the month of its Monday
 * (`weeksCountedByMonday`, for the warning to say so).
 */
export const coarsenSeriesForRendering = <T extends { data: TimeSeriesPoint[] }>(
  series: T[],
  interval: string,
  maxPoints = MAX_RENDERED_BARS,
) => {
  const countPoints = (candidate: T[]) => candidate.reduce((count, serie) => count + serie.data.length, 0);
  let renderedInterval = interval;
  let renderedSeries = series;
  while (countPoints(renderedSeries) > maxPoints && COARSER_INTERVAL[renderedInterval]) {
    const coarserInterval = COARSER_INTERVAL[renderedInterval];
    renderedInterval = coarserInterval;
    renderedSeries = series.map((serie) => ({ ...serie, data: sumByInterval(serie.data, coarserInterval) }));
  }
  return {
    series: renderedSeries,
    interval: renderedInterval,
    pointsCount: countPoints(renderedSeries),
    // Months, quarters and years do not start on a Monday: each week is counted in the one of its Monday
    weeksCountedByMonday: interval === 'week' && renderedInterval !== interval,
  };
};

/**
 * Names of the series, numbered by order when several share one: the entities the user cannot access are
 * all named "Restricted" and nothing else of them can be shown, while the legend must tell them apart.
 */
export const numberSharedSeriesNames = (names: string[]) => {
  const counts = new Map<string, number>();
  names.forEach((name) => counts.set(name, (counts.get(name) ?? 0) + 1));
  // A number another series is already named with is skipped: "Alice (1)" next to two "Alice"
  const inputNames = new Set(names);
  const ranks = new Map<string, number>();
  return names.map((name) => {
    if ((counts.get(name) ?? 0) < 2) return name;
    let rank = (ranks.get(name) ?? 0) + 1;
    while (inputNames.has(`${name} (${rank})`)) rank += 1;
    ranks.set(name, rank);
    return `${name} (${rank})`;
  });
};

// Shades of the palette of the series, the first one tried first: enough colors for the 50 series of a breakdown
const PALETTE_SHADES = { dark: [400, 200, 700], light: [600, 800, 300] } as const;

/**
 * Colors the series of a breakdown are drawn with: the hues of the chart palette without its greys, as the
 * "Other" series is grey, in several shades. The first shade holds the colors a key is hashed to.
 */
export const getBreakdownPalette = (mode: 'light' | 'dark'): string[][] => PALETTE_SHADES[mode].map((shade) => (
  (colors(shade) as string[]).filter((color) => color !== C.grey[shade] && color !== C.blueGrey[shade])
));

/**
 * Color of an entity type, as the platform draws it, when it tells the type apart: the families of the
 * relationships and of the restricted entities are one grey for all.
 */
export const getEntityTypeColor = (type: string) => {
  const family = itemFamily(type);
  return family && family !== 'relationships' && family !== 'restricted' ? itemColor(type) : undefined;
};

const HEX_COLOR = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;

// The red, green and blue of a color written #rgb or #rrggbb
const toRgb = (color: string) => {
  const hex = color.length === 4 ? color.slice(1).split('').map((digit) => digit + digit).join('') : color.slice(1);
  return [0, 2, 4].map((start) => parseInt(hex.slice(start, start + 2), 16));
};

// A color written #rgb or #rrggbb, as #rrggbb in lower case
const toHexColor = (color: string) => `#${toRgb(color).map((channel) => channel.toString(16).padStart(2, '0')).join('')}`;

// Below this distance between their red, green and blue, an own color can be taken for the one of the "Other" series
const MIN_DISTANCE_TO_OTHER = 48;
const isCloseTo = (color: string, reference: string) => {
  if (!HEX_COLOR.test(reference)) return false;
  const [r, g, b] = toRgb(color);
  const [referenceR, referenceG, referenceB] = toRgb(reference);
  return Math.hypot(r - referenceR, g - referenceG, b - referenceB) < MIN_DISTANCE_TO_OTHER;
};

/**
 * The own color of a value as it can be drawn on the card: white (TLP:CLEAR, PAP:CLEAR) is drawn black in the light
 * theme, as the donut widgets do.
 */
export const getReadableOwnColor = (color: string | null | undefined, mode: 'light' | 'dark') => {
  const isWhite = !!color && ['#fff', '#ffffff'].includes(color.toLowerCase());
  return mode === 'light' && isWhite ? '#000000' : color;
};

// Same key, same number, whatever the widget
const hashKey = (key: string) => {
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (Math.imul(hash, 31) + key.charCodeAt(i)) >>> 0;
  }
  return hash;
};

/**
 * Colors of the series of a breakdown. A value keeps its own color (`ownColor`: the one of its label, of its marking,
 * of its entity type), otherwise takes the one its `key` is hashed to in the first shade of the `palette`.
 * Two series of a widget never share a color: a color already taken goes on to the next free one of the palette.
 * The colors are given in the order of the keys, not of the ranks, so that a value has the same color in every widget
 * showing the same values, whatever their ranks.
 * The "Other" series takes `otherColor`, which no other series takes, nor an own color close to it.
 */
export const getBreakdownSeriesColors = (
  series: ReadonlyArray<{ key: string; isOther: boolean; ownColor?: string | null }>,
  palette: string[][],
  // The neutral color of the theme, a grey without theme
  otherColor: string = C.grey[500],
): string[] => {
  const neutral = HEX_COLOR.test(otherColor) ? toHexColor(otherColor) : otherColor.toLowerCase();
  const taken = new Set([neutral]);
  const colors: string[] = series.map(({ isOther }) => (isOther ? otherColor : ''));
  // Same order for any ranking of the same values: the one of their keys, compared code unit by code unit
  const byKey = series
    .map((serie, index) => ({ ...serie, index }))
    .filter(({ isOther }) => !isOther)
    .sort((a, b) => {
      if (a.key === b.key) return 0;
      return a.key < b.key ? -1 : 1;
    });
  // The own colors first: of two values of the same color, the first key keeps it. Compared as #rrggbb, as #000 and
  // #000000 are the same color
  byKey.forEach(({ ownColor, index }) => {
    if (!ownColor || !HEX_COLOR.test(ownColor) || isCloseTo(ownColor, neutral)) return;
    const color = toHexColor(ownColor);
    if (taken.has(color)) return;
    taken.add(color);
    colors[index] = color;
  });
  const sequence = palette.flat().map((color) => color.toLowerCase());
  const firstShadeSize = Math.max(1, palette[0]?.length ?? 0);
  byKey.forEach(({ key, index }) => {
    if (colors[index]) return;
    const start = hashKey(key) % firstShadeSize;
    for (let probe = 0; probe < sequence.length; probe += 1) {
      const color = sequence[(start + probe) % sequence.length];
      if (!taken.has(color)) {
        taken.add(color);
        colors[index] = color;
        return;
      }
    }
    // More series than colors: the hashed one is shared
    colors[index] = sequence[start] ?? otherColor;
  });
  return colors;
};
