import type { WidgetTimeSeriesBreakdownData } from './WidgetTimeSeriesBreakdown';

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

/**
 * Number of bars the chart can draw for a given width in pixels, an unknown width gives the maximum.
 */
export const getRenderedBarsBudget = (width: number) => {
  if (!(width > 0)) return MAX_RENDERED_BARS;
  return Math.min(MAX_RENDERED_BARS, Math.max(MIN_RENDERED_BARS, Math.floor(width / PIXELS_PER_BAR)));
};

/**
 * Number of points the chart can draw for a given width in pixels: bars share the width between
 * every series, while lines, areas and heatmaps draw each series across the whole width.
 */
export const getRenderedPointsBudget = (type: string, width: number, seriesCount: number) => {
  if (type === 'vertical-bar') return getRenderedBarsBudget(width);
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
