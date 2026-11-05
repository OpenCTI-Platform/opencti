import { describe, expect, it } from 'vitest';
import {
  coarsenSeriesForRendering,
  getBreakdownTickAmount,
  getRenderedBarsBudget,
  getRenderedPointsBudget,
  isSameBreakdown,
  MAX_RENDERED_BARS,
  MAX_RENDERED_HEATMAP_CELLS,
  MAX_RENDERED_LINE_POINTS,
  MIN_RENDERED_BARS,
  nextBreakdownChartWidth,
  numberSharedSeriesNames,
} from './timeSeriesBreakdownRendering';

// One point per UTC day, starting on a given date
const daily = (start: string, values: number[]) => values.map((y, i) => {
  const x = new Date(start);
  x.setUTCDate(x.getUTCDate() + i);
  return { x, y };
});

describe('rendered bars budget', () => {
  it('follows the width, within the minimum and maximum', () => {
    expect(getRenderedBarsBudget(800)).toEqual(400);
    expect(getRenderedBarsBudget(801)).toEqual(400);
    expect(getRenderedBarsBudget(100)).toEqual(MIN_RENDERED_BARS);
    expect(getRenderedBarsBudget(5000)).toEqual(MAX_RENDERED_BARS);
  });

  it('gives the maximum when the width is unknown', () => {
    expect(getRenderedBarsBudget(0)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(-10)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(Number.NaN)).toEqual(MAX_RENDERED_BARS);
  });
});

describe('rendered points budget', () => {
  it('shares the bars budget between every series', () => {
    expect(getRenderedPointsBudget('vertical-bar', 800, 20)).toEqual(getRenderedBarsBudget(800));
  });

  it('gives each line or area series a point every 2 pixels', () => {
    expect(getRenderedPointsBudget('line', 700, 1)).toEqual(350);
    expect(getRenderedPointsBudget('area', 700, 10)).toEqual(350 * 10);
  });

  it('gives each heatmap series a cell every 6 pixels', () => {
    expect(getRenderedPointsBudget('heatmap', 600, 10)).toEqual(100 * 10);
  });

  it('keeps a few points per series on a tiny or unknown width', () => {
    expect(getRenderedPointsBudget('heatmap', 12, 2)).toEqual(10 * 2);
    expect(getRenderedPointsBudget('line', 0, 1)).toEqual((MAX_RENDERED_BARS * 2) / 2);
  });

  it('caps the points of a wide chart with many series, keeping a few points per series', () => {
    expect(getRenderedPointsBudget('line', 2000, 50)).toEqual(MAX_RENDERED_LINE_POINTS);
    expect(getRenderedPointsBudget('heatmap', 1200, 20)).toEqual(MAX_RENDERED_HEATMAP_CELLS);
    expect(getRenderedPointsBudget('heatmap', 600, 200)).toEqual(10 * 200);
  });
});

describe('isSameBreakdown', () => {
  const breakdown = (values: number[], overrides = {}) => ({
    truncated: false,
    dates: ['2025-10-01T00:00:00.000Z', '2025-10-02T00:00:00.000Z'],
    series: [{ label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Alice' }, values }],
    ...overrides,
  });

  it('finds a refreshed breakdown with the same values the same', () => {
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2]))).toBe(true);
    expect(isSameBreakdown(null, null)).toBe(true);
  });

  it('finds a breakdown with other values, dates, series or names different', () => {
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 3]))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { truncated: true }))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { dates: ['2025-10-02T00:00:00.000Z', '2025-10-03T00:00:00.000Z'] }))).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), breakdown([1, 2], { series: [] }))).toBe(false);
    const renamed = breakdown([1, 2], { series: [{ label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Bob' }, values: [1, 2] }] });
    expect(isSameBreakdown(breakdown([1, 2]), renamed)).toBe(false);
    expect(isSameBreakdown(breakdown([1, 2]), null)).toBe(false);
  });
});

describe('nextBreakdownChartWidth', () => {
  it('takes the first measured width', () => {
    expect(nextBreakdownChartWidth(undefined, 800)).toEqual(800);
  });

  it('keeps the previous width on a small resize, and changes it from 20 %', () => {
    expect(nextBreakdownChartWidth(800, 900)).toEqual(800); // +12.5 %
    expect(nextBreakdownChartWidth(800, 700)).toEqual(800); // -12.5 %
    expect(nextBreakdownChartWidth(800, 960)).toEqual(960); // +20 %
    expect(nextBreakdownChartWidth(800, 500)).toEqual(500);
  });
});

describe('getBreakdownTickAmount', () => {
  it('gives a label per 60 pixels, at least 2', () => {
    expect(getBreakdownTickAmount(1200)).toEqual(20);
    expect(getBreakdownTickAmount(130)).toEqual(2);
    expect(getBreakdownTickAmount(0)).toEqual(2);
  });
});

describe('coarsenSeriesForRendering', () => {
  it('keeps the series untouched under the budget', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3]) }];
    const result = coarsenSeriesForRendering(series, 'day', 10);
    expect(result.interval).toEqual('day');
    expect(result.series).toBe(series);
    expect(result.pointsCount).toEqual(3);
  });

  it('sums days into weeks starting on Monday', () => {
    // 2026-01-01 is a Thursday: Thu-Sun belong to the week of Monday 2025-12-29
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) }];
    const result = coarsenSeriesForRendering(series, 'day', 5);
    expect(result.interval).toEqual('week');
    expect(result.series[0].data).toEqual([
      { x: new Date('2025-12-29T00:00:00.000Z'), y: 1 + 2 + 3 + 4 },
      { x: new Date('2026-01-05T00:00:00.000Z'), y: 5 + 6 + 7 + 8 + 9 + 10 },
    ]);
    expect(result.series[0].name).toEqual('A');
  });

  it('keeps getting coarser until the budget is met, without losing any count', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = Array.from({ length: 20 }, (_, i) => ({ name: `S${i}`, data: daily('2025-10-01T00:00:00.000Z', values) }));
    const total = values.reduce((sum, value) => sum + value, 0);

    const toWeeks = coarsenSeriesForRendering(series, 'day', 1200);
    expect(toWeeks.interval).toEqual('week');
    expect(toWeeks.pointsCount).toBeLessThanOrEqual(1200);

    const toMonths = coarsenSeriesForRendering(series, 'day', 600);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toHaveLength(13); // October 2025 to October 2026 included
    toMonths.series.forEach((serie) => {
      expect(serie.data.reduce((sum, point) => sum + point.y, 0)).toEqual(total);
    });
    expect(toMonths.weeksCountedByMonday).toBe(false);
  });

  it('coarsens a week series with a smaller budget', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = [{ name: 'A', data: daily('2025-10-01T00:00:00.000Z', values) }];
    expect(coarsenSeriesForRendering(series, 'day', MIN_RENDERED_BARS).interval).toEqual('week');
    const result = coarsenSeriesForRendering(series, 'week', 20);
    expect(result.interval).toEqual('month');
    expect(result.pointsCount).toEqual(13);
  });

  it('tells when weeks are counted in the month, quarter or year of their Monday', () => {
    // The week of Monday 2026-03-30 ends in April: it is counted in March, and in the first quarter
    const weekly = [
      { x: new Date('2026-03-23T00:00:00.000Z'), y: 1 },
      { x: new Date('2026-03-30T00:00:00.000Z'), y: 2 },
      { x: new Date('2026-04-06T00:00:00.000Z'), y: 4 },
    ];
    const series = [{ name: 'A', data: weekly }];
    const toMonths = coarsenSeriesForRendering(series, 'week', 2);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toEqual([
      { x: new Date('2026-03-01T00:00:00.000Z'), y: 1 + 2 },
      { x: new Date('2026-04-01T00:00:00.000Z'), y: 4 },
    ]);
    expect(toMonths.weeksCountedByMonday).toBe(true);
    const toYears = coarsenSeriesForRendering(series, 'week', 1);
    expect(toYears.interval).toEqual('year');
    expect(toYears.weeksCountedByMonday).toBe(true);

    // Weeks drawn as weeks, or weeks summed from days, keep every count where it belongs
    expect(coarsenSeriesForRendering(series, 'week', 3).weeksCountedByMonday).toBe(false);
    expect(coarsenSeriesForRendering([{ name: 'A', data: daily('2026-03-23T00:00:00.000Z', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) }], 'day', 5))
      .toMatchObject({ interval: 'week', weeksCountedByMonday: false });
  });

  it('never goes beyond years', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2]) }];
    const result = coarsenSeriesForRendering(series, 'year', 1);
    expect(result.interval).toEqual('year');
    expect(result.series).toBe(series);
  });
});

describe('numberSharedSeriesNames', () => {
  it('numbers by order the series sharing a name, and only them', () => {
    expect(numberSharedSeriesNames(['Restricted', 'Alice', 'Restricted', 'Bob', 'Restricted']))
      .toEqual(['Restricted (1)', 'Alice', 'Restricted (2)', 'Bob', 'Restricted (3)']);
    expect(numberSharedSeriesNames(['Alice', 'Bob'])).toEqual(['Alice', 'Bob']);
    expect(numberSharedSeriesNames([])).toEqual([]);
  });

  it('skips the numbers other series are already named with', () => {
    expect(numberSharedSeriesNames(['Alice', 'Alice', 'Alice (1)'])).toEqual(['Alice (2)', 'Alice (3)', 'Alice (1)']);
    expect(numberSharedSeriesNames(['Alice (2)', 'Alice', 'Alice', 'Alice', 'Alice (4)'])).toEqual(['Alice (2)', 'Alice (1)', 'Alice (3)', 'Alice (5)', 'Alice (4)']);
    // Shared numbered names are numbered too, apart from the others
    const names = numberSharedSeriesNames(['Alice', 'Alice', 'Alice (1)', 'Alice (1)']);
    expect(names).toEqual(['Alice (2)', 'Alice (3)', 'Alice (1) (1)', 'Alice (1) (2)']);
    expect(new Set(names).size).toEqual(names.length);
  });
});
