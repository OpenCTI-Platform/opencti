import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApexOptions } from 'apexcharts';
import testRender from '../../utils/tests/test-render';

const mocks = vi.hoisted(() => ({ chart: vi.fn() }));

vi.mock('@components/common/charts/Chart', () => ({
  default: (props: { options: ApexOptions }) => {
    mocks.chart(props);
    return <div data-testid="chart" />;
  },
}));

import WidgetMultiHeatMap from './WidgetMultiHeatMap';

const series = [{ name: 'Report', data: [{ x: new Date('2025-10-01T00:00:00.000Z'), y: 3 }] }];
const lastOptions = () => mocks.chart.mock.lastCall?.[0].options as ApexOptions;

describe('Time series chart widgets', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('heatmap color ranges', () => {
    type ColorRange = { from: number; to: number; color: string };
    // The ranges of the values, the range of 0 left aside: the last one
    const valueRanges = (minValue: number, maxValue: number) => {
      testRender(<WidgetMultiHeatMap data={series} minValue={minValue} maxValue={maxValue} />);
      const ranges = (lastOptions().plotOptions?.heatmap?.colorScale?.ranges ?? []) as ColorRange[];
      expect(ranges.at(-1)).toMatchObject({ from: 0, to: 0 });
      return ranges.slice(0, -1);
    };
    // ApexCharts colors a cell with the last range it falls in
    const rangeOf = (ranges: ColorRange[], value: number) => ranges.findLastIndex(({ from, to }) => from <= value && value <= to);
    const legend = (ranges: ColorRange[]) => ranges.map(({ from, to }) => `${from} - ${to}`);

    it('colors every value up to the hottest cell, with at most 10 ranges, none above the highest value', () => {
      [0, 3, 8, 11, 17, 26, 71, 100].forEach((spread) => {
        [0, 5].forEach((minValue) => {
          const maxValue = minValue + spread;
          const ranges = valueRanges(minValue, maxValue);
          expect(ranges.length).toBeLessThanOrEqual(10);
          for (let value = Math.max(1, minValue); value <= maxValue; value += 1) {
            expect(rangeOf(ranges, value), `value ${value} of ${minValue} - ${maxValue}`).toBeGreaterThanOrEqual(0);
          }
          // The hottest cells take the last range, and no range goes past them
          expect(rangeOf(ranges, maxValue)).toEqual(ranges.length - 1);
          ranges.forEach(({ from, to }) => {
            expect(from).toBeLessThanOrEqual(to);
            expect(to).toBeLessThanOrEqual(maxValue);
          });
          // Whole numbers, one range after the other: none overlaps the next
          ranges.slice(1).forEach(({ from }, i) => expect(from).toEqual(ranges[i].to + 1));
        });
      });
    });

    it('gives the values above 0 a range per value up to 10, and ranges of a tenth of them beyond', () => {
      expect(legend(valueRanges(0, 3))).toEqual(['1 - 1', '2 - 2', '3 - 3']);
      expect(legend(valueRanges(0, 10))).toEqual(['1 - 1', '2 - 2', '3 - 3', '4 - 4', '5 - 5', '6 - 6', '7 - 7', '8 - 8', '9 - 9', '10 - 10']);
      expect(legend(valueRanges(0, 17))).toEqual(['1 - 2', '3 - 4', '5 - 6', '7 - 8', '9 - 10', '11 - 12', '13 - 14', '15 - 16', '17 - 17']);
      expect(legend(valueRanges(0, 100))).toEqual(['1 - 10', '11 - 20', '21 - 30', '31 - 40', '41 - 50', '51 - 60', '61 - 70', '71 - 80', '81 - 90', '91 - 100']);
      expect(legend(valueRanges(5, 5))).toEqual(['5 - 5']);
      expect(legend(valueRanges(5, 8))).toEqual(['5 - 5', '6 - 6', '7 - 7', '8 - 8']);
    });

    it('only colors 0 without a value above it, or without values', () => {
      expect(valueRanges(0, 0)).toEqual([]);
      // The bounds of no value at all
      expect(valueRanges(Math.min(), Math.max())).toEqual([]);
    });
  });
});
