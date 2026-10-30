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

import WidgetMultiLines from './WidgetMultiLines';
import WidgetMultiAreas from './WidgetMultiAreas';
import WidgetMultiHeatMap from './WidgetMultiHeatMap';

const series = [{ name: 'Report', data: [{ x: new Date('2025-10-01T00:00:00.000Z'), y: 3 }] }];
const lastOptions = () => mocks.chart.mock.lastCall?.[0].options as ApexOptions;

describe('Time series chart widgets', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps the animations of lines and areas by default, and disables them on demand', () => {
    testRender(<WidgetMultiLines series={series} interval="day" />);
    expect(lastOptions().chart?.animations?.enabled).not.toBe(false);
    testRender(<WidgetMultiLines series={series} interval="day" isAnimated={false} />);
    expect(lastOptions().chart?.animations?.enabled).toBe(false);
    expect(lastOptions().chart?.type).toEqual('line');

    testRender(<WidgetMultiAreas series={series} interval="day" />);
    expect(lastOptions().chart?.animations?.enabled).not.toBe(false);
    testRender(<WidgetMultiAreas series={series} interval="day" isStacked isAnimated={false} />);
    expect(lastOptions().chart?.animations?.enabled).toBe(false);
    expect(lastOptions().chart?.stacked).toBe(true);
  });

  it('keeps the first draw animated without animating the updates on demand', () => {
    testRender(<WidgetMultiLines series={series} interval="day" isUpdateAnimated={false} />);
    expect(lastOptions().chart?.animations?.enabled).not.toBe(false);
    expect(lastOptions().chart?.animations?.dynamicAnimation?.enabled).toBe(false);

    testRender(<WidgetMultiAreas series={series} interval="day" isUpdateAnimated={false} />);
    expect(lastOptions().chart?.animations?.dynamicAnimation?.enabled).toBe(false);
    testRender(<WidgetMultiHeatMap data={series} minValue={0} maxValue={3} isUpdateAnimated={false} />);
    expect(lastOptions().chart?.animations?.dynamicAnimation?.enabled).toBe(false);
  });

  it('colors the values of a heatmap spread over less than 9', () => {
    testRender(<WidgetMultiHeatMap data={series} minValue={0} maxValue={3} />);
    const ranges = lastOptions().plotOptions?.heatmap?.colorScale?.ranges ?? [];
    [1, 2, 3].forEach((value) => {
      expect(ranges.some((range) => (range.from ?? 0) <= value && value <= (range.to ?? 0))).toBe(true);
    });
  });

  it('labels the heatmap axis with its interval and disables its animations on demand', () => {
    testRender(<WidgetMultiHeatMap data={series} minValue={0} maxValue={3} />);
    expect(lastOptions().chart?.animations?.enabled).not.toBe(false);

    testRender(<WidgetMultiHeatMap data={series} minValue={0} maxValue={3} interval="month" isAnimated={false} />);
    const options = lastOptions();
    expect(options.chart?.animations?.enabled).toBe(false);
    const formatter = (options.xaxis?.labels?.formatter) as (value: string) => string;
    expect(formatter('2025-10-01T00:00:00.000Z')).toEqual('October 2025');
  });
});
