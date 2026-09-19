import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import type { ApexOptions } from 'apexcharts';
import Chart from './Chart';

let receivedOptions: ApexOptions | undefined;

vi.mock('react-apexcharts', () => ({
  default: ({ options }: { options: ApexOptions }) => {
    receivedOptions = options;
    return <div data-testid="apex-chart" />;
  },
}));

const renderChart = (options: ApexOptions) => {
  render(<Chart options={options} series={[]} type="bar" />);
  return receivedOptions as ApexOptions;
};

// Formatters are declared with a loose signature by ApexCharts, calling them in tests requires a cast.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const callFormatter = (formatter: unknown, value: unknown) => (formatter as any)(value);

describe('Component: Chart', () => {
  beforeEach(() => {
    receivedOptions = undefined;
  });

  it('should keep the mounted callback and the given options', () => {
    const onMounted = vi.fn();
    render(<Chart options={{ chart: { type: 'donut' } }} series={[]} type="donut" onMounted={onMounted} />);
    expect(receivedOptions?.chart?.type).toEqual('donut');
    expect(receivedOptions?.chart?.events?.mounted).toEqual(onMounted);
  });

  describe('Legend labels', () => {
    it('should escape markup in a legend label', () => {
      const options = renderChart({});
      const label = callFormatter(options.legend?.formatter, '<img src=x onerror=alert(1)>');
      expect(label).not.toContain('<img');
      expect(label).toEqual('&lt;img src=x onerror=alert(1)&gt;');
    });

    it('should display a label containing an ampersand as is', () => {
      const options = renderChart({});
      // '&amp;' is decoded back to '&' by the browser when the legend is rendered
      expect(callFormatter(options.legend?.formatter, 'AT&T')).toEqual('AT&amp;T');
    });

    it('should keep the formatter already configured on the chart', () => {
      const options = renderChart({ legend: { formatter: (value) => `[${value}]` } });
      expect(callFormatter(options.legend?.formatter, 'ACME')).toEqual('[ACME]');
      expect(callFormatter(options.legend?.formatter, '<b>ACME</b>')).toEqual('[&lt;b&gt;ACME&lt;/b&gt;]');
    });

    it('should join the parts of a multiline label', () => {
      const options = renderChart({});
      expect(callFormatter(options.legend?.formatter, ['ACME', 'Corp'])).toEqual('ACME Corp');
    });
  });

  describe('Tooltip labels', () => {
    it('should escape markup in the tooltip title', () => {
      const options = renderChart({});
      const title = callFormatter(options.tooltip?.x?.formatter, '<img src=x onerror=alert(1)>');
      expect(title).not.toContain('<img');
      expect(title).toEqual('&lt;img src=x onerror=alert(1)&gt;');
    });

    it('should keep the axis formatting of the tooltip title of an horizontal bars chart', () => {
      const options = renderChart({
        plotOptions: { bar: { horizontal: true } },
        yaxis: { labels: { formatter: (value) => `${value}!` } },
      });
      expect(callFormatter(options.tooltip?.x?.formatter, 'ACME')).toEqual('ACME!');
      expect(callFormatter(options.tooltip?.x?.formatter, '<b>ACME</b>')).toEqual('&lt;b&gt;ACME&lt;/b&gt;!');
    });

    it('should not format the tooltip title of a datetime chart', () => {
      const options = renderChart({ xaxis: { type: 'datetime' } });
      expect(options.tooltip?.x?.formatter).toBeUndefined();
    });

    it('should escape markup in a series name', () => {
      const options = renderChart({});
      const tooltipY = Array.isArray(options.tooltip?.y) ? options.tooltip?.y[0] : options.tooltip?.y;
      const name = callFormatter(tooltipY?.title?.formatter, '<b>ACME</b>');
      expect(name).toEqual('&lt;b&gt;ACME&lt;/b&gt;: ');
    });

    it('should keep an empty series name empty', () => {
      const options = renderChart({});
      const tooltipY = Array.isArray(options.tooltip?.y) ? options.tooltip?.y[0] : options.tooltip?.y;
      expect(callFormatter(tooltipY?.title?.formatter, '')).toEqual('');
    });
  });
});
