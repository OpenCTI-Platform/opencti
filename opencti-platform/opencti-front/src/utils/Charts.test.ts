import { describe, expect, it, vi } from 'vitest';
import { areaChartOptions, lineChartOptions, simpleLabelTooltip, verticalBarsChartOptions } from './Charts';

interface ThemeOverrides {
  background?: { nav?: unknown };
  text?: { primary?: unknown };
}

const buildTheme = (overrides: ThemeOverrides = {}) => ({
  palette: {
    background: { nav: '#0a0a0a', ...overrides.background },
    text: { primary: '#ffffff', ...overrides.text },
  },
});

describe('Charts utils', () => {
  describe('Function: simpleLabelTooltip()', () => {
    it('should render the label and theme colors when inputs are safe', () => {
      const theme = buildTheme();
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['Organization ABC'] } } });
      expect(html).toContain('Organization ABC');
      expect(html).toContain('#0a0a0a');
      expect(html).toContain('#ffffff');
    });

    it('should sanitize a malicious entity label (stored XSS payload)', () => {
      const theme = buildTheme();
      const maliciousLabel = '<img src=x onerror=alert(1)>';
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: [maliciousLabel] } } });
      expect(html).not.toContain(maliciousLabel);
      expect(html).not.toContain('<img');
      expect(html).toContain('&lt;img');
    });

    it('should reject a malicious theme background color (theme_nav injection) and fall back to a safe value', () => {
      const theme = buildTheme({ background: { nav: '"><script>alert(1)</script>' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('<script>');
      expect(html).not.toContain('"><');
      expect(html).toContain('background: inherit');
    });

    it('should reject a malicious theme text color and fall back to a safe value', () => {
      const theme = buildTheme({ text: { primary: '"><svg onload=alert(1)>' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('<svg');
      expect(html).not.toContain('"><');
      expect(html).toContain('color: inherit');
    });

    it('should reject a color value breaking out of the style attribute via a quote and fall back to a safe value', () => {
      // an unvalidated color like this would close the style="..." attribute early
      // and inject a new onmouseover attribute on the div element
      const theme = buildTheme({ text: { primary: '" onmouseover="alert(1)' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('" onmouseover="');
      expect(html).toContain('color: inherit');
    });

    it('should reject a color value trying to inject extra CSS declarations via a semicolon', () => {
      const theme = buildTheme({ background: { nav: 'red; background-image: url(https://evil.example/leak)' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('background-image');
      expect(html).toContain('background: inherit');
    });

    it('should accept a well-formed 6-digit hex color', () => {
      const theme = buildTheme({ background: { nav: '#123abc' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).toContain('background: #123abc');
    });

    it('should not throw and fall back to an empty string when the label is undefined', () => {
      const theme = buildTheme();
      expect(() => simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: [undefined] } } })).not.toThrow();
    });

    it('should not throw and coerce non-string labels (numbers/booleans)', () => {
      const theme = buildTheme();
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: [42] } } });
      expect(html).toContain('42');
    });

    it('should not throw when theme color values are undefined', () => {
      const theme = buildTheme({ background: { nav: undefined }, text: { primary: undefined } });
      expect(() => simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } })).not.toThrow();
    });
  });
});

/**
 * ApexCharts hands `click`/`mouseMove` `Object.assign({}, w, { seriesIndex,
 * dataPointIndex })` (Events.js:73-76), so the series live under
 * `config.config`, not `config.w.config`. Both indices come from
 * `e.target.getAttribute(...)`, hence the strings below.
 */
const chartTheme = {
  palette: {
    mode: 'dark',
    background: { paper: '#111111' },
    text: { secondary: '#cccccc' },
    primary: { main: '#00ff00' },
  },
};

const apexConfig = (points: unknown[], seriesIndex: unknown = '0', dataPointIndex: unknown = '1') => ({
  seriesIndex,
  dataPointIndex,
  config: { series: [{ data: points }] },
});

const mouseEvent = (overrides: Record<string, unknown> = {}) => ({
  ctrlKey: false,
  metaKey: false,
  button: 0,
  preventDefault: vi.fn(),
  stopPropagation: vi.fn(),
  target: { style: {} as Record<string, string>, classList: { add: vi.fn(), remove: vi.fn() } },
  ...overrides,
});

const POINTS = [
  { x: new Date('2024-02-01T00:00:00.000Z'), y: 3 },
  { x: new Date('2024-03-01T00:00:00.000Z'), y: 7 },
];

describe.each([
  ['lineChartOptions', (drilldown: unknown) => lineChartOptions(chartTheme, true, null, null, undefined, false, true, drilldown)],
  ['areaChartOptions', (drilldown: unknown) => areaChartOptions(chartTheme, true, null, null, undefined, false, true, drilldown)],
  ['verticalBarsChartOptions', (drilldown: unknown) => verticalBarsChartOptions(chartTheme, null, null, false, false, false, false, undefined, drilldown)],
])('%s drill-down wiring', (_name, build) => {
  it('navigates to the link resolved for the clicked bucket', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/dashboard/arsenal/malwares?filters=%7B%7D');
    const options = build({ getLink, navigate });

    options.chart.events.click(mouseEvent(), {}, apexConfig(POINTS));

    expect(getLink).toHaveBeenCalledWith(0, { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' });
    expect(navigate).toHaveBeenCalledWith('/dashboard/arsenal/malwares?filters=%7B%7D');
  });

  it('stays inert when the resolver refuses the bucket', () => {
    const navigate = vi.fn();
    const options = build({ getLink: () => null, navigate });

    options.chart.events.click(mouseEvent(), {}, apexConfig(POINTS));

    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert when the click landed outside any data point', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/x');
    const options = build({ getLink, navigate });

    options.chart.events.click(mouseEvent(), {}, apexConfig(POINTS, '-1', '-1'));

    expect(getLink).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows a pointer exactly where clicking would navigate', () => {
    const getLink = (_i: number, bucket: { date: string }) => (bucket.date === '2024-03-01T00:00:00.000Z' ? '/x' : null);
    const options = build({ getLink, navigate: vi.fn() });

    const onLink = mouseEvent();
    options.chart.events.mouseMove(onLink, {}, apexConfig(POINTS));
    expect(onLink.target.style.cursor).toBe('pointer');

    const offLink = mouseEvent();
    options.chart.events.mouseMove(offLink, {}, apexConfig(POINTS, '0', '0'));
    expect(offLink.target.style.cursor).toBe('default');
    // Charts reuse their SVG nodes between hovers, so leaving an inert surface
    // marked noDrag would silently make part of the widget undraggable.
    expect(offLink.target.classList.remove).toHaveBeenCalledWith('noDrag');
  });

  it('marks the clickable surface noDrag so the widget is not dragged instead', () => {
    const options = build({ getLink: () => '/x', navigate: vi.fn() });
    const event = mouseEvent();

    options.chart.events.mouseMove(event, {}, apexConfig(POINTS));

    expect(event.target.classList.add).toHaveBeenCalledWith('noDrag');
  });

  it('opens a new tab on ctrl-click instead of navigating', () => {
    const navigate = vi.fn();
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    const options = build({ getLink: () => '/x', navigate });

    options.chart.events.click(mouseEvent({ ctrlKey: true }), {}, apexConfig(POINTS));

    expect(open).toHaveBeenCalledWith('/x', '_blank');
    expect(navigate).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('installs no handler at all when the widget has no drill-down', () => {
    expect(build(undefined).chart.events?.click).toBeUndefined();
  });
});
