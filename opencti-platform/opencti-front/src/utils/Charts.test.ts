import { describe, expect, it, vi } from 'vitest';
import {
  areaChartOptions,
  donutChartOptions,
  horizontalBarsChartOptions,
  lineChartOptions,
  polarAreaChartOptions,
  radarChartOptions,
  simpleLabelTooltip,
  treeMapOptions,
  verticalBarsChartOptions,
} from './Charts';

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
    text: { secondary: '#cccccc', primary: '#ffffff' },
    primary: { main: '#00ff00' },
    common: { white: '#ffffff', black: '#000000' },
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

type ChartEvents = {
  click?: (event: unknown, ctx: unknown, config: unknown) => void;
  mouseMove?: (event: unknown, ctx: unknown, config: unknown) => void;
  xAxisLabelClick?: (event: unknown, ctx: unknown, config: unknown) => void;
};

/** The factories are plain JS, so the events bag needs naming before use. */
const chartEvents = (options: { chart: { events?: unknown } }) => (options.chart.events ?? {}) as ChartEvents;

type TestDrilldown = {
  getLink: (selectionIndex: number, bucket: { kind: string; date: string }) => string | null;
  navigate: (to: string) => void;
};

const identityFormatter = (value: unknown) => String(value);

const POINTS = [
  { x: new Date('2024-02-01T00:00:00.000Z'), y: 3 },
  { x: new Date('2024-03-01T00:00:00.000Z'), y: 7 },
];

describe.each([
  ['lineChartOptions', (drilldown?: TestDrilldown) => lineChartOptions(chartTheme, true, undefined, undefined, undefined, false, true, drilldown)],
  ['areaChartOptions', (drilldown?: TestDrilldown) => areaChartOptions(chartTheme, true, undefined, undefined, undefined, false, true, drilldown)],
  ['verticalBarsChartOptions', (drilldown?: TestDrilldown) => verticalBarsChartOptions(chartTheme, identityFormatter, identityFormatter, false, false, false, false, undefined, drilldown)],
])('%s drill-down wiring', (_name, build) => {
  it('navigates to the link resolved for the clicked bucket', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/dashboard/arsenal/malwares?filters=%7B%7D');
    const options = build({ getLink, navigate });

    chartEvents(options).click!(mouseEvent(), {}, apexConfig(POINTS));

    expect(getLink).toHaveBeenCalledWith(0, { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' });
    expect(navigate).toHaveBeenCalledWith('/dashboard/arsenal/malwares?filters=%7B%7D');
  });

  it('stays inert when the resolver refuses the bucket', () => {
    const navigate = vi.fn();
    const options = build({ getLink: () => null, navigate });

    chartEvents(options).click!(mouseEvent(), {}, apexConfig(POINTS));

    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert when the click landed outside any data point', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/x');
    const options = build({ getLink, navigate });

    chartEvents(options).click!(mouseEvent(), {}, apexConfig(POINTS, '-1', '-1'));

    expect(getLink).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert when ApexCharts reports no index at all', () => {
    // `Events.js` yields the raw `getAttribute` result, so a click on the chart
    // background before any point was hovered gives null -- and `Number(null)`
    // is 0, which would otherwise resolve the first bucket.
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/x');
    const options = build({ getLink, navigate });

    chartEvents(options).click!(mouseEvent(), {}, apexConfig(POINTS, null, null));

    expect(getLink).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows a pointer exactly where clicking would navigate', () => {
    const getLink = (_i: number, bucket: { date: string }) => (bucket.date === '2024-03-01T00:00:00.000Z' ? '/x' : null);
    const options = build({ getLink, navigate: vi.fn() });

    const onLink = mouseEvent();
    chartEvents(options).mouseMove!(onLink, {}, apexConfig(POINTS));
    expect(onLink.target.style.cursor).toBe('pointer');

    const offLink = mouseEvent();
    chartEvents(options).mouseMove!(offLink, {}, apexConfig(POINTS, '0', '0'));
    expect(offLink.target.style.cursor).toBe('default');
    // Charts reuse their SVG nodes between hovers, so leaving an inert surface
    // marked noDrag would silently make part of the widget undraggable.
    expect(offLink.target.classList.remove).toHaveBeenCalledWith('noDrag');
  });

  it('marks the clickable surface noDrag so the widget is not dragged instead', () => {
    const options = build({ getLink: () => '/x', navigate: vi.fn() });
    const event = mouseEvent();

    chartEvents(options).mouseMove!(event, {}, apexConfig(POINTS));

    expect(event.target.classList.add).toHaveBeenCalledWith('noDrag');
  });

  it('opens a new tab on ctrl-click instead of navigating', () => {
    const navigate = vi.fn();
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    const options = build({ getLink: () => '/x', navigate });

    chartEvents(options).click!(mouseEvent({ ctrlKey: true }), {}, apexConfig(POINTS));

    expect(open).toHaveBeenCalledWith('/x', '_blank');
    expect(navigate).not.toHaveBeenCalled();
    open.mockRestore();
  });

  it('installs no handler at all when the widget has no drill-down', () => {
    expect(chartEvents(build(undefined)).click).toBeUndefined();
  });
});

describe('horizontalBarsChartOptions with gapped redirections', () => {
  // `buildDistributionRedirectionUtils` now yields `null` for buckets that
  // resolve to no entity, which is what keeps the array aligned with the bars.
  const withGap = [null, { id: 'c', entity_type: 'Tool' }];

  const build = () => horizontalBarsChartOptions(
    chartTheme, false, undefined, undefined, false, vi.fn(), withGap, false, false, undefined, false, 'normal',
  );

  it('ignores a label click on a bucket with no entity', () => {
    const navigate = vi.fn();
    const options = horizontalBarsChartOptions(
      chartTheme, false, undefined, undefined, false, navigate, withGap, false, false, undefined, false, 'normal',
    );
    expect(() => chartEvents(options).xAxisLabelClick!(mouseEvent(), {}, { labelIndex: 0 })).not.toThrow();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('still navigates for the bucket that kept its index', () => {
    const navigate = vi.fn();
    const options = horizontalBarsChartOptions(
      chartTheme, false, undefined, undefined, false, navigate, withGap, false, false, undefined, false, 'normal',
    );
    chartEvents(options).xAxisLabelClick!(mouseEvent(), {}, { labelIndex: 1 });
    expect(navigate).toHaveBeenCalledWith(expect.stringContaining('/c'));
  });

  it('does not throw when a bar with no entity is clicked', () => {
    const options = build();
    expect(() => chartEvents(options).click!(mouseEvent(), {}, { dataPointIndex: 0, seriesIndex: -1 })).not.toThrow();
  });
});

describe('horizontalBarsChartOptions falls back to the entity page', () => {
  // Widgets aggregating on an attribute the drill-down cannot express as a list
  // filter (`internal_id`, used by every Home dashboard bar chart) resolve no
  // link. The bar must keep its historical navigation rather than go inert.
  const redirections = [{ id: 'c', entity_type: 'Tool' }];
  const barConfig = { seriesIndex: 0, dataPointIndex: '0' };

  const build = (getLink: () => string | null, navigate: () => void, drilldownNavigate: () => void) => horizontalBarsChartOptions(
    chartTheme, false, undefined, undefined, false, navigate, redirections, false, false, undefined, false, 'normal',
    { getLink, navigate: drilldownNavigate, buckets: BUCKETS },
  );

  it('navigates to the entity when the drill-down resolves no link', () => {
    const navigate = vi.fn();
    const drilldownNavigate = vi.fn();
    const options = build(() => null, navigate, drilldownNavigate);

    chartEvents(options).click!(mouseEvent(), {}, barConfig);

    expect(drilldownNavigate).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(expect.stringContaining('/c'));
  });

  it('keeps the pointer cursor on a bar that falls back to the entity page', () => {
    const event = mouseEvent();
    const options = build(() => null, vi.fn(), vi.fn());

    chartEvents(options).mouseMove!(event, {}, barConfig);

    expect(event.target.style.cursor).toBe('pointer');
  });

  it('prefers the filtered list when the drill-down resolves a link', () => {
    const navigate = vi.fn();
    const drilldownNavigate = vi.fn();
    const options = build(() => '/dashboard/list?filters=x', navigate, drilldownNavigate);

    chartEvents(options).click!(mouseEvent(), {}, barConfig);

    expect(navigate).not.toHaveBeenCalled();
    expect(drilldownNavigate).toHaveBeenCalledWith('/dashboard/list?filters=x');
  });
});

type DistributionBucket = { kind: 'distribution'; rawValue: string | null; entityId?: string | null };

const BUCKETS: (DistributionBucket | null)[] = [
  { kind: 'distribution', rawValue: 'Malware', entityId: null },
  { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
  null,
];

type TestDistributionDrilldown = {
  getLink: (selectionIndex: number, bucket: DistributionBucket) => string | null;
  navigate: (to: string) => void;
  buckets: (DistributionBucket | null)[];
};

/**
 * Distribution charts report the clicked bucket through `dataPointIndex` only:
 * pie slices and radar markers carry a `j` attribute but no `i`, so the series
 * index is not reliable -- and it is not needed either, these widgets always
 * render a single data selection.
 */
const distributionConfig = (dataPointIndex: unknown) => ({ seriesIndex: 0, dataPointIndex });

describe.each([
  ['donutChartOptions', (d?: TestDistributionDrilldown) => donutChartOptions(chartTheme, ['A', 'B', 'C'], 'bottom', false, [], true, true, true, true, 70, true, d)],
  ['polarAreaChartOptions', (d?: TestDistributionDrilldown) => polarAreaChartOptions(chartTheme, ['A', 'B', 'C'], identityFormatter, 'bottom', [], d)],
  ['radarChartOptions', (d?: TestDistributionDrilldown) => radarChartOptions(chartTheme, ['A', 'B', 'C'], identityFormatter, [], true, undefined, undefined, undefined, d)],
  ['treeMapOptions', (d?: TestDistributionDrilldown) => treeMapOptions(chartTheme, identityFormatter, 'bottom', false, d)],
  ['horizontalBarsChartOptions', (d?: TestDistributionDrilldown) => horizontalBarsChartOptions(chartTheme, false, identityFormatter, identityFormatter, false, undefined, undefined, false, false, undefined, false, 'normal', d)],
])('%s distribution drill-down wiring', (_name, build) => {
  const drilldown = (getLink: () => string | null, navigate = vi.fn()) => ({ getLink, navigate, buckets: BUCKETS });

  it('navigates to the link resolved for the clicked bucket', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/dashboard/entities/organizations?filters=%7B%7D');
    const options = build({ getLink, navigate, buckets: BUCKETS });

    chartEvents(options).click!(mouseEvent(), {}, distributionConfig('1'));

    expect(getLink).toHaveBeenCalledWith(0, BUCKETS[1]);
    expect(navigate).toHaveBeenCalledWith('/dashboard/entities/organizations?filters=%7B%7D');
  });

  it('stays inert when the resolver refuses the bucket', () => {
    const navigate = vi.fn();
    const options = build(drilldown(() => null, navigate));

    chartEvents(options).click!(mouseEvent(), {}, distributionConfig('0'));

    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert on a bucket that carries no value', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/x');
    const options = build({ getLink, navigate, buckets: BUCKETS });

    chartEvents(options).click!(mouseEvent(), {}, distributionConfig('2'));

    expect(getLink).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert when ApexCharts reports no index at all', () => {
    const navigate = vi.fn();
    const getLink = vi.fn(() => '/x');
    const options = build({ getLink, navigate, buckets: BUCKETS });

    chartEvents(options).click!(mouseEvent(), {}, distributionConfig(null));

    expect(getLink).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('stays inert past the end of the buckets', () => {
    const navigate = vi.fn();
    const options = build(drilldown(() => '/x', navigate));

    chartEvents(options).click!(mouseEvent(), {}, distributionConfig('9'));

    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows a pointer exactly where clicking would navigate', () => {
    const options = build(drilldown(() => '/x'));
    const event = mouseEvent();

    chartEvents(options).mouseMove!(event, {}, distributionConfig('0'));

    expect(event.target.style.cursor).toBe('pointer');
    expect(event.target.classList.add).toHaveBeenCalledWith('noDrag');
  });

  it('gives the cursor and the drag back on an inert surface', () => {
    const options = build(drilldown(() => null));
    const event = mouseEvent();

    chartEvents(options).mouseMove!(event, {}, distributionConfig('0'));

    expect(event.target.style.cursor).toBe('default');
    expect(event.target.classList.remove).toHaveBeenCalledWith('noDrag');
  });

  it('opens a new tab on ctrl-click instead of navigating', () => {
    const navigate = vi.fn();
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    const options = build(drilldown(() => '/x', navigate));

    chartEvents(options).click!(mouseEvent({ ctrlKey: true }), {}, distributionConfig('0'));

    expect(open).toHaveBeenCalledWith('/x', '_blank');
    expect(navigate).not.toHaveBeenCalled();
    open.mockRestore();
  });
});
