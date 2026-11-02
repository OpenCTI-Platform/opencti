import { describe, it, expect } from 'vitest';
import { areaChartOptions, lineChartOptions, pointXTooltipFormatter, simpleLabelTooltip } from './Charts';

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

  describe('Function: pointXTooltipFormatter()', () => {
    const july = new Date('2025-07-01T00:00:00.000Z');
    const august = new Date('2025-08-01T00:00:00.000Z');
    const w = { config: { series: [{ name: 'serie', data: [{ x: july, y: 3 }, { x: august, y: 5 }] }] } };
    const isoFormatter = (date: Date) => date.toISOString().slice(0, 7);

    it('should format the date of the hovered point, not the index given on a category axis', () => {
      // On a category axis ApexCharts passes the point index (1) as the value:
      // formatted as a date it would be the epoch on every point (issue #17917).
      expect(pointXTooltipFormatter(isoFormatter)(1, { seriesIndex: 0, dataPointIndex: 1, w })).toEqual('2025-08');
      expect(pointXTooltipFormatter(isoFormatter)(0, { seriesIndex: 0, dataPointIndex: 0, w })).toEqual('2025-07');
    });

    it('should fall back to the given value when the point cannot be found', () => {
      const value = july.getTime();
      expect(pointXTooltipFormatter((v: number) => `v${v}`)(value, { seriesIndex: 3, dataPointIndex: 0, w })).toEqual(`v${value}`);
      expect(pointXTooltipFormatter((v: number) => `v${v}`)(value)).toEqual(`v${value}`);
    });

    it('should return the raw x value without a formatter', () => {
      expect(pointXTooltipFormatter(null)(0, { seriesIndex: 0, dataPointIndex: 0, w })).toEqual(july);
    });

    it('should be the tooltip header formatter of the line and area charts', () => {
      const theme = { palette: { mode: 'dark', background: { paper: '#000000' }, text: { secondary: '#ffffff' }, primary: { main: '#0fbcff' } } };
      [lineChartOptions(theme, false, isoFormatter), areaChartOptions(theme, false, isoFormatter)].forEach((options) => {
        expect(options.tooltip.x?.formatter(1, { seriesIndex: 0, dataPointIndex: 1, w })).toEqual('2025-08');
      });
    });

    it('should keep the default tooltip header of the line and area charts without a formatter', () => {
      const theme = { palette: { mode: 'dark', background: { paper: '#000000' }, text: { secondary: '#ffffff' }, primary: { main: '#0fbcff' } } };
      expect(lineChartOptions(theme, true).tooltip).toEqual({ theme: 'dark' });
      expect(areaChartOptions(theme, true).tooltip).toEqual({ theme: 'dark' });
    });
  });
});
