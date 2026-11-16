import { describe, it, expect } from 'vitest';
import { getSeriesMaxValue, simpleLabelTooltip, withCompactLegend, withIntegerYAxis } from './Charts';

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

  describe('Function: withCompactLegend()', () => {
    it('brings the legend items 2 pixels apart vertically, keeping the rest of the legend', () => {
      const options = withCompactLegend({ legend: { show: true, itemMargin: { horizontal: 5, vertical: 20 } } });
      expect(options.legend).toEqual({ show: true, itemMargin: { horizontal: 5, vertical: 2 } });
    });
  });

  describe('Function: getSeriesMaxValue()', () => {
    const day = (date: number) => new Date(Date.UTC(2026, 0, date));
    const series = [
      { data: [{ x: day(1), y: 2 }, { x: day(2), y: 5 }] },
      { data: [{ x: day(1), y: 4 }, { x: day(2), y: 0 }] },
    ];

    it('reads the highest value, or the highest sum of a date when stacked', () => {
      expect(getSeriesMaxValue(series)).toEqual(5);
      expect(getSeriesMaxValue(series, true)).toEqual(6);
    });

    it('reads values, pairs and missing values too', () => {
      expect(getSeriesMaxValue([{ data: [1, null, 3] }, { data: [2, 2, 2] }], true)).toEqual(5);
      expect(getSeriesMaxValue([{ data: [[day(1), 7]] }, { data: [[day(1), 1]] }], true)).toEqual(8);
      expect(getSeriesMaxValue([])).toEqual(0);
    });
  });

  describe('Function: withIntegerYAxis()', () => {
    const ticks = (maxValue: number) => {
      const { yaxis } = withIntegerYAxis({ yaxis: { labels: { show: true } } }, maxValue);
      return Array.from({ length: yaxis.tickAmount + 1 }, (_, i) => yaxis.min + (i * (yaxis.max - yaxis.min)) / yaxis.tickAmount);
    };

    it('labels a small count once per unit, from 0', () => {
      expect(ticks(1)).toEqual([0, 1]);
      expect(ticks(3)).toEqual([0, 1, 2, 3]);
      expect(ticks(5)).toEqual([0, 1, 2, 3, 4, 5]);
    });

    it('labels a larger count with about 5 integer steps of 1, 2 or 5 times a power of 10', () => {
      expect(ticks(7)).toEqual([0, 2, 4, 6, 8]);
      expect(ticks(12)).toEqual([0, 5, 10, 15]);
      expect(ticks(1234)).toEqual([0, 500, 1000, 1500]);
      [2, 9, 17, 48, 99, 250, 3001].forEach((maxValue) => {
        const values = ticks(maxValue);
        values.forEach((value) => expect(Number.isInteger(value)).toBe(true));
        expect(values.at(-1)).toBeGreaterThanOrEqual(maxValue);
        expect(values.length).toBeLessThanOrEqual(11);
      });
    });

    it('keeps the axis of no count from 0, and the rest of the axis', () => {
      expect(withIntegerYAxis({ yaxis: { labels: { show: true } } }, 0).yaxis).toEqual({ labels: { show: true }, min: 0 });
      expect(withIntegerYAxis({ yaxis: { labels: { show: true } } }, 3).yaxis.labels).toEqual({ show: true });
    });
  });
});
