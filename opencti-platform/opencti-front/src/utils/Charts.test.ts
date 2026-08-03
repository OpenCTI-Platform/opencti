import { describe, it, expect } from 'vitest';
import { simpleLabelTooltip } from './Charts';

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
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['Organization ABC'] } },
      });
      expect(html).toContain('Organization ABC');
      expect(html).toContain('#0a0a0a');
      expect(html).toContain('#ffffff');
    });

    it('should sanitize a malicious entity label (stored XSS payload)', () => {
      const theme = buildTheme();
      const maliciousLabel = '<img src=x onerror=alert(1)>';
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: [maliciousLabel] } },
      });
      expect(html).not.toContain(maliciousLabel);
      expect(html).not.toContain('<img');
      expect(html).toContain('&lt;img');
    });

    it('should reject a malicious theme background color (theme_nav injection) and fall back to a safe value', () => {
      const theme = buildTheme({ background: { nav: '"><script>alert(1)</script>' } });
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['label'] } },
      });
      expect(html).not.toContain('<script>');
      expect(html).not.toContain('"><');
      expect(html).toContain('background: inherit');
    });

    it('should reject a malicious theme text color and fall back to a safe value', () => {
      const theme = buildTheme({ text: { primary: '"><svg onload=alert(1)>' } });
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['label'] } },
      });
      expect(html).not.toContain('<svg');
      expect(html).not.toContain('"><');
      expect(html).toContain('color: inherit');
    });

    it('should reject a color value breaking out of the style attribute via a quote and fall back to a safe value', () => {
      // an unvalidated color like this would close the style="..." attribute early
      // and inject a new onmouseover attribute on the div element
      const theme = buildTheme({ text: { primary: '" onmouseover="alert(1)' } });
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['label'] } },
      });
      expect(html).not.toContain('" onmouseover="');
      expect(html).toContain('color: inherit');
    });

    it('should reject a color value trying to inject extra CSS declarations via a semicolon', () => {
      const theme = buildTheme({
        background: { nav: 'red; background-image: url(https://evil.example/leak)' },
      });
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['label'] } },
      });
      expect(html).not.toContain('background-image');
      expect(html).toContain('background: inherit');
    });

    it('should accept a well-formed 6-digit hex color', () => {
      const theme = buildTheme({ background: { nav: '#123abc' } });
      const html = simpleLabelTooltip(theme)({
        seriesIndex: 0,
        w: { config: { labels: ['label'] } },
      });
      expect(html).toContain('background: #123abc');
    });

    it('should not throw and fall back to an empty string when the label is undefined', () => {
      const theme = buildTheme();
      expect(() =>
        simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: [undefined] } } }),
      ).not.toThrow();
    });

    it('should not throw and coerce non-string labels (numbers/booleans)', () => {
      const theme = buildTheme();
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: [42] } } });
      expect(html).toContain('42');
    });

    it('should not throw when theme color values are undefined', () => {
      const theme = buildTheme({ background: { nav: undefined }, text: { primary: undefined } });
      expect(() =>
        simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } }),
      ).not.toThrow();
    });
  });
});
