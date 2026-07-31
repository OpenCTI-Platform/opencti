import { describe, it, expect } from 'vitest';
import { simpleLabelTooltip } from './Charts';

const buildTheme = (overrides = {}) => ({
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
      expect(html).not.toContain('<img');
      expect(html).not.toContain('onerror=');
    });

    it('should sanitize a malicious theme background color (theme_nav injection)', () => {
      const theme = buildTheme({ background: { nav: '"><script>alert(1)</script>' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('<script>');
    });

    it('should sanitize a malicious theme text color', () => {
      const theme = buildTheme({ text: { primary: '"><svg onload=alert(1)>' } });
      const html = simpleLabelTooltip(theme)({ seriesIndex: 0, w: { config: { labels: ['label'] } } });
      expect(html).not.toContain('<svg');
      expect(html).not.toContain('onload=');
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
