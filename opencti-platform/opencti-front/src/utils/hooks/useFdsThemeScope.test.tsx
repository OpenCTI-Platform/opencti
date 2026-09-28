import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import useFdsThemeScope from './useFdsThemeScope';
import { isLightThemeName } from '../themeName';
import { FDS } from '../../components/fds-tokens.generated';

describe('Hook: useFdsThemeScope', () => {
  const root = () => document.documentElement;

  beforeEach(() => {
    root().classList.remove('light', 'dark');
    root().removeAttribute('style');
  });

  /*
   * Issue #18468. MUI's palette does not drive CSS custom properties, so a colour
   * this hook does not write keeps the library's own value and a customised theme
   * stays blue. These assertions are the reason the suite exists — the class
   * assertions above passed happily while five of the six settings were unwired.
   */
  const token = (name: string) => root().style.getPropertyValue(name);

  it('writes the class on the document root, not on a container', () => {
    renderHook(() => useFdsThemeScope('Light'));

    expect(root().classList.contains('light')).toBe(true);
    expect(root().classList.contains('dark')).toBe(false);
  });

  it('swaps the class reactively when the theme changes after mount', () => {
    const { rerender } = renderHook(
      ({ name }: { name: string }) => useFdsThemeScope(name),
      { initialProps: { name: 'Dark' } },
    );

    expect(root().classList.contains('dark')).toBe(true);

    rerender({ name: 'Light' });
    expect(root().classList.contains('light')).toBe(true);
    expect(root().classList.contains('dark')).toBe(false);

    rerender({ name: 'Dark' });
    expect(root().classList.contains('dark')).toBe(true);
    expect(root().classList.contains('light')).toBe(false);
  });

  // The acquired behaviour this migration must not lose: custom themes are stored in database
  // under arbitrary names, and `themeBuilder` treats everything that is not `Light` as dark.
  it.each(['Dark', 'Corporate', 'filigran-2026', '', undefined])(
    'resolves the non-Light theme name %p to dark',
    (name) => {
      renderHook(() => useFdsThemeScope(name));

      expect(root().classList.contains('dark')).toBe(true);
      expect(root().classList.contains('light')).toBe(false);
    },
  );

  it('writes the light class for the built-in light theme', () => {
    renderHook(() => useFdsThemeScope('Filigran Light'));

    expect(root().classList.contains('light')).toBe(true);
    expect(root().classList.contains('dark')).toBe(false);
  });

  it('writes the dark class for the built-in dark theme', () => {
    renderHook(() => useFdsThemeScope('Filigran Dark'));

    expect(root().classList.contains('dark')).toBe(true);
    expect(root().classList.contains('light')).toBe(false);
  });

  // The three consumers of the theme name -- the MUI palette, this class, and the body `data-theme` attribute --
  // must never disagree.
  it.each(['Filigran Light', 'Light', 'Filigran Dark', 'Dark', 'Corporate', undefined])(
    'agrees with isLightThemeName for %p',
    (name) => {
      const mode = renderHook(() => useFdsThemeScope(name)).result.current;

      expect(mode).toBe(isLightThemeName(name) ? 'light' : 'dark');
      expect(root().classList.contains(mode)).toBe(true);
    },
  );

  it('returns the resolved mode so callers do not re-derive it', () => {
    expect(renderHook(() => useFdsThemeScope('Light')).result.current).toBe('light');
    expect(renderHook(() => useFdsThemeScope('Corporate')).result.current).toBe('dark');
  });

  it('writes every custom colour into the token the library actually reads', () => {
    renderHook(() => useFdsThemeScope('Corporate', {
      background: '#101010',
      paper: '#202020',
      nav: '#303030',
      primary: '#ff00aa',
      secondary: '#00ff88',
      accent: '#404040',
      text: '#f5f5f5',
    }));
    expect(token('--bg-elevation-default-layer-0')).toBe('#101010');
    expect(token('--bg-elevation-default-layer-1')).toBe('#202020');
    expect(token('--bg-elevation-heading-layer-0')).toBe('#303030');
    expect(token('--color-filigran-brand-primary')).toBe('#ff00aa');
    expect(token('--color-filigran-tonic-primary')).toBe('#00ff88');
    expect(token('--bg-elevation-default-layer-3')).toBe('#404040');
    expect(token('--text-default-primary')).toBe('#f5f5f5');
  });

  it('brings a highlight with every custom surface, so a field keeps standing out', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#25112a' }));
    const field = token('--bg-elevation-highlight-layer-1');
    expect(field).toMatch(/^#[0-9a-f]{6}$/);
    expect(field).not.toBe('#25112a');
    // The library's dark step lifts a field above its surface; the customer's must too.
    expect(parseInt(field.slice(1, 3), 16)).toBeGreaterThan(0x25);
  });

  it('moves the field the other way in light mode, where a field sits BELOW its surface', () => {
    renderHook(() => useFdsThemeScope('Filigran Light', { paper: '#f0e8f2' }));
    expect(parseInt(token('--bg-elevation-highlight-layer-1').slice(1, 3), 16)).toBeLessThan(0xf0);
  });

  it('mirrors the step when the surface has no room left, so a field never merges into it', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#ffffff' }));
    const field = token('--bg-elevation-highlight-layer-1');
    expect(field).not.toBe('#ffffff');
    expect(parseInt(field.slice(1, 3), 16)).toBeLessThan(0xff);
  });

  it('carries the whole layer family, so drawers and borders stop being blue', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#25112a' }));
    // layer 2 is the drawers, the one elevation with no setting of its own
    const drawer = token('--bg-elevation-default-layer-2');
    expect(drawer).toMatch(/^#[0-9a-f]{6}$/);
    expect(parseInt(drawer.slice(5, 7), 16)).toBeGreaterThan(parseInt(drawer.slice(3, 5), 16));
    for (const family of ['bg-elevation-highlight', 'border-elevation-subtle', 'border-elevation-default']) {
      expect(token(`--${family}-layer-1`)).toMatch(/^#[0-9a-f]{6}$/);
      expect(token(`--${family}-layer-2`)).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it('moves secondary and disabled text with the primary the customer chose', () => {
    renderHook(() => useFdsThemeScope('Corporate', { text: '#f2e9f5' }));
    const secondary = token('--text-default-secondary');
    expect(secondary).toMatch(/^#[0-9a-f]{6}$/);
    expect(secondary).not.toBe('#f2e9f5');
  });

  it('never lets a field separate less than the library does at its clearest layer', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#25112a' }));
    const surface = token('--bg-elevation-default-layer-2');
    const field = token('--bg-elevation-highlight-layer-2');
    const lum = (hex: string) => {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
      const f = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const [hi, lo] = [lum(surface), lum(field)].sort((a, b) => b - a);
    expect((hi + 0.05) / (lo + 0.05)).toBeGreaterThan(1.2);
  });

  it('covers every per-layer family, not the handful a screenshot happened to show', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#25112a' }));
    // the drawer header and the selected option each live in their own family
    for (const family of ['bg-elevation-heading', 'bg-elevation-hover', 'bg-elevation-disabled',
      'bg-elevation-highlight', 'border-elevation-subtle', 'border-elevation-subtle-soft',
      'border-elevation-default', 'border-elevation-disabled']) {
      expect(token(`--${family}-layer-2`)).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it('lets a setting that owns a token outright win over the derivation', () => {
    renderHook(() => useFdsThemeScope('Corporate', { background: '#101010', nav: '#303030' }));
    expect(token('--bg-elevation-heading-layer-0')).toBe('#303030');
  });

  it('carries the whole accent family, so a hover does not fall back to the library blue', () => {
    renderHook(() => useFdsThemeScope('Corporate', { primary: '#c77dff', secondary: '#00ff88' }));
    for (const name of ['--color-filigran-brand-secondary', '--color-filigran-tonic-secondary',
      '--color-filigran-tonic-accent']) {
      expect(token(name)).toMatch(/^#[0-9a-f]{6}$/);
    }
    expect(token('--color-filigran-brand-tertiary')).toMatch(/^#[0-9a-f]{6}$/);
    expect(token('--color-filigran-brand-tertiary')).not.toBe('#009edb');
    expect(token('--color-filigran-tonic-tertiary')).toMatch(/^#[0-9a-f]{6}$/);
  });

  it('carries the far stop of the body gradient, so the page does not fade back to blue', () => {
    renderHook(() => useFdsThemeScope('Corporate', { background: '#1a0a1f' }));
    const stop = token('--bg-elevation-default-layer-0-gradient');
    expect(stop).toMatch(/^#[0-9a-f]{6}$/);
    expect(stop).not.toBe('#0c1527');
  });

  it('writes nothing when a setting still holds the library value, leaving the default theme alone', () => {
    renderHook(() => useFdsThemeScope('Filigran Dark', {
      paper: FDS.colors.dark['--bg-elevation-default-layer-1'],
      primary: FDS.colors.dark['--color-filigran-brand-primary'],
    }));
    expect(token('--bg-elevation-default-layer-1')).toBe('');
    expect(token('--bg-elevation-highlight-layer-1')).toBe('');
    expect(token('--bg-elevation-default-layer-2')).toBe('');
    expect(token('--border-elevation-subtle-layer-1')).toBe('');
    expect(token('--color-filigran-brand-primary')).toBe('');
  });

  it('clears an override when the theme goes back to the default', () => {
    const { rerender } = renderHook(
      ({ c }: { c: Parameters<typeof useFdsThemeScope>[1] }) => useFdsThemeScope('Corporate', c),
      { initialProps: { c: { paper: '#25112a' } as Parameters<typeof useFdsThemeScope>[1] } },
    );
    expect(token('--bg-elevation-default-layer-1')).toBe('#25112a');
    rerender({ c: {} });
    expect(token('--bg-elevation-default-layer-1')).toBe('');
    expect(token('--bg-elevation-highlight-layer-1')).toBe('');
  });
});
