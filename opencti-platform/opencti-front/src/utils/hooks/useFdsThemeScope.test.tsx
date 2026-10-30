import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import useFdsThemeScope from './useFdsThemeScope';
import { isLightThemeName } from '../themeName';
import { FDS } from '../../components/fds-tokens.generated';

describe('Hook: useFdsThemeScope', () => {
  const root = () => document.documentElement;

  beforeEach(() => {
    root().removeAttribute('class');
    root().removeAttribute('style');
  });

  /*
   * Issue #18468. MUI's palette does not drive CSS custom properties, so a colour
   * this hook does not write keeps the library's own value and a customised theme
   * stays blue. The class assertions alone passed happily while five of the six
   * settings were unwired. What each class switches on is locked by
   * static/css/custom-theme-tokens.test.ts.
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

  it('switches on the derived tokens of each customised setting, and only those', () => {
    renderHook(() => useFdsThemeScope('Corporate', { paper: '#25112a', primary: '#c77dff' }));
    expect(root().classList.contains('fds-custom-paper')).toBe(true);
    expect(root().classList.contains('fds-custom-primary')).toBe(true);
    expect(root().classList.contains('fds-custom-background')).toBe(false);
    expect(root().classList.contains('fds-custom-text')).toBe(false);
  });

  it('writes nothing when a setting still holds the library value, leaving the default theme alone', () => {
    renderHook(() => useFdsThemeScope('Filigran Dark', {
      paper: FDS.colors.dark['--bg-elevation-default-layer-1'],
      primary: FDS.colors.dark['--color-filigran-brand-primary'].toUpperCase(),
    }));
    expect(token('--bg-elevation-default-layer-1')).toBe('');
    expect(token('--color-filigran-brand-primary')).toBe('');
    expect(root().classList.contains('fds-custom-paper')).toBe(false);
    expect(root().classList.contains('fds-custom-primary')).toBe(false);
  });

  it('clears an override when the theme goes back to the default', () => {
    const { rerender } = renderHook(
      ({ c }: { c: Parameters<typeof useFdsThemeScope>[1] }) => useFdsThemeScope('Corporate', c),
      { initialProps: { c: { paper: '#25112a' } as Parameters<typeof useFdsThemeScope>[1] } },
    );
    expect(token('--bg-elevation-default-layer-1')).toBe('#25112a');
    rerender({ c: {} });
    expect(token('--bg-elevation-default-layer-1')).toBe('');
    expect(root().classList.contains('fds-custom-paper')).toBe(false);
  });
});
