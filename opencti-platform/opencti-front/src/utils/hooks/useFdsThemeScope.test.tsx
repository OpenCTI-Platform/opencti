import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import useFdsThemeScope from './useFdsThemeScope';
import { isLightThemeName } from '../themeName';

describe('Hook: useFdsThemeScope', () => {
  const root = () => document.documentElement;

  beforeEach(() => {
    root().classList.remove('light', 'dark');
  });

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

  // The built-in themes were renamed to `Filigran Dark` / `Filigran Light`. When this hook
  // still tested the legacy name only, a light install wrote `.dark` on the root while MUI
  // built the light palette: light surfaces painted with dark tokens.
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

  // The three consumers of the theme name -- the MUI palette, this class, and the body
  // `data-theme` attribute -- must never disagree. They agree because they all ask
  // `isLightThemeName`; this pins that they still do.
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
});
