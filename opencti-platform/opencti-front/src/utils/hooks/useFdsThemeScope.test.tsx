import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import useFdsThemeScope from './useFdsThemeScope';

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

  // The acquired behaviour this migration must not lose: custom themes are
  // stored in database under arbitrary names, and `themeBuilder` treats
  // everything that is not `Light` as dark. If this hook resolved such a name
  // to light, MUI and FDS would disagree and the rail would be unreadable.
  it.each(['Dark', 'Corporate', 'filigran-2026', '', undefined])(
    'resolves the non-Light theme name %p to dark',
    (name) => {
      renderHook(() => useFdsThemeScope(name));

      expect(root().classList.contains('dark')).toBe(true);
      expect(root().classList.contains('light')).toBe(false);
    },
  );

  it('returns the resolved mode so callers do not re-derive it', () => {
    expect(renderHook(() => useFdsThemeScope('Light')).result.current).toBe('light');
    expect(renderHook(() => useFdsThemeScope('Corporate')).result.current).toBe('dark');
  });
});
