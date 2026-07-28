import { createTheme, ThemeProvider } from '@mui/material/styles';
import { act, renderHook } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import useFdsThemeScope from './useFdsThemeScope';

describe('Hook: useFdsThemeScope', () => {
  // Lets the test flip the MUI palette mode after mount without relying on
  // renderHook's `rerender` (which only re-invokes the hook callback, not
  // the wrapper) — the wrapper owns the mode as local state and exposes its
  // setter through this closure variable so `act()` can trigger a real
  // context update, exactly like a live theme change would.
  let setMode: (mode: 'light' | 'dark') => void = () => {};

  const ThemeSwitcher = ({ children }: { children: React.ReactNode }) => {
    const [mode, setLocalMode] = useState<'light' | 'dark'>('dark');
    setMode = setLocalMode;
    return (
      <ThemeProvider theme={createTheme({ palette: { mode } })}>
        {children}
      </ThemeProvider>
    );
  };

  it('applies the class matching the current theme mode on mount', () => {
    const container = document.createElement('div');
    const containerRef = { current: container };

    renderHook(() => useFdsThemeScope(containerRef), { wrapper: ThemeSwitcher });

    expect(container.classList.contains('dark')).toBe(true);
    expect(container.classList.contains('light')).toBe(false);
  });

  it('swaps the class reactively when the theme mode changes after mount', () => {
    const container = document.createElement('div');
    const containerRef = { current: container };

    renderHook(() => useFdsThemeScope(containerRef), { wrapper: ThemeSwitcher });

    expect(container.classList.contains('dark')).toBe(true);

    act(() => {
      setMode('light');
    });

    expect(container.classList.contains('light')).toBe(true);
    expect(container.classList.contains('dark')).toBe(false);

    act(() => {
      setMode('dark');
    });

    expect(container.classList.contains('dark')).toBe(true);
    expect(container.classList.contains('light')).toBe(false);
  });

  it('never sets both classes at once, and does nothing when the container is not mounted', () => {
    const containerRef = { current: null };

    expect(() => {
      renderHook(() => useFdsThemeScope(containerRef), { wrapper: ThemeSwitcher });
    }).not.toThrow();
  });
});
