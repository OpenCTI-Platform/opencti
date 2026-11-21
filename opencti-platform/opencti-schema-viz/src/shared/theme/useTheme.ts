import { useCallback, useEffect, useState } from 'react';

export type ThemeMode = 'dark' | 'light';

const STORAGE_KEY = 'opencti-schema-viz:theme';

// The design system is class-based and dark by default; it never reads prefers-color-scheme.
const initialTheme = (): ThemeMode => {
  try {
    return localStorage.getItem(STORAGE_KEY) === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
};

export const useTheme = () => {
  const [theme, setTheme] = useState<ThemeMode>(initialTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('dark', 'light');
    root.classList.add(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Not persisted, still applied.
    }
  }, [theme]);

  const toggleTheme = useCallback(() => setTheme((current) => (current === 'dark' ? 'light' : 'dark')), []);
  return { theme, toggleTheme };
};
