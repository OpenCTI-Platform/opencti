import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import React, { ReactNode } from 'react';
import { act, renderHook } from '@testing-library/react';
import { useMatrixImageExport } from './useMatrixImageExport';
import { createMockUserContext } from '../../../../../utils/tests/test-render';
import { UserContext, UserContextType } from '../../../../../utils/hooks/useAuth';
import ExportThemeContext from '../../../../../utils/ExportThemeContext';
import AppIntlProvider from '../../../../../components/AppIntlProvider';
import { exportImage } from '../../../../../utils/Image';
import { MESSAGING$ } from '../../../../../relay/environment';

vi.mock('../../../../../utils/Image', () => ({ exportImage: vi.fn() }));
vi.mock('../../../../../relay/environment', () => ({ MESSAGING$: { notifyError: vi.fn() } }));

const themes = {
  edges: [
    { node: { id: 'dark', name: 'Dark', theme_background: '#111111' } },
    { node: { id: 'light', name: 'Light', theme_background: '#ffffff' } },
  ],
};

describe('useMatrixImageExport', () => {
  const setExportTheme = vi.fn();
  let element: HTMLElement;

  const wrapper = ({ children }: { children: ReactNode }) => (
    <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
      <UserContext.Provider value={createMockUserContext({ themes }) as UserContextType}>
        <ExportThemeContext.Provider value={{ exportTheme: null, setExportTheme }}>
          {children}
        </ExportThemeContext.Provider>
      </UserContext.Provider>
    </AppIntlProvider>
  );

  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(exportImage).mockReset();
    vi.mocked(MESSAGING$.notifyError).mockReset();
    setExportTheme.mockReset();
    element = document.createElement('div');
    element.id = 'matrix-export';
    element.setAttribute('style', 'padding: 16px');
    document.body.appendChild(element);
  });

  afterEach(() => {
    vi.useRealTimers();
    element.remove();
  });

  it('offers each theme with and without background', () => {
    const { result } = renderHook(() => useMatrixImageExport({ elementId: 'matrix-export', name: 'Case - Matrix view' }), { wrapper });

    expect(result.current.options).toEqual([
      { key: 'dark:bg', label: 'Dark (with background)' },
      { key: 'dark:nobg', label: 'Dark (without background)' },
      { key: 'light:bg', label: 'Light (with background)' },
      { key: 'light:nobg', label: 'Light (without background)' },
    ]);
    expect(result.current.exporting).toBe(false);
  });

  it('captures the element with the chosen theme and background, then restores it', async () => {
    let styleDuringExport: string | null = null;
    vi.mocked(exportImage).mockImplementation(async () => {
      styleDuringExport = element.getAttribute('style');
    });
    const { result } = renderHook(() => useMatrixImageExport({ elementId: 'matrix-export', name: 'Case - Matrix view' }), { wrapper });

    let withBackground!: Promise<void>;
    act(() => {
      withBackground = result.current.exportImage('light:bg');
    });
    expect(result.current.exporting).toBe(true);
    expect(setExportTheme).toHaveBeenCalledWith(themes.edges[1].node);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
      await withBackground;
    });

    expect(exportImage).toHaveBeenCalledTimes(1);
    expect(vi.mocked(exportImage).mock.calls[0].slice(0, 5)).toEqual(['matrix-export', 0, 0, 'Case - Matrix view', '#ffffff']);
    expect(styleDuringExport).toContain('max-content');
    expect(element.getAttribute('style')).toBe('padding: 16px');
    expect(setExportTheme).toHaveBeenLastCalledWith(null);
    expect(result.current.exporting).toBe(false);

    let withoutBackground!: Promise<void>;
    act(() => {
      withoutBackground = result.current.exportImage('dark:nobg');
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
      await withoutBackground;
    });
    expect(vi.mocked(exportImage).mock.calls[1][4]).toBeNull();
  });

  it('notifies a failed capture and ends the export', async () => {
    vi.mocked(exportImage).mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useMatrixImageExport({ elementId: 'matrix-export', name: 'Case - Matrix view' }), { wrapper });

    let pending!: Promise<void>;
    act(() => {
      pending = result.current.exportImage('dark:bg');
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
      await pending;
    });

    expect(MESSAGING$.notifyError).toHaveBeenCalledWith('Dashboard cannot be exported to image');
    expect(element.getAttribute('style')).toBe('padding: 16px');
    expect(setExportTheme).toHaveBeenLastCalledWith(null);
    expect(result.current.exporting).toBe(false);
  });
});
