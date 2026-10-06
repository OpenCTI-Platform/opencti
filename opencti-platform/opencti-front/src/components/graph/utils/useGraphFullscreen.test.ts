import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import useGraphFullscreen from './useGraphFullscreen';

describe('useGraphFullscreen', () => {
  let fullscreenElement: Element | null;
  const requestFullscreen = vi.fn(async () => {
    fullscreenElement = document.documentElement;
  });
  const exitFullscreen = vi.fn(async () => {
    fullscreenElement = null;
  });

  beforeEach(() => {
    fullscreenElement = null;
    requestFullscreen.mockClear();
    exitFullscreen.mockClear();
    Object.defineProperty(document, 'fullscreenEnabled', { configurable: true, get: () => true });
    Object.defineProperty(document, 'fullscreenElement', { configurable: true, get: () => fullscreenElement });
    Object.defineProperty(document, 'exitFullscreen', { configurable: true, value: exitFullscreen });
    Object.defineProperty(document.documentElement, 'requestFullscreen', { configurable: true, value: requestFullscreen });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const renderFullscreen = () => {
    const container = document.createElement('div');
    container.style.cssText = 'height: 400px;';
    const containerRef = { current: container };
    const setIsFullscreen = vi.fn();
    const hook = renderHook(({ isFullscreen }) => useGraphFullscreen(containerRef, isFullscreen, setIsFullscreen, 'black'), {
      initialProps: { isFullscreen: false },
    });
    return { container, setIsFullscreen, ...hook };
  };

  it('lays the container over the window and asks the browser for full screen', async () => {
    const { result, container, setIsFullscreen } = renderFullscreen();
    await act(async () => result.current.toggle());
    expect(container.style.position).toBe('fixed');
    expect(setIsFullscreen).toHaveBeenCalledWith(true);
    expect(requestFullscreen).toHaveBeenCalledTimes(1);
  });

  it('leaves the full screen it asked for when the graph unmounts', async () => {
    const { result, container, unmount } = renderFullscreen();
    await act(async () => result.current.toggle());
    unmount();
    expect(exitFullscreen).toHaveBeenCalledTimes(1);
    expect(container.style.cssText).toBe('height: 400px;');
  });

  it('leaves the full screen it asked for once it is entered, when the graph unmounted meanwhile', async () => {
    let enter = () => {};
    requestFullscreen.mockImplementationOnce(() => new Promise<void>((resolve) => {
      enter = () => {
        fullscreenElement = document.documentElement;
        resolve();
      };
    }));
    const { result, unmount } = renderFullscreen();
    act(() => result.current.toggle());
    unmount();
    expect(exitFullscreen).not.toHaveBeenCalled();
    await act(async () => enter());
    expect(exitFullscreen).toHaveBeenCalledTimes(1);
  });

  it('leaves alone a full screen the graph did not ask for', async () => {
    fullscreenElement = document.body;
    const { result, unmount } = renderFullscreen();
    await act(async () => result.current.toggle());
    expect(requestFullscreen).not.toHaveBeenCalled();
    unmount();
    expect(exitFullscreen).not.toHaveBeenCalled();
  });
});
