import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useExternalTab from './useExternalTab';

const HUB_ORIGIN = 'https://hub.filigran.io';

const dispatchMessage = (source: unknown, origin: string, data: Record<string, unknown>) => {
  const event = new MessageEvent('message', { data, origin });
  Object.defineProperty(event, 'source', { value: source });
  window.dispatchEvent(event);
};

const openHubTab = (onMessage: (event: MessageEvent) => void, onOriginMismatch = vi.fn()) => {
  const tab = { closed: false, close: vi.fn(), focus: vi.fn() };
  vi.spyOn(window, 'open').mockReturnValue(tab as unknown as Window);
  const { result } = renderHook(() => useExternalTab({
    url: `${HUB_ORIGIN}/app/redirect/register-opencti`,
    tabName: 'xtmhub-registration',
    expectedOrigin: HUB_ORIGIN,
    onMessage,
    onClosingTab: vi.fn(),
    onOriginMismatch,
  }));
  act(() => {
    result.current.openTab();
  });
  return tab;
};

describe('Hook: useExternalTab', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('handles a message sent by the opened tab from the expected origin', () => {
    const onMessage = vi.fn();
    const tab = openHubTab(onMessage);

    act(() => {
      dispatchMessage(tab, HUB_ORIGIN, { action: 'cancel' });
    });

    expect(onMessage).toHaveBeenCalledOnce();
    expect(tab.close).toHaveBeenCalledOnce();
  });

  it('reports a Hub action sent by the opened tab from another origin without handling it', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onMessage = vi.fn();
    const onOriginMismatch = vi.fn();
    const tab = openHubTab(onMessage, onOriginMismatch);

    act(() => {
      dispatchMessage(tab, 'https://other.example', { action: 'register', token: 'token' });
    });

    expect(onMessage).not.toHaveBeenCalled();
    expect(onOriginMismatch).toHaveBeenCalledExactlyOnceWith('https://other.example');
    expect(tab.close).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('"https://other.example"'));
    expect(warn).not.toHaveBeenCalledWith(expect.stringContaining('token'));
  });

  it('keeps listening after an origin mismatch and handles a later message from the expected origin', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onMessage = vi.fn();
    const onOriginMismatch = vi.fn();
    const tab = openHubTab(onMessage, onOriginMismatch);

    act(() => {
      dispatchMessage(tab, 'https://other.example', { action: 'register', token: 'token' });
    });
    act(() => {
      dispatchMessage(tab, HUB_ORIGIN, { action: 'register', token: 'token' });
    });

    expect(onOriginMismatch).toHaveBeenCalledOnce();
    expect(onMessage).toHaveBeenCalledOnce();
    expect(tab.close).toHaveBeenCalledOnce();
  });

  it('silently ignores an unknown message sent by the opened tab from another origin', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onMessage = vi.fn();
    const onOriginMismatch = vi.fn();
    const tab = openHubTab(onMessage, onOriginMismatch);

    act(() => {
      dispatchMessage(tab, 'https://sso.example', { type: 'analytics' });
    });

    expect(onMessage).not.toHaveBeenCalled();
    expect(onOriginMismatch).not.toHaveBeenCalled();
    expect(tab.close).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });

  it('ignores a message from the expected origin sent by another window', () => {
    const onMessage = vi.fn();
    const onOriginMismatch = vi.fn();
    openHubTab(onMessage, onOriginMismatch);

    act(() => {
      dispatchMessage({}, HUB_ORIGIN, { action: 'register', token: 'token' });
    });

    expect(onMessage).not.toHaveBeenCalled();
    expect(onOriginMismatch).not.toHaveBeenCalled();
  });

  it('ignores a Hub action from another origin sent by another window', () => {
    const onMessage = vi.fn();
    const onOriginMismatch = vi.fn();
    const tab = openHubTab(onMessage, onOriginMismatch);

    act(() => {
      dispatchMessage({}, 'https://other.example', { action: 'register', token: 'token' });
    });

    expect(onMessage).not.toHaveBeenCalled();
    expect(onOriginMismatch).not.toHaveBeenCalled();
    expect(tab.close).not.toHaveBeenCalled();
  });
});
