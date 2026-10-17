import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useXtmHubUserPlatformToken from './useXtmHubUserPlatformToken';

const HUB_URL = 'https://hub.filigran.io/app';
const HUB_ORIGIN = 'https://hub.filigran.io';

const dispatchMessage = (source: unknown, origin: string, data: Record<string, unknown>) => {
  const event = new MessageEvent('message', { data, origin });
  Object.defineProperty(event, 'source', { value: source });
  window.dispatchEvent(event);
};

const setOpener = (value: unknown) => {
  Object.defineProperty(window, 'opener', { value, configurable: true, writable: true });
};

describe('Hook: useXtmHubUserPlatformToken', () => {
  let opener: { postMessage: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    window.sessionStorage.clear();
    opener = { postMessage: vi.fn() };
    setOpener(opener);
  });

  afterEach(() => {
    setOpener(null);
    vi.restoreAllMocks();
  });

  it('asks the opener for a token, targeting the Hub origin only', () => {
    renderHook(() => useXtmHubUserPlatformToken(HUB_URL));

    expect(opener.postMessage).toHaveBeenCalledWith({ action: 'refresh-token' }, HUB_ORIGIN);
  });

  it('keeps a token sent by the opener from the Hub origin', () => {
    const { result } = renderHook(() => useXtmHubUserPlatformToken(HUB_URL));

    act(() => {
      dispatchMessage(opener, HUB_ORIGIN, { action: 'set-token', token: 'hub-token' });
    });

    expect(result.current.userPlatformToken).toBe('hub-token');
  });

  it('ignores a token sent from another origin', () => {
    const { result } = renderHook(() => useXtmHubUserPlatformToken(HUB_URL));

    act(() => {
      dispatchMessage(opener, 'https://other.example', { action: 'set-token', token: 'other-token' });
    });

    expect(result.current.userPlatformToken).toBeNull();
  });

  it('does not ask for a token when the Hub URL is unknown', () => {
    renderHook(() => useXtmHubUserPlatformToken(undefined));

    expect(opener.postMessage).not.toHaveBeenCalled();
  });
});
