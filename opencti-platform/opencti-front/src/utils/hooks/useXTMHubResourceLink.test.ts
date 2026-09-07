import { describe, expect, it } from 'vitest';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import { useXTMHubResourceLink } from './useXTMHubResourceLink';

const HUB_URL = 'https://hub.filigran.io';
const SETTINGS_ID = 'settings-id-1';

const renderLink = (urlPath?: string | null, settings?: Record<string, unknown>) => {
  const { hook } = testRenderHook(() => useXTMHubResourceLink(urlPath), {
    userContext: createMockUserContext({
      settings: settings ?? { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL },
    }),
  });
  return hook.result.current;
};

describe('useXTMHubResourceLink', () => {
  it('returns undefined when the hub url is not configured', () => {
    expect(renderLink('/dashboards/1', { id: SETTINGS_ID })).toBeUndefined();
  });

  it('returns undefined when the hub url is empty', () => {
    expect(renderLink('/dashboards/1', { id: SETTINGS_ID, platform_xtmhub_url: '' })).toBeUndefined();
  });

  it('returns undefined when the url path is undefined', () => {
    expect(renderLink(undefined)).toBeUndefined();
  });

  it('returns undefined when the url path is null', () => {
    expect(renderLink(null)).toBeUndefined();
  });

  it('returns undefined when the url path is empty', () => {
    expect(renderLink('')).toBeUndefined();
  });

  it('returns undefined for an absolute http url', () => {
    expect(renderLink('https://evil.example/steal')).toBeUndefined();
  });

  it('returns undefined for a protocol relative url', () => {
    expect(renderLink('//evil.example/steal')).toBeUndefined();
  });

  it('returns undefined for a javascript scheme', () => {
    expect(renderLink('javascript:alert(1)')).toBeUndefined();
  });

  it('builds an absolute url from the hub url and the relative path', () => {
    const link = renderLink('/dashboards/1');
    expect(link).toBeDefined();
    const url = new URL(link as string);
    expect(url.origin).toBe(HUB_URL);
    expect(url.pathname).toBe('/dashboards/1');
  });

  it('appends the platform id of the settings', () => {
    const link = renderLink('/dashboards/1');
    expect(new URL(link as string).searchParams.get('platform_id')).toBe(SETTINGS_ID);
  });

  it('preserves an existing query string of the url path', () => {
    const url = new URL(renderLink('/dashboards/1?tab=widgets') as string);
    expect(url.searchParams.get('tab')).toBe('widgets');
    expect(url.searchParams.get('platform_id')).toBe(SETTINGS_ID);
  });

  it('resolves a path without a leading slash against the hub url', () => {
    const url = new URL(renderLink('dashboards/1') as string);
    expect(url.origin).toBe(HUB_URL);
    expect(url.pathname).toBe('/dashboards/1');
  });
});
