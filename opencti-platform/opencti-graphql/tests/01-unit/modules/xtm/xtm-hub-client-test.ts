import { afterEach, describe, expect, it, vi } from 'vitest';
import conf from '../../../../src/config/conf';
import { getHubBackendUrl } from '../../../../src/modules/xtm/hub/xtm-hub-client';

describe('xtm-hub-client', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getHubBackendUrl', () => {
    it('should prefer override URL when both URLs are configured', () => {
      vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
        if (key === 'xtm:xtmhub_api_override_url') return '  https://override.local  ';
        if (key === 'xtm:xtmhub_url') return 'https://hub.local';
        return undefined;
      });

      expect(getHubBackendUrl()).toBe('https://override.local');
    });

    it('should fallback to hub URL when override URL is empty', () => {
      vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
        if (key === 'xtm:xtmhub_api_override_url') return '   ';
        if (key === 'xtm:xtmhub_url') return '  https://hub.local  ';
        return undefined;
      });

      expect(getHubBackendUrl()).toBe('https://hub.local');
    });

    it('should return undefined when both URLs are missing or blank', () => {
      vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
        if (key === 'xtm:xtmhub_api_override_url') return undefined;
        if (key === 'xtm:xtmhub_url') return '';
        return undefined;
      });

      expect(getHubBackendUrl()).toBeUndefined();
    });

    it('should ignore non-string values', () => {
      vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
        if (key === 'xtm:xtmhub_api_override_url') return 42;
        if (key === 'xtm:xtmhub_url') return false;
        return undefined;
      });

      expect(getHubBackendUrl()).toBeUndefined();
    });
  });
});
