import { describe, expect, it } from 'vitest';
import { getRegistrationPlatformTitle, getXtmHubProductName } from './XtmHubTab';

describe('XtmHubTab helpers', () => {
  describe('getXtmHubProductName', () => {
    it('returns product name from search params', () => {
      expect(getXtmHubProductName('?productName=OpenCTI')).toEqual('OpenCTI');
    });

    it('returns null when product name is absent', () => {
      expect(getXtmHubProductName('?foo=bar')).toBeNull();
    });

    it('returns null when product name is blank', () => {
      expect(getXtmHubProductName('?productName=%20%20')).toBeNull();
    });
  });

  describe('getRegistrationPlatformTitle', () => {
    it('uses auto registration product name when available', () => {
      expect(
        getRegistrationPlatformTitle({
          autoRegistrationProductName: 'OpenCTI',
          fallbackPlatformTitle: 'OpenCTI Platform',
        }),
      ).toEqual('OpenCTI');
    });

    it('falls back to platform title when auto registration product name is missing', () => {
      expect(
        getRegistrationPlatformTitle({
          autoRegistrationProductName: null,
          fallbackPlatformTitle: 'OpenCTI Platform',
        }),
      ).toEqual('OpenCTI Platform');
    });
  });
});
