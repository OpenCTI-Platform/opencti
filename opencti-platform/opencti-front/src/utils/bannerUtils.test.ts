import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import moment from 'moment-timezone';
import {
  getSmtpRefreshTokenBannerState,
  readRegisterDismissed,
  resetRegisterBannerDismiss,
  shouldDisplayLicenseBanner,
  shouldDisplayRegisterBanner,
  shouldDisplayTrialBanner,
  SMTP_REFRESH_TOKEN_EXPIRATION_WARNING_DAYS,
} from './bannerUtils';
import { REGISTER_BANNER_DISMISSED_BUS, REGISTER_BANNER_DISMISSED_KEY } from './bannerConstants';
import * as useBusModule from './hooks/useBus';

describe('bannerUtils', () => {
  describe('readRegisterDismissed / resetRegisterBannerDismiss', () => {
    beforeEach(() => localStorage.clear());
    afterEach(() => vi.restoreAllMocks());

    it('should return false when nothing is stored', () => {
      expect(readRegisterDismissed()).toBe(false);
    });

    it('should return true when the register banner was dismissed', () => {
      localStorage.setItem(REGISTER_BANNER_DISMISSED_KEY, 'true');
      expect(readRegisterDismissed()).toBe(true);
    });

    it('should clear the dismissed key and dispatch false', () => {
      localStorage.setItem(REGISTER_BANNER_DISMISSED_KEY, 'true');
      const dispatchSpy = vi.spyOn(useBusModule, 'dispatch');

      resetRegisterBannerDismiss();

      expect(readRegisterDismissed()).toBe(false);
      expect(dispatchSpy).toHaveBeenCalledWith(REGISTER_BANNER_DISMISSED_BUS, false);
    });
  });

  describe('shouldDisplayLicenseBanner', () => {
    it('should return false when there is no EE settings', () => {
      expect(shouldDisplayLicenseBanner(undefined)).toBe(false);
      expect(shouldDisplayLicenseBanner(null)).toBe(false);
    });

    it('should return false when the platform is not on an enterprise license', () => {
      expect(shouldDisplayLicenseBanner({
        license_enterprise: false,
        license_validated: false,
        license_extra_expiration: false,
        license_type: 'trial',
      } as never)).toBe(false);
    });

    it('should return true when the enterprise license is not validated', () => {
      expect(shouldDisplayLicenseBanner({
        license_enterprise: true,
        license_validated: false,
        license_extra_expiration: false,
        license_type: 'enterprise',
      } as never)).toBe(true);
    });

    it('should return true when the enterprise license has an extra expiration', () => {
      expect(shouldDisplayLicenseBanner({
        license_enterprise: true,
        license_validated: true,
        license_extra_expiration: true,
        license_type: 'enterprise',
      } as never)).toBe(true);
    });

    it('should return true when the license type is trial', () => {
      expect(shouldDisplayLicenseBanner({
        license_enterprise: true,
        license_validated: true,
        license_extra_expiration: false,
        license_type: 'trial',
      } as never)).toBe(true);
    });

    it('should return false when the enterprise license is validated, not extra-expired and not a trial', () => {
      expect(shouldDisplayLicenseBanner({
        license_enterprise: true,
        license_validated: true,
        license_extra_expiration: false,
        license_type: 'enterprise',
      } as never)).toBe(false);
    });
  });

  describe('shouldDisplayTrialBanner', () => {
    it('should return false when there are no settings', () => {
      expect(shouldDisplayTrialBanner(undefined)).toBe(false);
      expect(shouldDisplayTrialBanner(null)).toBe(false);
    });

    it('should return false when platform_xtmhub_url is missing', () => {
      expect(shouldDisplayTrialBanner({ platform_xtmhub_url: null, platform_demo: true } as never)).toBe(false);
    });

    it('should return false when platform_demo is falsy', () => {
      expect(shouldDisplayTrialBanner({ platform_xtmhub_url: 'https://hub.io', platform_demo: false } as never)).toBe(false);
    });

    it('should return true when platform_xtmhub_url is set and platform_demo is true', () => {
      expect(shouldDisplayTrialBanner({ platform_xtmhub_url: 'https://hub.io', platform_demo: true } as never)).toBe(true);
    });
  });

  describe('shouldDisplayRegisterBanner', () => {
    const baseSettings = {
      xtm_hub_backend_is_reachable: true,
      xtm_hub_registration_status: 'not_registered',
    };

    it('should return false when the banner was dismissed', () => {
      expect(shouldDisplayRegisterBanner(baseSettings as never, true, true, true)).toBe(false);
    });

    it('should return false when XTM Hub is not accessible', () => {
      expect(shouldDisplayRegisterBanner(baseSettings as never, false, true, false)).toBe(false);
      expect(shouldDisplayRegisterBanner(baseSettings as never, null, true, false)).toBe(false);
    });

    it('should return false when the user is not granted to XTM Hub', () => {
      expect(shouldDisplayRegisterBanner(baseSettings as never, true, false, false)).toBe(false);
    });

    it('should return false when the XTM Hub backend is not reachable', () => {
      expect(shouldDisplayRegisterBanner({ ...baseSettings, xtm_hub_backend_is_reachable: false } as never, true, true, false)).toBe(false);
    });

    it('should return false when the platform is already registered', () => {
      expect(shouldDisplayRegisterBanner({ ...baseSettings, xtm_hub_registration_status: 'registered' } as never, true, true, false)).toBe(false);
    });

    it('should return true when all conditions are met', () => {
      expect(shouldDisplayRegisterBanner(baseSettings as never, true, true, false)).toBe(true);
    });
  });

  describe('getSmtpRefreshTokenBannerState', () => {
    it('should return none when auth_type is not oauth2', () => {
      const inFewDays = moment().add(2, 'days').toISOString();
      expect(getSmtpRefreshTokenBannerState('basic', inFewDays)).toBe('none');
      expect(getSmtpRefreshTokenBannerState(null, inFewDays)).toBe('none');
      expect(getSmtpRefreshTokenBannerState(undefined, inFewDays)).toBe('none');
    });

    it('should return none when the expiration date is missing', () => {
      expect(getSmtpRefreshTokenBannerState('oauth2', null)).toBe('none');
      expect(getSmtpRefreshTokenBannerState('oauth2', undefined)).toBe('none');
      expect(getSmtpRefreshTokenBannerState('oauth2', '')).toBe('none');
    });

    it('should return none when the expiration date is not a valid date', () => {
      expect(getSmtpRefreshTokenBannerState('oauth2', 'not-a-date')).toBe('none');
    });

    it('should return expired when the expiration date is in the past', () => {
      const yesterday = moment().subtract(1, 'day').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', yesterday)).toBe('expired');

      const longAgo = moment().subtract(1, 'year').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', longAgo)).toBe('expired');
    });

    it('should return expiring_soon when the expiration date is within the warning window', () => {
      const inTwoDays = moment().add(2, 'days').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', inTwoDays)).toBe('expiring_soon');

      const justUnderTheThreshold = moment().add(SMTP_REFRESH_TOKEN_EXPIRATION_WARNING_DAYS - 1, 'days').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', justUnderTheThreshold)).toBe('expiring_soon');
    });

    it('should return none when the expiration date is beyond the warning window', () => {
      const farInTheFuture = moment().add(SMTP_REFRESH_TOKEN_EXPIRATION_WARNING_DAYS + 1, 'days').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', farInTheFuture)).toBe('none');

      const inOneYear = moment().add(1, 'year').toISOString();
      expect(getSmtpRefreshTokenBannerState('oauth2', inOneYear)).toBe('none');
    });
  });
});
