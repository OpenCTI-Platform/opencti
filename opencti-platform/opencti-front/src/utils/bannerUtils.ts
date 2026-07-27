import moment from 'moment-timezone';
import { dispatch } from './hooks/useBus';
import { isNotEmptyField } from './utils';
import { RootSettings$data } from '../private/__generated__/RootSettings.graphql';
import { REGISTER_BANNER_DISMISSED_BUS, REGISTER_BANNER_DISMISSED_KEY } from './bannerConstants';

export const SMTP_REFRESH_TOKEN_EXPIRATION_WARNING_DAYS = 7;

// -- Register banner dismiss store --

export const readRegisterDismissed = (): boolean => localStorage.getItem(REGISTER_BANNER_DISMISSED_KEY) === 'true';

export const resetRegisterBannerDismiss = () => {
  localStorage.removeItem(REGISTER_BANNER_DISMISSED_KEY);
  dispatch(REGISTER_BANNER_DISMISSED_BUS, false);
};

// -- Display conditions --

export const shouldDisplayLicenseBanner = (
  eeSettings: RootSettings$data['platform_enterprise_edition'] | undefined | null,
): boolean => {
  if (!eeSettings?.license_enterprise) return false;
  return Boolean(!eeSettings.license_validated || eeSettings.license_extra_expiration
    || eeSettings.license_type === 'trial');
};

export const shouldDisplayTrialBanner = (
  settings: RootSettings$data | undefined | null,
): boolean => {
  return isNotEmptyField(settings?.platform_xtmhub_url) && !!settings?.platform_demo;
};

export const shouldDisplayRegisterBanner = (
  settings: RootSettings$data | undefined,
  isXTMHubAccessible: boolean | null | undefined,
  isGrantedToXtmHub: boolean,
  isDismissed: boolean,
): boolean => {
  return !isDismissed
    && isXTMHubAccessible === true
    && isGrantedToXtmHub
    && !!settings?.xtm_hub_backend_is_reachable
    && settings?.xtm_hub_registration_status !== 'registered';
};

export type SmtpRefreshTokenBannerState = 'none' | 'expiring_soon' | 'expired';

export const getSmtpRefreshTokenBannerState = (
  authType: string | null | undefined,
  refreshTokenExpiresAt: string | null | undefined,
): SmtpRefreshTokenBannerState => {
  if (authType !== 'oauth2' || !isNotEmptyField(refreshTokenExpiresAt)) return 'none';
  const expirationDate = moment(refreshTokenExpiresAt);
  if (!expirationDate.isValid()) return 'none';
  if (expirationDate.isBefore(moment())) return 'expired';
  if (expirationDate.diff(moment(), 'days') < SMTP_REFRESH_TOKEN_EXPIRATION_WARNING_DAYS) return 'expiring_soon';
  return 'none';
};
