import { dispatch } from './hooks/useBus';
import { isNotEmptyField } from './utils';
import { RootSettings$data } from '../private/__generated__/RootSettings.graphql';

// -- Register banner dismiss store --

export const REGISTER_BANNER_DISMISSED_KEY = 'register-banner-dismissed';
export const REGISTER_BANNER_DISMISSED_BUS = `${REGISTER_BANNER_DISMISSED_KEY}_bus`;

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
