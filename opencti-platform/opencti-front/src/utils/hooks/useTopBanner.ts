import { useState } from 'react';
import useAuth from './useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from './useGranted';
import { readRegisterDismissed, shouldDisplayLicenseBanner, shouldDisplayRegisterBanner, shouldDisplayTrialBanner } from '../bannerUtils';
import { REGISTER_BANNER_DISMISSED_BUS } from '../bannerConstants';
import useBus from './useBus';
import { TOP_BANNER_HEIGHT } from '../../components/TopBanner';

export interface TopBannerState {
  showLicenseBanner: boolean;
  showTrialBanner: boolean;
  showRegisterBanner: boolean;
  height: number;
}

const useTopBanner = (): TopBannerState => {
  const { settings, isXTMHubAccessible } = useAuth();
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const [isDismissed, setIsDismissed] = useState<boolean>(readRegisterDismissed);
  useBus(REGISTER_BANNER_DISMISSED_BUS, (value: boolean) => setIsDismissed(value), []);

  const showLicenseBanner = shouldDisplayLicenseBanner(settings?.platform_enterprise_edition);
  const showTrialBanner = shouldDisplayTrialBanner(settings);
  const showRegisterBanner = shouldDisplayRegisterBanner(settings, isXTMHubAccessible, isGrantedToXtmHub, isDismissed);

  const height = (showLicenseBanner || showTrialBanner || showRegisterBanner) ? TOP_BANNER_HEIGHT : 0;

  return { showLicenseBanner, showTrialBanner, showRegisterBanner, height };
};

export default useTopBanner;
