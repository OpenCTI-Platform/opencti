import { useState } from 'react';
import useAuth from './useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from './useGranted';
import useHelper from './useHelper';
import { TOP_BANNER_HEIGHT } from '../../components/TopBanner';
import { REGISTER_BANNER_DISMISSED_BUS, readRegisterDismissed, shouldDisplayLicenseBanner, shouldDisplayRegisterBanner, shouldDisplayTrialBanner } from '../bannerUtils';
import useBus from './useBus';

const useTopBannerHeight = (): number => {
  const { settings, isXTMHubAccessible } = useAuth();
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { isFeatureEnable } = useHelper();

  const [isDismissed, setIsDismissed] = useState<boolean>(readRegisterDismissed);
  useBus(REGISTER_BANNER_DISMISSED_BUS, (value: boolean) => setIsDismissed(value), []);

  const showLicenseBanner = shouldDisplayLicenseBanner(settings?.platform_enterprise_edition);
  const showTrialBanner = shouldDisplayTrialBanner(settings);
  const showRegisterBanner = isFeatureEnable('XTMHUB_NEWS_FEED_ENABLED') && shouldDisplayRegisterBanner(settings, isXTMHubAccessible, isGrantedToXtmHub, isDismissed);

  return (showTrialBanner || showRegisterBanner || showLicenseBanner) ? TOP_BANNER_HEIGHT : 0;
};

export default useTopBannerHeight;
